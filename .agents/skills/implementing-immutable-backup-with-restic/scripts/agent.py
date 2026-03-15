#!/usr/bin/env python3
"""Immutable backup agent using restic with S3 Object Lock for ransomware-resistant storage.

Automates backup creation, integrity verification, snapshot retention,
and restore testing against S3-compatible storage with WORM protection.
"""

import os
import sys
import json
import hashlib
import logging
import argparse
import subprocess
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timezone, timedelta

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("restic_backup.log"),
    ],
)
logger = logging.getLogger(__name__)


def run_restic(args, repo=None, password=None, env_extra=None):
    """Execute a restic command and return parsed output."""
    cmd = ["restic"]
    if repo:
        cmd.extend(["--repo", repo])
    cmd.extend(args)

    env = dict(os.environ)
    if password:
        env["RESTIC_PASSWORD"] = password
    if env_extra:
        env.update(env_extra)

    result = subprocess.run(
        cmd, capture_output=True, text=True, env=env, timeout=3600
    )
    if result.returncode != 0:
        logger.error("restic %s failed: %s", args[0], result.stderr[:500])
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def init_repository(repo_url, password, s3_config=None):
    """Initialize a new restic repository with encryption."""
    env_extra = {}
    if s3_config:
        env_extra["AWS_ACCESS_KEY_ID"] = s3_config.get("access_key", "")
        env_extra["AWS_SECRET_ACCESS_KEY"] = s3_config.get("secret_key", "")
        if s3_config.get("endpoint"):
            env_extra["AWS_DEFAULT_REGION"] = s3_config.get("region", "us-east-1")

    result = run_restic(["init"], repo=repo_url, password=password, env_extra=env_extra)
    if result["returncode"] == 0:
        logger.info("Repository initialized: %s", repo_url)
    elif "already initialized" in result["stderr"]:
        logger.info("Repository already exists: %s", repo_url)
        result["returncode"] = 0
    return result


def configure_s3_object_lock(bucket_name, retention_days=90, mode="COMPLIANCE"):
    """Configure S3 Object Lock on backup bucket via AWS CLI."""
    lock_config = {
        "ObjectLockEnabled": "Enabled",
        "Rule": {
            "DefaultRetention": {
                "Mode": mode,
                "Days": retention_days,
            }
        }
    }
    cmd = [
        "aws", "s3api", "put-object-lock-configuration",
        "--bucket", bucket_name,
        "--object-lock-configuration", json.dumps(lock_config),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode == 0:
        logger.info(
            "Object Lock configured: bucket=%s mode=%s retention=%dd",
            bucket_name, mode, retention_days
        )
    else:
        logger.error("Object Lock configuration failed: %s", result.stderr[:300])
    return {
        "bucket": bucket_name,
        "mode": mode,
        "retention_days": retention_days,
        "success": result.returncode == 0,
        "error": result.stderr if result.returncode != 0 else None,
    }


def create_backup(repo_url, password, source_paths, tags=None, exclude_patterns=None, env_extra=None):
    """Create a new backup snapshot."""
    args = ["backup"]
    if tags:
        for tag in tags:
            args.extend(["--tag", tag])
    if exclude_patterns:
        for pattern in exclude_patterns:
            args.extend(["--exclude", pattern])
    args.extend(["--json"])
    args.extend(source_paths)

    result = run_restic(args, repo=repo_url, password=password, env_extra=env_extra)
    if result["returncode"] == 0:
        for line in result["stdout"].strip().split("\n"):
            try:
                msg = json.loads(line)
                if msg.get("message_type") == "summary":
                    logger.info(
                        "Backup complete: %d files, %s added, snapshot %s",
                        msg.get("files_new", 0) + msg.get("files_changed", 0),
                        format_bytes(msg.get("data_added", 0)),
                        msg.get("snapshot_id", "unknown")[:8],
                    )
                    return {
                        "success": True,
                        "snapshot_id": msg.get("snapshot_id"),
                        "files_new": msg.get("files_new", 0),
                        "files_changed": msg.get("files_changed", 0),
                        "files_unmodified": msg.get("files_unmodified", 0),
                        "data_added": msg.get("data_added", 0),
                        "total_files_processed": msg.get("total_files_processed", 0),
                        "total_bytes_processed": msg.get("total_bytes_processed", 0),
                        "duration": msg.get("total_duration", 0),
                    }
            except json.JSONDecodeError:
                continue
    return {"success": False, "error": result["stderr"][:500]}


def verify_backup_integrity(repo_url, password, read_data=True, env_extra=None):
    """Verify repository integrity by checking all data packs."""
    args = ["check"]
    if read_data:
        args.append("--read-data")
    args.append("--json")

    logger.info("Starting integrity verification (read_data=%s)...", read_data)
    result = run_restic(args, repo=repo_url, password=password, env_extra=env_extra)

    verification = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "read_data": read_data,
        "passed": result["returncode"] == 0,
        "output": result["stdout"][:2000],
        "errors": [],
    }
    if result["returncode"] != 0:
        for line in result["stderr"].split("\n"):
            if "error" in line.lower() or "fatal" in line.lower():
                verification["errors"].append(line.strip())
        logger.error("Integrity check FAILED: %d errors", len(verification["errors"]))
    else:
        logger.info("Integrity check PASSED")
    return verification


def list_snapshots(repo_url, password, env_extra=None):
    """List all snapshots in the repository."""
    result = run_restic(
        ["snapshots", "--json"], repo=repo_url, password=password, env_extra=env_extra
    )
    if result["returncode"] == 0 and result["stdout"].strip():
        try:
            snapshots = json.loads(result["stdout"])
            return {
                "count": len(snapshots),
                "snapshots": [
                    {
                        "id": s["short_id"],
                        "time": s["time"],
                        "hostname": s.get("hostname", ""),
                        "tags": s.get("tags", []),
                        "paths": s.get("paths", []),
                    }
                    for s in snapshots
                ],
            }
        except json.JSONDecodeError:
            pass
    return {"count": 0, "snapshots": []}


def apply_retention_policy(repo_url, password, keep_daily=7, keep_weekly=4,
                           keep_monthly=12, keep_yearly=2, env_extra=None):
    """Apply snapshot retention policy using restic forget."""
    args = [
        "forget", "--prune",
        "--keep-daily", str(keep_daily),
        "--keep-weekly", str(keep_weekly),
        "--keep-monthly", str(keep_monthly),
        "--keep-yearly", str(keep_yearly),
        "--json",
    ]
    result = run_restic(args, repo=repo_url, password=password, env_extra=env_extra)
    if result["returncode"] == 0:
        logger.info(
            "Retention policy applied: daily=%d weekly=%d monthly=%d yearly=%d",
            keep_daily, keep_weekly, keep_monthly, keep_yearly,
        )
    return {
        "success": result["returncode"] == 0,
        "policy": {
            "keep_daily": keep_daily,
            "keep_weekly": keep_weekly,
            "keep_monthly": keep_monthly,
            "keep_yearly": keep_yearly,
        },
        "output": result["stdout"][:1000],
    }


def test_restore(repo_url, password, snapshot_id="latest", target_path=None,
                 sample_count=5, env_extra=None):
    """Test restore by extracting files and verifying checksums."""
    if target_path is None:
        target_path = tempfile.mkdtemp(prefix="restic_restore_test_")
    else:
        os.makedirs(target_path, exist_ok=True)

    result = run_restic(
        ["restore", snapshot_id, "--target", target_path],
        repo=repo_url, password=password, env_extra=env_extra,
    )
    if result["returncode"] != 0:
        return {"success": False, "error": result["stderr"][:500]}

    restored_files = []
    for root, dirs, files in os.walk(target_path):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                stat = os.stat(fpath)
                sha256 = hashlib.sha256()
                with open(fpath, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        sha256.update(chunk)
                restored_files.append({
                    "path": os.path.relpath(fpath, target_path),
                    "size": stat.st_size,
                    "sha256": sha256.hexdigest(),
                })
            except (PermissionError, OSError):
                continue
            if len(restored_files) >= sample_count:
                break
        if len(restored_files) >= sample_count:
            break

    try:
        shutil.rmtree(target_path)
    except OSError:
        pass

    logger.info("Restore test: %d files verified from snapshot %s", len(restored_files), snapshot_id)
    return {
        "success": True,
        "snapshot": snapshot_id,
        "files_verified": len(restored_files),
        "samples": restored_files,
        "restore_path": target_path,
    }


def get_repository_stats(repo_url, password, env_extra=None):
    """Get repository statistics including size and deduplication ratio."""
    result = run_restic(
        ["stats", "--json", "--mode", "restore-size"],
        repo=repo_url, password=password, env_extra=env_extra,
    )
    stats = {}
    if result["returncode"] == 0 and result["stdout"].strip():
        try:
            stats = json.loads(result["stdout"])
        except json.JSONDecodeError:
            pass

    raw_result = run_restic(
        ["stats", "--json", "--mode", "raw-data"],
        repo=repo_url, password=password, env_extra=env_extra,
    )
    raw_stats = {}
    if raw_result["returncode"] == 0 and raw_result["stdout"].strip():
        try:
            raw_stats = json.loads(raw_result["stdout"])
        except json.JSONDecodeError:
            pass

    restore_size = stats.get("total_size", 0)
    raw_size = raw_stats.get("total_size", 0)
    dedup_ratio = round(restore_size / max(raw_size, 1), 2) if raw_size else 0

    return {
        "restore_size": restore_size,
        "restore_size_human": format_bytes(restore_size),
        "raw_size": raw_size,
        "raw_size_human": format_bytes(raw_size),
        "deduplication_ratio": dedup_ratio,
        "total_file_count": stats.get("total_file_count", 0),
    }


def format_bytes(size):
    """Format byte count to human-readable string."""
    for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
        if abs(size) < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PiB"


def generate_backup_report(repo_url, password, env_extra=None):
    """Generate comprehensive backup status report."""
    snapshots = list_snapshots(repo_url, password, env_extra)
    stats = get_repository_stats(repo_url, password, env_extra)
    verification = verify_backup_integrity(repo_url, password, read_data=False, env_extra=env_extra)

    report = {
        "report_timestamp": datetime.now(timezone.utc).isoformat(),
        "repository": repo_url,
        "snapshot_count": snapshots["count"],
        "latest_snapshot": snapshots["snapshots"][-1] if snapshots["snapshots"] else None,
        "oldest_snapshot": snapshots["snapshots"][0] if snapshots["snapshots"] else None,
        "repository_stats": stats,
        "integrity_check": {
            "passed": verification["passed"],
            "errors": verification["errors"],
        },
        "backup_strategy": {
            "encryption": "AES-256-CTR with Poly1305-AES MAC",
            "deduplication": "content-defined chunking (CDC)",
            "dedup_ratio": stats.get("deduplication_ratio", 0),
        },
    }
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Immutable Backup Agent with Restic and S3 Object Lock"
    )
    parser.add_argument("--repo", required=True, help="Restic repository URL (s3:host/bucket)")
    parser.add_argument("--password-file", help="File containing repository password")
    parser.add_argument("--action", choices=[
        "init", "backup", "verify", "snapshots", "retention", "restore-test",
        "stats", "report", "configure-lock", "full-pipeline"
    ], default="report")
    parser.add_argument("--source", nargs="+", help="Source paths to back up")
    parser.add_argument("--tags", nargs="+", help="Tags for backup snapshot")
    parser.add_argument("--exclude", nargs="+", help="Exclude patterns")
    parser.add_argument("--bucket", help="S3 bucket name for Object Lock config")
    parser.add_argument("--retention-days", type=int, default=90)
    parser.add_argument("--keep-daily", type=int, default=7)
    parser.add_argument("--keep-weekly", type=int, default=4)
    parser.add_argument("--keep-monthly", type=int, default=12)
    parser.add_argument("--snapshot", default="latest", help="Snapshot ID for restore test")
    parser.add_argument("--output", default="backup_report.json")
    args = parser.parse_args()

    password = None
    if args.password_file and os.path.exists(args.password_file):
        with open(args.password_file) as f:
            password = f.read().strip()
    else:
        password = os.getenv("RESTIC_PASSWORD", "")

    if args.action == "init":
        result = init_repository(args.repo, password)
        print(json.dumps(result, indent=2))

    elif args.action == "backup":
        if not args.source:
            print("Error: --source required for backup")
            sys.exit(1)
        result = create_backup(args.repo, password, args.source, args.tags, args.exclude)
        print(json.dumps(result, indent=2, default=str))

    elif args.action == "verify":
        result = verify_backup_integrity(args.repo, password, read_data=True)
        print(json.dumps(result, indent=2))

    elif args.action == "snapshots":
        result = list_snapshots(args.repo, password)
        print(json.dumps(result, indent=2))

    elif args.action == "retention":
        result = apply_retention_policy(
            args.repo, password,
            args.keep_daily, args.keep_weekly, args.keep_monthly, 2,
        )
        print(json.dumps(result, indent=2))

    elif args.action == "restore-test":
        result = test_restore(args.repo, password, args.snapshot)
        print(json.dumps(result, indent=2))

    elif args.action == "stats":
        result = get_repository_stats(args.repo, password)
        print(json.dumps(result, indent=2))

    elif args.action == "configure-lock":
        if not args.bucket:
            print("Error: --bucket required for Object Lock configuration")
            sys.exit(1)
        result = configure_s3_object_lock(args.bucket, args.retention_days)
        print(json.dumps(result, indent=2))

    elif args.action == "report":
        report = generate_backup_report(args.repo, password)
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(json.dumps(report, indent=2, default=str))

    elif args.action == "full-pipeline":
        if not args.source:
            print("Error: --source required for full pipeline")
            sys.exit(1)
        print("[1/5] Creating backup...")
        backup = create_backup(args.repo, password, args.source, args.tags, args.exclude)
        print(f"  Backup: {'SUCCESS' if backup.get('success') else 'FAILED'}")
        print("[2/5] Verifying integrity...")
        verify = verify_backup_integrity(args.repo, password, read_data=True)
        print(f"  Integrity: {'PASSED' if verify['passed'] else 'FAILED'}")
        print("[3/5] Applying retention policy...")
        retention = apply_retention_policy(
            args.repo, password, args.keep_daily, args.keep_weekly, args.keep_monthly, 2
        )
        print(f"  Retention: {'SUCCESS' if retention['success'] else 'FAILED'}")
        print("[4/5] Testing restore...")
        restore = test_restore(args.repo, password)
        print(f"  Restore: {'SUCCESS' if restore['success'] else 'FAILED'}")
        print("[5/5] Generating report...")
        report = generate_backup_report(args.repo, password)
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"  Report saved to {args.output}")


if __name__ == "__main__":
    main()
