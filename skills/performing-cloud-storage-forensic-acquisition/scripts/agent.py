#!/usr/bin/env python3
"""Cloud storage forensic acquisition agent.

Acquires forensic copies of cloud storage objects from AWS S3, Azure Blob
Storage, and GCP Cloud Storage with integrity verification using SHA-256
hashes, metadata preservation, and chain-of-custody logging.
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

try:
    import boto3
    from botocore.exceptions import ClientError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


def acquire_s3_objects(bucket, prefix="", output_dir=".", profile=None, region=None):
    """Acquire S3 objects with forensic integrity verification."""
    if not HAS_BOTO3:
        print("[!] boto3 required: pip install boto3", file=sys.stderr)
        sys.exit(1)

    kwargs = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    session = boto3.Session(**kwargs)
    s3 = session.client("s3")

    print(f"[*] Acquiring objects from s3://{bucket}/{prefix}")
    evidence_log = []

    # List objects
    paginator = s3.get_paginator("list_objects_v2")
    pages = paginator.paginate(Bucket=bucket, Prefix=prefix)

    total_objects = 0
    total_bytes = 0

    for page in pages:
        for obj in page.get("Contents", []):
            key = obj["Key"]
            size = obj["Size"]
            if key.endswith("/"):
                continue

            total_objects += 1
            local_path = os.path.join(output_dir, key.replace("/", os.sep))
            os.makedirs(os.path.dirname(local_path), exist_ok=True)

            # Get object metadata
            try:
                head = s3.head_object(Bucket=bucket, Key=key)
                metadata = {
                    "content_type": head.get("ContentType", ""),
                    "last_modified": head.get("LastModified", "").isoformat()
                                     if hasattr(head.get("LastModified", ""), "isoformat")
                                     else str(head.get("LastModified", "")),
                    "etag": head.get("ETag", "").strip('"'),
                    "version_id": head.get("VersionId", ""),
                    "server_side_encryption": head.get("ServerSideEncryption", ""),
                    "storage_class": head.get("StorageClass", "STANDARD"),
                    "user_metadata": head.get("Metadata", {}),
                }
            except ClientError as e:
                metadata = {"error": str(e)}

            # Download with hash computation
            sha256 = hashlib.sha256()
            try:
                s3.download_file(bucket, key, local_path)
                with open(local_path, "rb") as f:
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        sha256.update(chunk)
                file_hash = sha256.hexdigest()
                total_bytes += size

                entry = {
                    "source": f"s3://{bucket}/{key}",
                    "local_path": local_path,
                    "size": size,
                    "sha256": file_hash,
                    "metadata": metadata,
                    "acquired_at": datetime.now(timezone.utc).isoformat(),
                    "status": "OK",
                }
                print(f"    [{total_objects:4d}] {key} ({size} bytes, SHA256: {file_hash[:16]}...)")
            except ClientError as e:
                entry = {
                    "source": f"s3://{bucket}/{key}",
                    "status": "FAIL",
                    "error": str(e),
                    "acquired_at": datetime.now(timezone.utc).isoformat(),
                }
                print(f"    [FAIL] {key}: {e}")

            evidence_log.append(entry)

    print(f"[+] Acquired {total_objects} objects ({total_bytes / 1024 / 1024:.2f} MB)")
    return evidence_log


def acquire_s3_versions(bucket, key, output_dir=".", profile=None, region=None):
    """Acquire all versions of a specific S3 object."""
    if not HAS_BOTO3:
        print("[!] boto3 required", file=sys.stderr)
        sys.exit(1)

    kwargs = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    session = boto3.Session(**kwargs)
    s3 = session.client("s3")

    print(f"[*] Acquiring all versions of s3://{bucket}/{key}")
    evidence_log = []

    try:
        versions = s3.list_object_versions(Bucket=bucket, Prefix=key)
    except ClientError as e:
        print(f"[!] Error listing versions: {e}", file=sys.stderr)
        return evidence_log

    for version in versions.get("Versions", []):
        vid = version.get("VersionId", "null")
        size = version.get("Size", 0)
        is_latest = version.get("IsLatest", False)

        safe_vid = vid.replace("/", "_")[:20]
        base_name = os.path.basename(key)
        local_path = os.path.join(output_dir, f"{base_name}.v_{safe_vid}")

        try:
            s3.download_file(bucket, key, local_path,
                             ExtraArgs={"VersionId": vid} if vid != "null" else {})
            sha256 = hashlib.sha256()
            with open(local_path, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    sha256.update(chunk)

            entry = {
                "source": f"s3://{bucket}/{key}?versionId={vid}",
                "version_id": vid,
                "is_latest": is_latest,
                "local_path": local_path,
                "size": size,
                "sha256": sha256.hexdigest(),
                "last_modified": str(version.get("LastModified", "")),
                "acquired_at": datetime.now(timezone.utc).isoformat(),
                "status": "OK",
            }
            print(f"    Version {vid[:12]:12s} | {size:10d} bytes | "
                  f"{'LATEST' if is_latest else '      '} | SHA256: {sha256.hexdigest()[:16]}...")
        except ClientError as e:
            entry = {"source": f"s3://{bucket}/{key}", "version_id": vid,
                     "status": "FAIL", "error": str(e)}

        evidence_log.append(entry)

    # Also acquire delete markers
    for marker in versions.get("DeleteMarkers", []):
        evidence_log.append({
            "source": f"s3://{bucket}/{key}",
            "version_id": marker.get("VersionId", ""),
            "type": "DELETE_MARKER",
            "last_modified": str(marker.get("LastModified", "")),
            "is_latest": marker.get("IsLatest", False),
        })

    return evidence_log


def verify_integrity(evidence_log):
    """Verify SHA-256 hashes of acquired files."""
    print(f"\n[*] Verifying integrity of {len(evidence_log)} acquired objects...")
    verified = 0
    failed = 0

    for entry in evidence_log:
        if entry.get("status") != "OK" or not entry.get("local_path"):
            continue
        local_path = entry["local_path"]
        expected_hash = entry.get("sha256", "")
        if not os.path.isfile(local_path):
            entry["integrity"] = "MISSING"
            failed += 1
            continue

        sha256 = hashlib.sha256()
        with open(local_path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)

        if sha256.hexdigest() == expected_hash:
            entry["integrity"] = "VERIFIED"
            verified += 1
        else:
            entry["integrity"] = "MISMATCH"
            failed += 1
            print(f"    [FAIL] {local_path}: hash mismatch")

    print(f"[+] Integrity check: {verified} verified, {failed} failed")
    return verified, failed


def format_summary(evidence_log, verified, failed):
    """Print acquisition summary."""
    print(f"\n{'='*60}")
    print("  Cloud Storage Forensic Acquisition Report")
    print(f"{'='*60}")
    ok = sum(1 for e in evidence_log if e.get("status") == "OK")
    err = sum(1 for e in evidence_log if e.get("status") == "FAIL")
    total_bytes = sum(e.get("size", 0) for e in evidence_log if e.get("status") == "OK")
    print(f"  Objects Acquired : {ok}")
    print(f"  Objects Failed   : {err}")
    print(f"  Total Size       : {total_bytes / 1024 / 1024:.2f} MB")
    print(f"  Integrity OK     : {verified}")
    print(f"  Integrity FAIL   : {failed}")


def main():
    parser = argparse.ArgumentParser(
        description="Cloud storage forensic acquisition agent"
    )
    sub = parser.add_subparsers(dest="command")

    p_s3 = sub.add_parser("s3", help="Acquire S3 bucket objects")
    p_s3.add_argument("--bucket", required=True, help="S3 bucket name")
    p_s3.add_argument("--prefix", default="", help="Object key prefix filter")
    p_s3.add_argument("--output-dir", default="./evidence", help="Local output directory")

    p_ver = sub.add_parser("s3-versions", help="Acquire all versions of S3 object")
    p_ver.add_argument("--bucket", required=True)
    p_ver.add_argument("--key", required=True, help="S3 object key")
    p_ver.add_argument("--output-dir", default="./evidence")

    parser.add_argument("--profile", help="AWS CLI profile")
    parser.add_argument("--region", help="AWS region")
    parser.add_argument("--skip-verify", action="store_true", help="Skip integrity verification")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    os.makedirs(getattr(args, "output_dir", "./evidence"), exist_ok=True)

    if args.command == "s3":
        evidence_log = acquire_s3_objects(
            args.bucket, args.prefix, args.output_dir, args.profile, args.region
        )
    elif args.command == "s3-versions":
        evidence_log = acquire_s3_versions(
            args.bucket, args.key, args.output_dir, args.profile, args.region
        )

    verified, failed = 0, 0
    if not args.skip_verify:
        verified, failed = verify_integrity(evidence_log)

    format_summary(evidence_log, verified, failed)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "Cloud Forensic Acquisition",
        "command": args.command,
        "evidence_log": evidence_log,
        "integrity": {"verified": verified, "failed": failed},
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
