#!/usr/bin/env python3
"""Agent for deploying and monitoring ransomware honeypot canary files."""

import os
import json
import argparse
import hashlib
import time
from datetime import datetime
from pathlib import Path
from collections import Counter


CANARY_EXTENSIONS = [".docx", ".xlsx", ".pdf", ".pptx", ".csv", ".txt",
                     ".jpg", ".png", ".sql", ".bak"]
CANARY_PREFIX_NAMES = [
    "!Accounting_Report_2024", "!Budget_Final", "!Confidential_HR",
    "!Employee_SSN_List", "!Financial_Audit", "!Payroll_Records",
    "~$Customer_Database", "~$Executive_Compensation",
]


def create_canary_files(target_dir, count=10):
    """Create canary files in strategic locations for ransomware detection."""
    canaries = []
    target = Path(target_dir)
    for i in range(min(count, len(CANARY_PREFIX_NAMES))):
        for ext in CANARY_EXTENSIONS[:3]:
            name = f"{CANARY_PREFIX_NAMES[i]}{ext}"
            path = target / name
            content = os.urandom(1024 * (i + 1))
            path.write_bytes(content)
            file_hash = hashlib.sha256(content).hexdigest()
            canaries.append({
                "path": str(path),
                "hash": file_hash,
                "size": len(content),
                "created": datetime.utcnow().isoformat(),
            })
    return canaries


def generate_canary_manifest(canaries, manifest_path):
    """Save canary file manifest for integrity monitoring."""
    manifest = {
        "created_at": datetime.utcnow().isoformat(),
        "canary_count": len(canaries),
        "canaries": canaries,
    }
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    return manifest_path


def check_canary_integrity(manifest_path):
    """Check canary files against manifest to detect tampering/encryption."""
    with open(manifest_path) as f:
        manifest = json.load(f)
    alerts = []
    for canary in manifest.get("canaries", []):
        path = Path(canary["path"])
        if not path.exists():
            alerts.append({
                "type": "DELETED",
                "path": canary["path"],
                "severity": "CRITICAL",
                "detail": "Canary file deleted - possible ransomware wiper",
            })
            continue
        current_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        if current_hash != canary["hash"]:
            alerts.append({
                "type": "MODIFIED",
                "path": canary["path"],
                "severity": "CRITICAL",
                "original_hash": canary["hash"],
                "current_hash": current_hash,
                "detail": "Canary file modified - possible ransomware encryption",
            })
        current_size = path.stat().st_size
        if abs(current_size - canary["size"]) > canary["size"] * 0.1:
            alerts.append({
                "type": "SIZE_CHANGE",
                "path": canary["path"],
                "severity": "HIGH",
                "original_size": canary["size"],
                "current_size": current_size,
            })
    checked = len(manifest.get("canaries", []))
    return {
        "checked": checked,
        "alerts": alerts,
        "alert_count": len(alerts),
        "status": "ALERT" if alerts else "CLEAN",
    }


def detect_ransomware_indicators(watch_dir, window_seconds=60):
    """Detect rapid file modifications indicative of ransomware."""
    watch_path = Path(watch_dir)
    now = time.time()
    recently_modified = []
    extension_changes = Counter()
    new_extensions = Counter()

    for fp in watch_path.rglob("*"):
        if not fp.is_file():
            continue
        try:
            mtime = fp.stat().st_mtime
            if now - mtime < window_seconds:
                recently_modified.append(str(fp))
                ext = fp.suffix.lower()
                if ext in (".encrypted", ".locked", ".crypto", ".crypt",
                           ".enc", ".pay", ".ransom"):
                    new_extensions[ext] += 1
        except (OSError, PermissionError):
            continue

    indicators = []
    if len(recently_modified) > 50:
        indicators.append({
            "indicator": "Mass file modification",
            "count": len(recently_modified),
            "severity": "CRITICAL",
            "detail": f"{len(recently_modified)} files modified in {window_seconds}s",
        })
    if new_extensions:
        indicators.append({
            "indicator": "Ransomware file extensions detected",
            "extensions": dict(new_extensions),
            "severity": "CRITICAL",
        })
    return {
        "files_checked_window": window_seconds,
        "recently_modified": len(recently_modified),
        "indicators": indicators,
        "status": "ALERT" if indicators else "CLEAN",
    }


def generate_honeypot_share_config(share_name="FinanceArchive", share_path="/srv/honeypot"):
    """Generate SMB honeypot share configuration."""
    return {
        "samba_config": {
            "share_name": share_name,
            "path": share_path,
            "comment": "Financial Archive (Read Only)",
            "read_only": False,
            "browseable": True,
            "guest_ok": False,
            "valid_users": "@domain_users",
            "vfs_objects": "full_audit",
            "full_audit_prefix": f"%u|%I|%S",
            "full_audit_success": "open opendir write rename unlink mkdir rmdir",
            "full_audit_failure": "open",
            "full_audit_facility": "LOCAL7",
            "full_audit_priority": "NOTICE",
        },
        "monitoring": {
            "log_path": "/var/log/samba/audit.log",
            "alert_on": ["write", "rename", "unlink"],
            "siem_integration": "syslog -> SIEM",
        },
    }


def analyze_honeypot_logs(log_path):
    """Analyze honeypot access logs for suspicious activity."""
    with open(log_path) as f:
        events = json.load(f)
    items = events if isinstance(events, list) else events.get("events", [])
    by_user = Counter(e.get("user", "unknown") for e in items)
    by_action = Counter(e.get("action", "unknown") for e in items)
    write_events = [e for e in items if e.get("action") in ("write", "rename", "delete")]
    return {
        "total_events": len(items),
        "by_user": dict(by_user.most_common(10)),
        "by_action": dict(by_action),
        "write_events": len(write_events),
        "suspicious": len(write_events) > 5,
        "severity": "CRITICAL" if len(write_events) > 20 else
                    "HIGH" if len(write_events) > 5 else "INFO",
    }


def main():
    parser = argparse.ArgumentParser(description="Ransomware Honeypot Agent")
    parser.add_argument("--deploy", help="Directory to deploy canary files")
    parser.add_argument("--manifest", help="Canary manifest JSON for integrity check")
    parser.add_argument("--watch", help="Directory to watch for ransomware indicators")
    parser.add_argument("--honeypot-log", help="Honeypot access log JSON")
    parser.add_argument("--action", choices=["deploy", "check", "detect", "analyze",
                                              "share-config", "full"], default="full")
    parser.add_argument("--output", default="ransomware_honeypot_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}

    if args.action in ("deploy", "full") and args.deploy:
        canaries = create_canary_files(args.deploy)
        manifest = generate_canary_manifest(canaries, args.deploy + "/canary_manifest.json")
        report["results"]["deployed"] = {"count": len(canaries), "manifest": manifest}
        print(f"[+] Deployed {len(canaries)} canary files")

    if args.action in ("check", "full") and args.manifest:
        result = check_canary_integrity(args.manifest)
        report["results"]["integrity"] = result
        print(f"[+] Integrity: {result['status']} ({result['alert_count']} alerts)")

    if args.action in ("detect", "full") and args.watch:
        result = detect_ransomware_indicators(args.watch)
        report["results"]["detection"] = result
        print(f"[+] Detection: {result['status']}")

    if args.action in ("share-config", "full"):
        config = generate_honeypot_share_config()
        report["results"]["share_config"] = config
        print("[+] Honeypot share config generated")

    if args.action in ("analyze", "full") and args.honeypot_log:
        result = analyze_honeypot_logs(args.honeypot_log)
        report["results"]["log_analysis"] = result
        print(f"[+] Honeypot events: {result['total_events']}, writes: {result['write_events']}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
