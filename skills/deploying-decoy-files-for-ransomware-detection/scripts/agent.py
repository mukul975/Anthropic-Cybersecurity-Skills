#!/usr/bin/env python3
"""Decoy file (canary) deployment agent for ransomware detection.

Deploys canary files across file systems and monitors them for modifications
that indicate ransomware encryption activity. Provides real-time alerting
when decoy files are modified, renamed, or deleted.
"""

import hashlib
import json
import logging
import os
import sys
import time
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("canary_agent")

CANARY_EXTENSIONS = [".docx", ".xlsx", ".pdf", ".csv", ".sql", ".txt", ".pptx"]

CANARY_NAMES_FIRST = [
    "_AAAA_budget_2024", "_AAAA_financial_report", "_AAAA_payroll_data",
    "_AAA_employee_records", "_AAA_client_contracts",
]

CANARY_NAMES_LAST = [
    "~zzzz_annual_review", "~zzzz_backup_config", "~zzzz_tax_returns",
    "~zzz_insurance_claims", "~zzz_merger_docs",
]

RANSOMWARE_EXTENSIONS = {
    ".locked", ".encrypted", ".crypt", ".locky", ".cerber", ".wncry",
    ".dharma", ".basta", ".blackcat", ".hive", ".royal", ".akira",
    ".lockbit", ".conti", ".ryuk", ".maze", ".revil", ".phobos",
    ".makop", ".stop", ".djvu", ".rhysida",
}

RANSOM_NOTE_NAMES = {
    "readme.txt", "readme.html", "decrypt.txt", "decrypt.html",
    "how_to_decrypt.txt", "restore_files.txt", "read_me.txt",
    "how_to_recover.txt", "ransom_note.txt",
}


def compute_file_hash(filepath):
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_canary_content(canary_type, name):
    """Generate realistic content for canary files."""
    timestamp = datetime.now().isoformat()
    content = f"CANARY_TOKEN:{name}\n"
    content += f"Generated: {timestamp}\n"
    content += "Classification: CONFIDENTIAL\n\n"

    if "budget" in name or "financial" in name:
        content += "Q4 Financial Summary\n"
        content += "Total Revenue: $12,450,000\n"
        content += "Operating Expenses: $8,230,000\n"
        content += "Net Income: $4,220,000\n"
    elif "payroll" in name or "employee" in name:
        content += "Employee Records - Human Resources\n"
        content += "Total Headcount: 342\n"
        content += "Departments: Engineering, Sales, Marketing, Operations\n"
    elif "client" in name or "contract" in name:
        content += "Client Contract Summary\n"
        content += "Active Contracts: 156\n"
        content += "Pending Renewal: 23\n"
    else:
        content += "Internal Document - Do Not Distribute\n"
        content += "This document contains sensitive business information.\n"

    return content


def deploy_canaries(target_dirs, canaries_per_dir=4):
    """Deploy canary files to target directories."""
    deployed = []
    names = CANARY_NAMES_FIRST[:canaries_per_dir // 2] + CANARY_NAMES_LAST[:canaries_per_dir // 2]

    for target_dir in target_dirs:
        if not os.path.isdir(target_dir):
            logger.warning("Directory does not exist: %s", target_dir)
            continue

        for i, name in enumerate(names):
            ext = CANARY_EXTENSIONS[i % len(CANARY_EXTENSIONS)]
            filename = f"{name}{ext}"
            filepath = os.path.join(target_dir, filename)

            content = generate_canary_content(ext, name)
            with open(filepath, "w") as f:
                f.write(content)

            file_hash = compute_file_hash(filepath)
            record = {
                "path": filepath,
                "hash": file_hash,
                "size": os.path.getsize(filepath),
                "deployed_at": datetime.now().isoformat(),
                "name": filename,
            }
            deployed.append(record)
            logger.info("Deployed canary: %s (hash: %s)", filepath, file_hash[:16])

    return deployed


def check_canary_integrity(canary_records):
    """Check all canary files for modifications, deletions, or renames."""
    alerts = []

    for record in canary_records:
        filepath = record["path"]

        if not os.path.exists(filepath):
            # Check if file was renamed with ransomware extension
            parent_dir = os.path.dirname(filepath)
            basename = os.path.basename(filepath)
            renamed = False
            if os.path.isdir(parent_dir):
                for f in os.listdir(parent_dir):
                    if f.startswith(basename) and any(f.endswith(ext) for ext in RANSOMWARE_EXTENSIONS):
                        alerts.append({
                            "type": "RANSOMWARE_RENAME",
                            "severity": "CRITICAL",
                            "original": filepath,
                            "renamed_to": os.path.join(parent_dir, f),
                            "timestamp": datetime.now().isoformat(),
                        })
                        renamed = True
                        break

            if not renamed:
                alerts.append({
                    "type": "CANARY_DELETED",
                    "severity": "HIGH",
                    "path": filepath,
                    "timestamp": datetime.now().isoformat(),
                })
            continue

        current_hash = compute_file_hash(filepath)
        if current_hash != record["hash"]:
            alerts.append({
                "type": "CANARY_MODIFIED",
                "severity": "CRITICAL",
                "path": filepath,
                "original_hash": record["hash"],
                "current_hash": current_hash,
                "timestamp": datetime.now().isoformat(),
            })

        current_size = os.path.getsize(filepath)
        if abs(current_size - record["size"]) > record["size"] * 0.5:
            alerts.append({
                "type": "SIGNIFICANT_SIZE_CHANGE",
                "severity": "HIGH",
                "path": filepath,
                "original_size": record["size"],
                "current_size": current_size,
                "timestamp": datetime.now().isoformat(),
            })

    # Check for ransom notes in canary directories
    checked_dirs = set()
    for record in canary_records:
        parent_dir = os.path.dirname(record["path"])
        if parent_dir in checked_dirs or not os.path.isdir(parent_dir):
            continue
        checked_dirs.add(parent_dir)
        for f in os.listdir(parent_dir):
            if f.lower() in RANSOM_NOTE_NAMES:
                alerts.append({
                    "type": "RANSOM_NOTE_DETECTED",
                    "severity": "CRITICAL",
                    "path": os.path.join(parent_dir, f),
                    "timestamp": datetime.now().isoformat(),
                })

    return alerts


def monitor_loop(canary_records, interval=10):
    """Continuously monitor canary files at specified interval."""
    logger.info("Starting canary monitoring loop (interval: %ds)", interval)
    logger.info("Monitoring %d canary files", len(canary_records))

    while True:
        alerts = check_canary_integrity(canary_records)
        if alerts:
            for alert in alerts:
                logger.critical(
                    "ALERT [%s] %s: %s",
                    alert["severity"],
                    alert["type"],
                    alert.get("path", alert.get("original", "unknown")),
                )
            print(json.dumps({"alerts": alerts}, indent=2))
        time.sleep(interval)


if __name__ == "__main__":
    print("=" * 60)
    print("Ransomware Canary File Deployment Agent")
    print("Deploy and monitor decoy files for encryption detection")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python agent.py deploy <dir1> [dir2] ...   Deploy canaries")
        print("  python agent.py check <registry.json>      Check canary integrity")
        print("  python agent.py monitor <registry.json>     Continuous monitoring")
        sys.exit(0)

    command = sys.argv[1]

    if command == "deploy":
        dirs = sys.argv[2:] if len(sys.argv) > 2 else [os.getcwd()]
        records = deploy_canaries(dirs)
        registry_file = "canary_registry.json"
        with open(registry_file, "w") as f:
            json.dump(records, f, indent=2)
        print(f"\n[+] Deployed {len(records)} canary files across {len(dirs)} directories")
        print(f"[+] Registry saved to: {registry_file}")

    elif command == "check":
        if len(sys.argv) < 3:
            print("[!] Provide canary registry JSON file")
            sys.exit(1)
        with open(sys.argv[2]) as f:
            records = json.load(f)
        alerts = check_canary_integrity(records)
        if alerts:
            print(f"\n[!] {len(alerts)} ALERTS DETECTED:")
            for a in alerts:
                print(f"  [{a['severity']}] {a['type']}: {a.get('path', a.get('original'))}")
        else:
            print(f"\n[+] All {len(records)} canary files intact. No alerts.")

    elif command == "monitor":
        if len(sys.argv) < 3:
            print("[!] Provide canary registry JSON file")
            sys.exit(1)
        with open(sys.argv[2]) as f:
            records = json.load(f)
        interval = int(sys.argv[3]) if len(sys.argv) > 3 else 10
        monitor_loop(records, interval)

    else:
        print(f"[!] Unknown command: {command}")
