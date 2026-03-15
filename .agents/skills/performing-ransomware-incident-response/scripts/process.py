#!/usr/bin/env python3
"""
Ransomware Incident Response Automation Script

Automates key ransomware IR tasks:
- Identifies ransomware variant from file extensions and ransom notes
- Scans for encryption indicators across file systems
- Checks for Volume Shadow Copy deletion
- Queries backup integrity
- Generates scope assessment report

Requirements:
    pip install requests yara-python watchdog
"""

import argparse
import csv
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f"ransomware_ir_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
    ],
)
logger = logging.getLogger("ransomware_ir")

# Known ransomware file extensions mapped to families
RANSOMWARE_EXTENSIONS = {
    ".lockbit": "LockBit",
    ".lockbit3": "LockBit 3.0",
    ".BlackCat": "BlackCat/ALPHV",
    ".cl0p": "Cl0p",
    ".royal": "Royal",
    ".play": "Play",
    ".akira": "Akira",
    ".rhysida": "Rhysida",
    ".blacksuit": "BlackSuit",
    ".medusa": "Medusa",
    ".8base": "8Base",
    ".bianlian": "BianLian",
    ".encrypted": "Generic/Multiple",
    ".locked": "Generic/Multiple",
    ".crypt": "Generic/Multiple",
    ".enc": "Generic/Multiple",
    ".ryk": "Ryuk",
    ".conti": "Conti",
    ".hive": "Hive",
    ".maze": "Maze",
    ".revil": "REvil/Sodinokibi",
    ".darkside": "DarkSide",
    ".babuk": "Babuk",
    ".phobos": "Phobos",
    ".dharma": "Dharma",
    ".stop": "STOP/Djvu",
    ".djvu": "STOP/Djvu",
}

RANSOM_NOTE_PATTERNS = [
    "README*.txt", "README*.html", "DECRYPT*.txt", "DECRYPT*.html",
    "HOW_TO_RECOVER*", "RESTORE_FILES*", "RECOVER_YOUR_DATA*",
    "!README!*", "_readme.txt", "info.txt", "info.hta",
    "HELP_RECOVER*", "YOUR_FILES*", "#DECRYPT#*", "RANSOM_NOTE*",
]

DECRYPTOR_SOURCES = {
    "No More Ransom": "https://www.nomoreransom.org/en/decryption-tools.html",
    "Emsisoft": "https://www.emsisoft.com/en/ransomware-decryption/",
    "Kaspersky": "https://noransom.kaspersky.com/",
    "Avast": "https://www.avast.com/ransomware-decryption-tools",
    "Bitdefender": "https://www.bitdefender.com/blog/labs/bitdefender-offers-free-universal-decryptor-for-revil-sodinokibi-ransomware/",
}


class RansomwareScanner:
    """Scan file systems for ransomware indicators."""

    def __init__(self, scan_paths: list):
        self.scan_paths = scan_paths
        self.encrypted_files = []
        self.ransom_notes = []
        self.extension_counts = Counter()
        self.affected_directories = set()

    def scan_for_encrypted_files(self, max_files: int = 10000) -> dict:
        """Scan for files with known ransomware extensions."""
        logger.info(f"Scanning {len(self.scan_paths)} paths for encrypted files...")
        count = 0
        for scan_path in self.scan_paths:
            scan_path = Path(scan_path)
            if not scan_path.exists():
                logger.warning(f"Path does not exist: {scan_path}")
                continue
            try:
                for item in scan_path.rglob("*"):
                    if count >= max_files:
                        logger.warning(f"Reached max file scan limit ({max_files})")
                        break
                    if item.is_file():
                        ext = item.suffix.lower()
                        if ext in RANSOMWARE_EXTENSIONS:
                            self.encrypted_files.append({
                                "path": str(item),
                                "extension": ext,
                                "family": RANSOMWARE_EXTENSIONS[ext],
                                "size": item.stat().st_size,
                                "modified": datetime.fromtimestamp(item.stat().st_mtime).isoformat(),
                            })
                            self.extension_counts[ext] += 1
                            self.affected_directories.add(str(item.parent))
                            count += 1
            except PermissionError as e:
                logger.warning(f"Permission denied: {e}")
            except Exception as e:
                logger.error(f"Error scanning {scan_path}: {e}")

        logger.info(f"Found {len(self.encrypted_files)} encrypted files")
        return {
            "total_encrypted": len(self.encrypted_files),
            "extension_breakdown": dict(self.extension_counts),
            "affected_directories": len(self.affected_directories),
            "likely_family": self._identify_family(),
        }

    def scan_for_ransom_notes(self) -> list:
        """Scan for ransom note files."""
        logger.info("Scanning for ransom notes...")
        for scan_path in self.scan_paths:
            scan_path = Path(scan_path)
            if not scan_path.exists():
                continue
            for pattern in RANSOM_NOTE_PATTERNS:
                try:
                    for note in scan_path.rglob(pattern):
                        if note.is_file():
                            content = ""
                            try:
                                content = note.read_text(errors="ignore")[:2000]
                            except Exception:
                                pass
                            self.ransom_notes.append({
                                "path": str(note),
                                "size": note.stat().st_size,
                                "modified": datetime.fromtimestamp(note.stat().st_mtime).isoformat(),
                                "content_preview": content[:500],
                                "bitcoin_addresses": self._extract_bitcoin_addresses(content),
                                "onion_urls": self._extract_onion_urls(content),
                            })
                except Exception as e:
                    logger.error(f"Error scanning for notes with pattern {pattern}: {e}")

        logger.info(f"Found {len(self.ransom_notes)} ransom notes")
        return self.ransom_notes

    def _identify_family(self) -> str:
        if not self.extension_counts:
            return "Unknown"
        most_common_ext = self.extension_counts.most_common(1)[0][0]
        return RANSOMWARE_EXTENSIONS.get(most_common_ext, "Unknown")

    @staticmethod
    def _extract_bitcoin_addresses(text: str) -> list:
        btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-zA-HJ-NP-Z0-9]{25,89}\b'
        return re.findall(btc_pattern, text)

    @staticmethod
    def _extract_onion_urls(text: str) -> list:
        onion_pattern = r'[a-z2-7]{16,56}\.onion'
        return re.findall(onion_pattern, text)


class BackupAssessor:
    """Assess backup availability and integrity for recovery planning."""

    def __init__(self):
        self.backup_status = []

    def check_vss_status(self) -> dict:
        """Check Volume Shadow Copy status on Windows."""
        if os.name != "nt":
            return {"status": "not_applicable", "platform": "linux"}
        try:
            result = subprocess.run(
                ["vssadmin", "list", "shadows"],
                capture_output=True, text=True, timeout=30,
            )
            shadows = re.findall(r"Shadow Copy Volume: (.+)", result.stdout)
            deleted = "No items found" in result.stdout or "no shadow copies" in result.stdout.lower()
            return {
                "status": "deleted" if deleted else "available",
                "shadow_count": len(shadows),
                "output": result.stdout[:2000],
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def check_windows_backup(self) -> dict:
        """Check Windows Server Backup status."""
        if os.name != "nt":
            return {"status": "not_applicable"}
        try:
            result = subprocess.run(
                ["wbadmin", "get", "versions"],
                capture_output=True, text=True, timeout=30,
            )
            versions = re.findall(r"Version identifier: (.+)", result.stdout)
            return {
                "status": "available" if versions else "no_backups",
                "versions": versions[:10],
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def check_backup_directory(self, backup_path: str) -> dict:
        """Check if a backup directory exists and has recent files."""
        bp = Path(backup_path)
        if not bp.exists():
            return {"path": backup_path, "status": "not_found"}
        try:
            files = list(bp.rglob("*"))
            file_count = len([f for f in files if f.is_file()])
            if file_count == 0:
                return {"path": backup_path, "status": "empty"}
            newest = max(f.stat().st_mtime for f in files if f.is_file())
            return {
                "path": backup_path,
                "status": "available",
                "file_count": file_count,
                "newest_file": datetime.fromtimestamp(newest).isoformat(),
                "total_size_gb": round(sum(f.stat().st_size for f in files if f.is_file()) / (1024**3), 2),
            }
        except Exception as e:
            return {"path": backup_path, "status": "error", "error": str(e)}


class EncryptionScopeAssessor:
    """Assess the scope of ransomware encryption across the environment."""

    def __init__(self):
        self.scope_data = defaultdict(list)

    def assess_windows_event_logs(self) -> dict:
        """Check Windows event logs for ransomware indicators."""
        if os.name != "nt":
            return {"status": "not_applicable"}
        indicators = {}
        # Check for VSS deletion events
        try:
            result = subprocess.run(
                ["wevtutil", "qe", "Application",
                 "/q:*[System[Provider[@Name='VSS'] and (EventID=8193 or EventID=8194)]]",
                 "/f:text", "/c:20"],
                capture_output=True, text=True, timeout=30,
            )
            indicators["vss_events"] = result.stdout[:2000] if result.stdout else "No VSS events found"
        except Exception as e:
            indicators["vss_events_error"] = str(e)

        # Check for service stop events (ransomware often stops services)
        try:
            result = subprocess.run(
                ["wevtutil", "qe", "System",
                 "/q:*[System[EventID=7036]]",
                 "/f:text", "/c:50"],
                capture_output=True, text=True, timeout=30,
            )
            indicators["service_stops"] = result.stdout[:2000] if result.stdout else "No service stop events"
        except Exception as e:
            indicators["service_stops_error"] = str(e)

        return indicators

    def check_running_encryption(self) -> dict:
        """Check if encryption is still actively running."""
        try:
            if os.name == "nt":
                result = subprocess.run(["tasklist", "/FO", "CSV"], capture_output=True, text=True)
            else:
                result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
            suspicious = []
            suspicious_names = [
                "encrypt", "ransom", "lock", "crypt", "vssadmin", "wbadmin",
                "bcdedit", "wmic shadowcopy", "cipher",
            ]
            for line in result.stdout.lower().split("\n"):
                for name in suspicious_names:
                    if name in line:
                        suspicious.append(line.strip())
            return {
                "active_encryption": len(suspicious) > 0,
                "suspicious_processes": suspicious[:20],
            }
        except Exception as e:
            return {"error": str(e)}


def generate_scope_report(incident_id: str, scanner: RansomwareScanner,
                          backup: BackupAssessor, output_dir: str):
    """Generate a comprehensive ransomware scope assessment report."""
    os.makedirs(output_dir, exist_ok=True)
    report = {
        "incident_id": incident_id,
        "assessment_time": datetime.now(timezone.utc).isoformat(),
        "ransomware_family": scanner._identify_family(),
        "encryption_scope": {
            "total_encrypted_files": len(scanner.encrypted_files),
            "extension_breakdown": dict(scanner.extension_counts),
            "affected_directories": len(scanner.affected_directories),
        },
        "ransom_notes": {
            "total_found": len(scanner.ransom_notes),
            "bitcoin_addresses": list(set(
                addr for note in scanner.ransom_notes for addr in note.get("bitcoin_addresses", [])
            )),
            "onion_urls": list(set(
                url for note in scanner.ransom_notes for url in note.get("onion_urls", [])
            )),
        },
        "backup_status": {
            "vss": backup.check_vss_status(),
        },
        "decryptor_check": {
            "family": scanner._identify_family(),
            "check_sources": DECRYPTOR_SOURCES,
            "recommendation": "Check listed sources for available free decryptors",
        },
    }

    report_path = os.path.join(output_dir, f"ransomware_scope_{incident_id}.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Scope report saved to: {report_path}")

    # Export encrypted files list
    if scanner.encrypted_files:
        csv_path = os.path.join(output_dir, f"encrypted_files_{incident_id}.csv")
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=scanner.encrypted_files[0].keys())
            writer.writeheader()
            writer.writerows(scanner.encrypted_files)
        logger.info(f"Encrypted files list saved to: {csv_path}")

    return report


def main():
    parser = argparse.ArgumentParser(description="Ransomware Incident Response Automation")
    parser.add_argument("--incident-id", required=True, help="Incident tracking ID")
    parser.add_argument("--scan-paths", nargs="+", required=True, help="Paths to scan for encrypted files")
    parser.add_argument("--backup-paths", nargs="*", default=[], help="Backup paths to check integrity")
    parser.add_argument("--output-dir", default="./ransomware_ir_output", help="Output directory")
    parser.add_argument("--max-files", type=int, default=10000, help="Maximum files to scan")
    parser.add_argument("--check-processes", action="store_true", help="Check for active encryption processes")

    args = parser.parse_args()

    logger.info(f"Starting ransomware IR assessment for {args.incident_id}")

    # Scan for encrypted files
    scanner = RansomwareScanner(args.scan_paths)
    enc_results = scanner.scan_for_encrypted_files(max_files=args.max_files)
    logger.info(f"Encryption scan: {enc_results}")

    # Scan for ransom notes
    notes = scanner.scan_for_ransom_notes()
    if notes:
        logger.info(f"Found {len(notes)} ransom notes")
        for note in notes[:5]:
            logger.info(f"  Note: {note['path']}")
            if note.get("bitcoin_addresses"):
                logger.info(f"  Bitcoin addresses: {note['bitcoin_addresses']}")

    # Check backup status
    backup = BackupAssessor()
    vss_status = backup.check_vss_status()
    logger.info(f"VSS status: {vss_status['status']}")

    for bp in args.backup_paths:
        bp_status = backup.check_backup_directory(bp)
        logger.info(f"Backup path {bp}: {bp_status['status']}")

    # Check for active encryption
    if args.check_processes:
        scope_assessor = EncryptionScopeAssessor()
        active = scope_assessor.check_running_encryption()
        if active.get("active_encryption"):
            logger.critical("ACTIVE ENCRYPTION DETECTED - IMMEDIATE ISOLATION REQUIRED")
            for proc in active.get("suspicious_processes", []):
                logger.critical(f"  Suspicious process: {proc}")

    # Generate report
    report = generate_scope_report(args.incident_id, scanner, backup, args.output_dir)
    logger.info(f"Assessment complete. Family: {report['ransomware_family']}")
    logger.info(f"Total encrypted files: {report['encryption_scope']['total_encrypted_files']}")

    print(f"\nRansomware IR Assessment Complete")
    print(f"Incident ID: {args.incident_id}")
    print(f"Likely Family: {report['ransomware_family']}")
    print(f"Encrypted Files: {report['encryption_scope']['total_encrypted_files']}")
    print(f"Ransom Notes: {report['ransom_notes']['total_found']}")
    print(f"Report: {args.output_dir}/ransomware_scope_{args.incident_id}.json")


if __name__ == "__main__":
    main()
