#!/usr/bin/env python3
"""
Mobile Data Storage Security Scanner

Analyzes extracted mobile app data directories for insecure storage patterns.
Scans SharedPreferences, SQLite databases, plists, and files for sensitive data.

Usage:
    python process.py --data-dir ./extracted_app_data [--platform android|ios] [--output report.json]
"""

import argparse
import json
import os
import re
import sqlite3
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path


SENSITIVE_PATTERNS = {
    "password": re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"<]+)", re.IGNORECASE),
    "api_key": re.compile(r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{16,})", re.IGNORECASE),
    "token": re.compile(r"(?:auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*['\"]?([a-zA-Z0-9_.-]{16,})", re.IGNORECASE),
    "secret": re.compile(r"(?:secret|private[_-]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9_/+=]{16,})", re.IGNORECASE),
    "jwt": re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "credit_card": re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d)\d{8,12}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "private_key": re.compile(r"BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY"),
}


def scan_shared_preferences(prefs_dir: str) -> list:
    """Scan Android SharedPreferences XML files for sensitive data."""
    findings = []
    prefs_path = Path(prefs_dir)

    if not prefs_path.exists():
        return findings

    for xml_file in prefs_path.glob("*.xml"):
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for element in root.iter():
                name = element.get("name", "")
                value = element.text or element.get("value", "")

                for pattern_name, pattern in SENSITIVE_PATTERNS.items():
                    if pattern.search(name) or pattern.search(str(value)):
                        findings.append({
                            "source": f"SharedPreferences/{xml_file.name}",
                            "key": name,
                            "value_preview": str(value)[:50] + "..." if len(str(value)) > 50 else str(value),
                            "pattern_matched": pattern_name,
                            "severity": "CRITICAL" if pattern_name in ("password", "private_key", "credit_card") else "HIGH",
                        })
        except ET.ParseError:
            findings.append({
                "source": f"SharedPreferences/{xml_file.name}",
                "key": "PARSE_ERROR",
                "pattern_matched": "error",
                "severity": "INFO",
            })

    return findings


def scan_sqlite_databases(db_dir: str) -> list:
    """Scan SQLite databases for sensitive data."""
    findings = []
    db_path = Path(db_dir)

    if not db_path.exists():
        return findings

    for db_file in list(db_path.glob("*.db")) + list(db_path.glob("*.sqlite")):
        try:
            conn = sqlite3.connect(str(db_file))
            cursor = conn.cursor()

            # Check if database is encrypted
            try:
                cursor.execute("SELECT count(*) FROM sqlite_master;")
                findings.append({
                    "source": f"Database/{db_file.name}",
                    "key": "encryption_status",
                    "value_preview": "Database is NOT encrypted (SQLCipher not used)",
                    "pattern_matched": "unencrypted_database",
                    "severity": "HIGH",
                })
            except sqlite3.DatabaseError:
                findings.append({
                    "source": f"Database/{db_file.name}",
                    "key": "encryption_status",
                    "value_preview": "Database appears to be encrypted",
                    "pattern_matched": "encrypted_database",
                    "severity": "INFO",
                })
                continue

            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]

            for table in tables:
                # Get column names
                cursor.execute(f"PRAGMA table_info('{table}');")
                columns = [col[1] for col in cursor.fetchall()]

                # Check column names for sensitive patterns
                sensitive_cols = []
                for col in columns:
                    col_lower = col.lower()
                    if any(s in col_lower for s in ["password", "token", "secret", "key", "auth", "credential", "ssn", "credit"]):
                        sensitive_cols.append(col)

                if sensitive_cols:
                    # Sample data from sensitive columns
                    cols_str = ", ".join(sensitive_cols)
                    cursor.execute(f"SELECT {cols_str} FROM '{table}' LIMIT 3;")
                    samples = cursor.fetchall()

                    findings.append({
                        "source": f"Database/{db_file.name}/{table}",
                        "key": f"sensitive_columns: {', '.join(sensitive_cols)}",
                        "value_preview": str(samples[:2]) if samples else "empty",
                        "pattern_matched": "sensitive_database_columns",
                        "severity": "CRITICAL",
                    })

                # Full text search in all columns
                try:
                    cursor.execute(f"SELECT * FROM '{table}' LIMIT 100;")
                    rows = cursor.fetchall()
                    for row in rows:
                        row_text = " ".join(str(cell) for cell in row if cell)
                        for pattern_name, pattern in SENSITIVE_PATTERNS.items():
                            if pattern.search(row_text):
                                findings.append({
                                    "source": f"Database/{db_file.name}/{table}",
                                    "key": f"row_data_match",
                                    "value_preview": row_text[:100],
                                    "pattern_matched": pattern_name,
                                    "severity": "HIGH",
                                })
                                break
                except sqlite3.OperationalError:
                    pass

            conn.close()

        except sqlite3.Error as e:
            findings.append({
                "source": f"Database/{db_file.name}",
                "key": "error",
                "value_preview": str(e),
                "pattern_matched": "error",
                "severity": "INFO",
            })

    return findings


def scan_plist_files(plist_dir: str) -> list:
    """Scan iOS plist files for sensitive data."""
    findings = []
    plist_path = Path(plist_dir)

    if not plist_path.exists():
        return findings

    for plist_file in plist_path.rglob("*.plist"):
        try:
            with open(plist_file, "r", errors="replace") as f:
                content = f.read()

            for pattern_name, pattern in SENSITIVE_PATTERNS.items():
                matches = pattern.findall(content)
                if matches:
                    findings.append({
                        "source": f"Plist/{plist_file.name}",
                        "key": pattern_name,
                        "value_preview": str(matches[0])[:50],
                        "pattern_matched": pattern_name,
                        "severity": "HIGH",
                    })
        except (OSError, UnicodeDecodeError):
            pass

    return findings


def scan_general_files(data_dir: str) -> list:
    """Scan general files for sensitive data and permission issues."""
    findings = []
    data_path = Path(data_dir)

    for file_path in data_path.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.suffix in (".so", ".dylib", ".png", ".jpg", ".gif", ".mp3", ".mp4"):
            continue
        if file_path.stat().st_size > 5 * 1024 * 1024:
            continue

        try:
            with open(file_path, "r", errors="replace") as f:
                content = f.read(10000)

            for pattern_name, pattern in SENSITIVE_PATTERNS.items():
                matches = pattern.findall(content)
                if matches:
                    findings.append({
                        "source": f"File/{file_path.relative_to(data_path)}",
                        "key": pattern_name,
                        "value_preview": str(matches[0])[:50],
                        "pattern_matched": pattern_name,
                        "severity": "HIGH" if pattern_name in ("password", "private_key") else "MEDIUM",
                    })
        except (OSError, UnicodeDecodeError):
            pass

    return findings


def main():
    parser = argparse.ArgumentParser(description="Mobile Data Storage Security Scanner")
    parser.add_argument("--data-dir", required=True, help="Extracted app data directory")
    parser.add_argument("--platform", choices=["android", "ios"], default="android")
    parser.add_argument("--output", default="storage_scan.json", help="Output report path")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        print(f"[-] Directory not found: {args.data_dir}")
        sys.exit(1)

    all_findings = []

    if args.platform == "android":
        print("[*] Scanning SharedPreferences...")
        all_findings.extend(scan_shared_preferences(str(data_dir / "shared_prefs")))

        print("[*] Scanning SQLite databases...")
        all_findings.extend(scan_sqlite_databases(str(data_dir / "databases")))
    else:
        print("[*] Scanning plist files...")
        all_findings.extend(scan_plist_files(str(data_dir / "Library" / "Preferences")))

        print("[*] Scanning SQLite databases...")
        all_findings.extend(scan_sqlite_databases(str(data_dir)))

    print("[*] Scanning general files...")
    all_findings.extend(scan_general_files(str(data_dir)))

    # Generate report
    severity_counts = {}
    for f in all_findings:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    report = {
        "scan": {
            "data_directory": str(data_dir),
            "platform": args.platform,
            "date": datetime.now().isoformat(),
        },
        "summary": {
            "total_findings": len(all_findings),
            "by_severity": severity_counts,
        },
        "findings": all_findings,
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[+] Scan complete: {len(all_findings)} findings")
    print(f"[+] Report saved: {args.output}")
    for sev, count in sorted(severity_counts.items()):
        print(f"    {sev}: {count}")


if __name__ == "__main__":
    main()
