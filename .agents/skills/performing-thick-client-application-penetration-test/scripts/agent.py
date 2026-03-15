#!/usr/bin/env python3
"""Agent for thick client application penetration testing.

Performs static analysis (strings extraction, .NET detection),
dynamic analysis (process monitoring, DLL search order checks),
local storage auditing, and API traffic interception assessment.
"""

import subprocess
import json
import sys
import os
import re
import sqlite3
from pathlib import Path
from datetime import datetime


class ThickClientPentestAgent:
    """Performs security assessment of thick/fat client applications."""

    def __init__(self, app_path, output_dir="./thick_client_pentest"):
        self.app_path = Path(app_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def extract_strings(self, min_length=6):
        """Extract readable strings from binary for credential/URL discovery."""
        patterns = {
            "url": re.compile(r'https?://[^\s"\'<>]{5,200}'),
            "email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            "ip_addr": re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
            "password_hint": re.compile(
                r'(?i)(password|passwd|pwd|secret|api.?key|token|'
                r'connectionstring|jdbc|bearer)', re.IGNORECASE),
            "sql_query": re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE)\s+', re.IGNORECASE),
        }
        results = {k: [] for k in patterns}
        try:
            with open(self.app_path, "rb") as f:
                data = f.read()
            text = data.decode("ascii", errors="ignore")
            for name, pattern in patterns.items():
                matches = pattern.findall(text)
                results[name] = list(set(matches))[:50]

            if results["password_hint"]:
                self.findings.append({
                    "type": "Credential Reference in Binary",
                    "severity": "Medium",
                    "details": f"Found {len(results['password_hint'])} credential-related strings",
                })
            if results["sql_query"]:
                self.findings.append({
                    "type": "SQL Queries in Binary",
                    "severity": "Medium",
                    "details": "Embedded SQL may be vulnerable to injection",
                })
        except (OSError, PermissionError) as exc:
            results["error"] = str(exc)
        return results

    def detect_framework(self):
        """Detect the application framework (.NET, Java, Electron, C++)."""
        try:
            with open(self.app_path, "rb") as f:
                header = f.read(4096)

            if b"BSJB" in header or b".NET" in header or b"mscorlib" in header:
                return {"framework": ".NET", "decompiler": "dnSpy / ILSpy"}
            if b"PK" in header[:4]:
                return {"framework": "Java (JAR)", "decompiler": "JD-GUI / JADX"}
            if b"asar" in header or b"electron" in header:
                return {"framework": "Electron", "tool": "asar extract"}
            return {"framework": "Native (C/C++)", "decompiler": "Ghidra / IDA Pro"}
        except OSError as exc:
            return {"error": str(exc)}

    def check_local_storage(self, app_name=None):
        """Scan common local storage locations for sensitive data."""
        app_name = app_name or self.app_path.stem
        locations = []
        appdata = os.environ.get("APPDATA", "")
        localappdata = os.environ.get("LOCALAPPDATA", "")

        search_dirs = [
            Path(appdata) / app_name if appdata else None,
            Path(localappdata) / app_name if localappdata else None,
            self.app_path.parent,
        ]
        sensitive_exts = {".db", ".sqlite", ".sqlite3", ".json", ".xml",
                         ".config", ".ini", ".cfg", ".log"}

        for search_dir in search_dirs:
            if search_dir is None or not search_dir.exists():
                continue
            for root, dirs, files in os.walk(search_dir):
                for fname in files:
                    fpath = Path(root) / fname
                    if fpath.suffix.lower() in sensitive_exts:
                        size = fpath.stat().st_size
                        locations.append({
                            "path": str(fpath), "type": fpath.suffix,
                            "size_bytes": size,
                        })

        if locations:
            self.findings.append({
                "type": "Sensitive Local Files",
                "severity": "Medium",
                "details": f"Found {len(locations)} potentially sensitive files",
            })
        return locations

    def audit_sqlite_databases(self, db_paths):
        """Check local SQLite databases for plaintext credentials."""
        results = []
        for db_path in db_paths:
            try:
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [r[0] for r in cursor.fetchall()]

                sensitive_tables = []
                for table in tables:
                    lower = table.lower()
                    if any(kw in lower for kw in
                           ["user", "account", "credential", "auth",
                            "login", "password", "token", "session"]):
                        cursor.execute(f'SELECT COUNT(*) FROM "{table}"')
                        count = cursor.fetchone()[0]
                        sensitive_tables.append({"table": table, "rows": count})

                if sensitive_tables:
                    self.findings.append({
                        "type": "Sensitive SQLite Database",
                        "severity": "High",
                        "details": f"{db_path}: {sensitive_tables}",
                    })
                results.append({"database": db_path, "tables": tables,
                                "sensitive_tables": sensitive_tables})
                conn.close()
            except sqlite3.Error as exc:
                results.append({"database": db_path, "error": str(exc)})
        return results

    def check_dll_hijack_paths(self):
        """Check for DLL hijacking via writable directories in PATH."""
        writable_dirs = []
        path_dirs = os.environ.get("PATH", "").split(os.pathsep)
        for d in path_dirs:
            if os.path.isdir(d) and os.access(d, os.W_OK):
                writable_dirs.append(d)

        app_dir = str(self.app_path.parent)
        app_dir_writable = os.access(app_dir, os.W_OK)

        if writable_dirs or app_dir_writable:
            self.findings.append({
                "type": "DLL Hijacking Risk",
                "severity": "High",
                "details": f"Writable PATH dirs: {len(writable_dirs)}, "
                           f"App dir writable: {app_dir_writable}",
            })
        return {"writable_path_dirs": writable_dirs,
                "app_dir_writable": app_dir_writable}

    def generate_report(self):
        """Generate comprehensive pentest findings report."""
        report = {
            "target": str(self.app_path),
            "report_date": datetime.utcnow().isoformat(),
            "framework": self.detect_framework(),
            "total_findings": len(self.findings),
            "critical": sum(1 for f in self.findings if f["severity"] == "Critical"),
            "high": sum(1 for f in self.findings if f["severity"] == "High"),
            "medium": sum(1 for f in self.findings if f["severity"] == "Medium"),
            "findings": self.findings,
        }
        report_path = self.output_dir / "thick_client_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <application.exe> [output_dir]")
        sys.exit(1)
    app_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "./thick_client_pentest"
    agent = ThickClientPentestAgent(app_path, output_dir)
    agent.extract_strings()
    agent.check_local_storage()
    agent.check_dll_hijack_paths()
    agent.generate_report()


if __name__ == "__main__":
    main()
