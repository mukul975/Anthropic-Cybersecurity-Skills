#!/usr/bin/env python3
"""
Thick Client Penetration Test — Static Analysis Helper

Performs basic static analysis on thick client applications: string extraction,
config file scanning, and DLL dependency analysis.

Usage:
    python process.py --app-dir "C:/Program Files/TargetApp" --output ./results
"""

import os
import re
import json
import argparse
import datetime
from pathlib import Path


SENSITIVE_PATTERNS = {
    "password": re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']+)'),
    "api_key": re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([^\s"\']+)'),
    "connection_string": re.compile(r'(?i)(connection[_-]?string|jdbc:)\s*[=:]\s*["\']?([^\s"\']+)'),
    "secret": re.compile(r'(?i)(secret|token)\s*[=:]\s*["\']?([^\s"\']+)'),
    "url_with_creds": re.compile(r'https?://[^:]+:[^@]+@[\w.]+'),
    "hardcoded_ip": re.compile(r'\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b'),
}


def extract_strings(filepath: str, min_length: int = 8) -> list[str]:
    """Extract printable strings from a binary file."""
    strings = []
    try:
        with open(filepath, "rb") as f:
            data = f.read()

        current = []
        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append("".join(current))
                current = []
        if len(current) >= min_length:
            strings.append("".join(current))
    except (PermissionError, OSError):
        pass
    return strings


def scan_for_secrets(strings: list[str]) -> list[dict]:
    """Scan extracted strings for sensitive patterns."""
    findings = []
    for s in strings:
        for name, pattern in SENSITIVE_PATTERNS.items():
            match = pattern.search(s)
            if match:
                findings.append({
                    "type": name,
                    "match": s[:200],
                    "severity": "High" if name in ("password", "connection_string", "secret") else "Medium"
                })
                break
    return findings


def scan_config_files(app_dir: str) -> list[dict]:
    """Scan configuration files for sensitive data."""
    config_extensions = {".config", ".xml", ".json", ".ini", ".properties", ".yaml", ".yml", ".cfg"}
    findings = []

    for root, dirs, files in os.walk(app_dir):
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in config_extensions:
                filepath = os.path.join(root, filename)
                try:
                    with open(filepath, encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    for name, pattern in SENSITIVE_PATTERNS.items():
                        matches = pattern.findall(content)
                        for match in matches:
                            findings.append({
                                "file": filepath,
                                "type": name,
                                "match": str(match)[:200],
                                "severity": "High"
                            })
                except (PermissionError, OSError):
                    continue
    return findings


def analyze_dlls(app_dir: str) -> list[dict]:
    """Analyze DLL dependencies for potential hijacking."""
    dlls = []
    for root, dirs, files in os.walk(app_dir):
        for filename in files:
            if filename.lower().endswith(".dll"):
                filepath = os.path.join(root, filename)
                dlls.append({
                    "name": filename,
                    "path": filepath,
                    "writable": os.access(filepath, os.W_OK),
                    "size": os.path.getsize(filepath)
                })

    writable = [d for d in dlls if d["writable"]]
    return dlls, writable


def generate_report(app_dir: str, string_findings: list[dict],
                     config_findings: list[dict], dll_info: tuple,
                     output_dir: Path) -> str:
    """Generate thick client analysis report."""
    report_file = output_dir / "thick_client_report.md"
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    all_dlls, writable_dlls = dll_info

    with open(report_file, "w") as f:
        f.write("# Thick Client Static Analysis Report\n\n")
        f.write(f"**Application:** {app_dir}\n")
        f.write(f"**Generated:** {timestamp}\n\n---\n\n")

        f.write("## Binary String Analysis\n\n")
        if string_findings:
            f.write(f"Found **{len(string_findings)}** potentially sensitive strings:\n\n")
            f.write("| Type | Match | Severity |\n|------|-------|----------|\n")
            for finding in string_findings[:50]:
                f.write(f"| {finding['type']} | `{finding['match'][:80]}` | {finding['severity']} |\n")
        else:
            f.write("No sensitive strings detected in binaries.\n")
        f.write("\n")

        f.write("## Configuration File Analysis\n\n")
        if config_findings:
            f.write(f"Found **{len(config_findings)}** sensitive entries in configs:\n\n")
            for finding in config_findings[:20]:
                f.write(f"- **{finding['type']}** in `{finding['file']}`: `{finding['match'][:80]}`\n")
        else:
            f.write("No sensitive data found in configuration files.\n")
        f.write("\n")

        f.write("## DLL Analysis\n\n")
        f.write(f"Total DLLs: **{len(all_dlls)}**\n")
        f.write(f"Writable DLLs (potential hijacking): **{len(writable_dlls)}**\n\n")
        if writable_dlls:
            f.write("| DLL | Path |\n|-----|------|\n")
            for dll in writable_dlls:
                f.write(f"| {dll['name']} | {dll['path']} |\n")
        f.write("\n")

    print(f"[+] Report: {report_file}")
    return str(report_file)


def main():
    parser = argparse.ArgumentParser(description="Thick Client Static Analysis")
    parser.add_argument("--app-dir", required=True, help="Application installation directory")
    parser.add_argument("--output", default="./results")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Scanning {args.app_dir}...")

    # Scan binaries for strings
    all_findings = []
    for root, dirs, files in os.walk(args.app_dir):
        for filename in files:
            if filename.lower().endswith((".exe", ".dll")):
                filepath = os.path.join(root, filename)
                strings = extract_strings(filepath)
                findings = scan_for_secrets(strings)
                all_findings.extend(findings)

    # Scan config files
    config_findings = scan_config_files(args.app_dir)

    # Analyze DLLs
    dll_info = analyze_dlls(args.app_dir)

    generate_report(args.app_dir, all_findings, config_findings, dll_info, output_dir)
    print("[+] Analysis complete")


if __name__ == "__main__":
    main()
