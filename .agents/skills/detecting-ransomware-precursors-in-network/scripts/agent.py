#!/usr/bin/env python3
"""Agent for detecting ransomware precursor activity in network traffic and logs."""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone


RANSOMWARE_PORTS = {445, 3389, 4444, 5985, 5986, 135, 139, 8443}
SUSPICIOUS_PROCESSES = [
    "vssadmin.exe", "wmic.exe", "bcdedit.exe", "wbadmin.exe",
    "powershell.exe", "cmd.exe", "certutil.exe", "bitsadmin.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "cscript.exe",
]
SHADOW_COPY_PATTERNS = [
    r"vssadmin\s+delete\s+shadows",
    r"wmic\s+shadowcopy\s+delete",
    r"bcdedit.*recoveryenabled.*no",
    r"wbadmin\s+delete\s+(catalog|systemstatebackup)",
]
SMB_LATERAL_PATTERNS = [
    r"\\\\[\d\.]+\\(C\$|ADMIN\$|IPC\$)",
    r"psexec",
    r"wmiexec",
]


def parse_zeek_conn_log(log_path):
    """Parse Zeek conn.log for suspicious network connections."""
    alerts = []
    try:
        with open(log_path, "r") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                fields = line.strip().split("\t")
                if len(fields) < 7:
                    continue
                src_ip, src_port, dst_ip, dst_port = fields[2], fields[3], fields[4], fields[5]
                try:
                    dp = int(dst_port)
                except ValueError:
                    continue
                if dp in RANSOMWARE_PORTS:
                    alerts.append({
                        "type": "suspicious_port",
                        "src": src_ip,
                        "dst": dst_ip,
                        "port": dp,
                        "detail": f"Connection to ransomware-associated port {dp}",
                    })
    except FileNotFoundError:
        print(f"[!] Log file not found: {log_path}")
    return alerts


def analyze_event_logs_windows():
    """Check Windows event logs for ransomware precursors."""
    alerts = []
    queries = [
        ("Shadow copy deletion", "Get-WinEvent -FilterHashtable @{LogName='System';Id=7036} "
         "| Where-Object {$_.Message -match 'Volume Shadow Copy'} | Select-Object -First 10 "
         "| ConvertTo-Json"),
        ("RDP brute force", "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} "
         "| Select-Object -First 20 | Group-Object {$_.Properties[5].Value} "
         "| Where-Object {$_.Count -gt 5} | ConvertTo-Json"),
        ("Service installs", "Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} "
         "| Select-Object -First 10 | ConvertTo-Json"),
    ]
    for name, ps_cmd in queries:
        try:
            result = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                text=True, errors="replace", timeout=30
            )
            if result.strip():
                data = json.loads(result) if result.strip().startswith(("[", "{")) else result
                alerts.append({"check": name, "findings": data})
        except (subprocess.SubprocessError, json.JSONDecodeError):
            pass
    return alerts


def scan_process_list():
    """Check running processes for ransomware tooling."""
    suspicious = []
    if sys.platform == "win32":
        try:
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"], text=True, errors="replace"
            )
            for line in out.splitlines():
                parts = line.strip('"').split('","')
                if parts:
                    pname = parts[0].lower()
                    for sp in SUSPICIOUS_PROCESSES:
                        if pname == sp.lower():
                            suspicious.append({"process": pname, "pid": parts[1] if len(parts) > 1 else "?"})
        except subprocess.SubprocessError:
            pass
    else:
        try:
            out = subprocess.check_output(["ps", "-eo", "pid,comm", "--no-headers"], text=True)
            for line in out.splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2:
                    for sp in SUSPICIOUS_PROCESSES:
                        if parts[1].strip().lower() == sp.replace(".exe", ""):
                            suspicious.append({"process": parts[1].strip(), "pid": parts[0]})
        except subprocess.SubprocessError:
            pass
    return suspicious


def check_file_encryption_activity(directory, threshold=50):
    """Detect mass file renaming or new encrypted extensions."""
    suspicious_exts = {".encrypted", ".locked", ".crypto", ".crypt", ".enc",
                       ".locky", ".cerber", ".zepto", ".thor", ".aaa"}
    findings = []
    count = 0
    try:
        for root, _, files in os.walk(directory):
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in suspicious_exts:
                    count += 1
                    if count <= 10:
                        findings.append(os.path.join(root, f))
            if count >= threshold:
                break
    except PermissionError:
        pass
    return {"encrypted_file_count": count, "samples": findings, "threshold_exceeded": count >= threshold}


def main():
    parser = argparse.ArgumentParser(
        description="Detect ransomware precursor activity in network and host"
    )
    parser.add_argument("--conn-log", help="Path to Zeek conn.log")
    parser.add_argument("--scan-dir", help="Directory to scan for encrypted files")
    parser.add_argument("--check-processes", action="store_true", help="Scan running processes")
    parser.add_argument("--windows-logs", action="store_true", help="Check Windows event logs")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    args = parser.parse_args()

    print("[*] Ransomware Precursor Detection Agent")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "findings": {}}

    if args.conn_log:
        alerts = parse_zeek_conn_log(args.conn_log)
        report["findings"]["network"] = alerts
        print(f"[*] Network alerts: {len(alerts)}")

    if args.check_processes:
        procs = scan_process_list()
        report["findings"]["suspicious_processes"] = procs
        print(f"[*] Suspicious processes: {len(procs)}")

    if args.windows_logs and sys.platform == "win32":
        events = analyze_event_logs_windows()
        report["findings"]["windows_events"] = events
        print(f"[*] Windows event findings: {len(events)}")

    if args.scan_dir:
        enc = check_file_encryption_activity(args.scan_dir)
        report["findings"]["encryption_activity"] = enc
        print(f"[*] Encrypted files found: {enc['encrypted_file_count']}")

    total = sum(
        len(v) if isinstance(v, list) else (1 if isinstance(v, dict) and v.get("threshold_exceeded") else 0)
        for v in report["findings"].values()
    )
    report["risk_level"] = "CRITICAL" if total >= 10 else "HIGH" if total >= 5 else "MEDIUM" if total > 0 else "LOW"
    print(f"[*] Overall risk: {report['risk_level']}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
