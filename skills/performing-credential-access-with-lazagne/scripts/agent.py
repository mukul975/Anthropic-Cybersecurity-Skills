#!/usr/bin/env python3
"""LaZagne credential access detection agent.

Detects evidence of LaZagne credential harvesting tool execution on
endpoints by scanning for process artifacts, file system indicators,
and Windows event log entries associated with credential dumping.
Used for defensive detection and incident response, not offensive use.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone


LAZAGNE_INDICATORS = {
    "file_paths": [
        "lazagne.exe", "LaZagne.exe", "laZagne.py",
        "lazagne_output.txt", "credentials.txt",
    ],
    "process_names": [
        "lazagne.exe", "python.exe lazagne",
    ],
    "registry_keys": [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    ],
    "event_ids": {
        4688: "Process creation (look for lazagne.exe or suspicious python)",
        4663: "File access audit (credential store access)",
        4656: "Handle request to credential objects",
    },
    "credential_stores": [
        # Windows
        r"%APPDATA%\Mozilla\Firefox\Profiles",
        r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data",
        r"%APPDATA%\Opera Software\Opera Stable\Login Data",
        # Linux
        os.path.expanduser("~/.mozilla/firefox"),
        os.path.expanduser("~/.config/google-chrome/Default/Login Data"),
        "/etc/shadow",
        os.path.expanduser("~/.ssh"),
    ],
}


def scan_filesystem_indicators(search_paths=None):
    """Scan file system for LaZagne artifacts."""
    findings = []
    if search_paths is None:
        if sys.platform == "win32":
            search_paths = [
                os.environ.get("TEMP", "C:\\Temp"),
                os.environ.get("USERPROFILE", "C:\\Users\\Default"),
                "C:\\Windows\\Temp",
            ]
        else:
            search_paths = ["/tmp", "/var/tmp", os.path.expanduser("~")]

    print("[*] Scanning filesystem for LaZagne indicators...")
    for search_path in search_paths:
        if not os.path.isdir(search_path):
            continue
        for root, dirs, files in os.walk(search_path):
            for fname in files:
                fname_lower = fname.lower()
                for indicator in LAZAGNE_INDICATORS["file_paths"]:
                    if indicator.lower() in fname_lower:
                        full_path = os.path.join(root, fname)
                        stat = os.stat(full_path)
                        findings.append({
                            "type": "file_indicator",
                            "path": full_path,
                            "indicator": indicator,
                            "size": stat.st_size,
                            "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                            "severity": "CRITICAL",
                            "description": f"LaZagne artifact found: {fname}",
                        })
            # Limit directory depth to avoid slow scans
            if root.count(os.sep) - search_path.count(os.sep) > 3:
                dirs.clear()

    return findings


def check_windows_event_logs():
    """Check Windows Security event logs for LaZagne-related activity."""
    findings = []
    if sys.platform != "win32":
        return findings

    print("[*] Checking Windows Security event logs...")

    # Check for process creation events matching LaZagne
    ps_script = """
    Get-WinEvent -FilterHashtable @{
        LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-7)
    } -MaxEvents 1000 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Properties[5].Value -match 'lazagne|LaZagne' -or
        $_.Properties[8].Value -match 'lazagne|LaZagne'
    } |
    Select-Object TimeCreated, @{N='ProcessName';E={$_.Properties[5].Value}},
        @{N='CommandLine';E={$_.Properties[8].Value}},
        @{N='User';E={$_.Properties[1].Value}} |
    ConvertTo-Json
    """
    result = subprocess.run(
        ["powershell", "-Command", ps_script],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode == 0 and result.stdout.strip():
        try:
            events = json.loads(result.stdout)
            if isinstance(events, dict):
                events = [events]
            for evt in events:
                findings.append({
                    "type": "event_log",
                    "event_id": 4688,
                    "time": str(evt.get("TimeCreated", "")),
                    "process": evt.get("ProcessName", ""),
                    "command_line": evt.get("CommandLine", "")[:200],
                    "user": evt.get("User", ""),
                    "severity": "CRITICAL",
                    "description": "LaZagne process execution detected in event logs",
                })
        except json.JSONDecodeError:
            pass

    # Check for credential file access (Event ID 4663)
    ps_script2 = """
    Get-WinEvent -FilterHashtable @{
        LogName='Security'; Id=4663; StartTime=(Get-Date).AddDays(-7)
    } -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Properties[6].Value -match 'Login Data|logins.json|Credentials|vault'
    } |
    Select-Object TimeCreated, @{N='ObjectName';E={$_.Properties[6].Value}},
        @{N='ProcessName';E={$_.Properties[11].Value}} |
    ConvertTo-Json
    """
    result = subprocess.run(
        ["powershell", "-Command", ps_script2],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode == 0 and result.stdout.strip():
        try:
            events = json.loads(result.stdout)
            if isinstance(events, dict):
                events = [events]
            for evt in events:
                findings.append({
                    "type": "credential_access",
                    "event_id": 4663,
                    "time": str(evt.get("TimeCreated", "")),
                    "object": evt.get("ObjectName", ""),
                    "process": evt.get("ProcessName", ""),
                    "severity": "HIGH",
                    "description": "Credential store accessed by process",
                })
        except json.JSONDecodeError:
            pass

    return findings


def check_credential_store_integrity():
    """Check if credential stores have been recently accessed unusually."""
    findings = []
    print("[*] Checking credential store integrity...")

    stores_to_check = []
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "")
        localappdata = os.environ.get("LOCALAPPDATA", "")
        stores_to_check = [
            (os.path.join(localappdata, "Google", "Chrome", "User Data", "Default", "Login Data"), "Chrome"),
            (os.path.join(appdata, "Mozilla", "Firefox"), "Firefox"),
        ]
    else:
        stores_to_check = [
            (os.path.expanduser("~/.config/google-chrome/Default/Login Data"), "Chrome"),
            (os.path.expanduser("~/.mozilla/firefox"), "Firefox"),
            (os.path.expanduser("~/.ssh"), "SSH Keys"),
        ]

    for path, store_name in stores_to_check:
        if os.path.exists(path):
            if os.path.isfile(path):
                stat = os.stat(path)
                access_time = datetime.fromtimestamp(stat.st_atime, tz=timezone.utc)
                mod_time = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                findings.append({
                    "type": "credential_store",
                    "store": store_name,
                    "path": path,
                    "last_accessed": access_time.isoformat(),
                    "last_modified": mod_time.isoformat(),
                    "severity": "INFO",
                })

    return findings


def format_summary(all_findings):
    """Print detection summary."""
    print(f"\n{'='*60}")
    print("  LaZagne Credential Access Detection Report")
    print(f"{'='*60}")

    file_findings = [f for f in all_findings if f["type"] == "file_indicator"]
    event_findings = [f for f in all_findings if f["type"] in ("event_log", "credential_access")]
    store_findings = [f for f in all_findings if f["type"] == "credential_store"]

    print(f"  File Indicators  : {len(file_findings)}")
    print(f"  Event Log Hits   : {len(event_findings)}")
    print(f"  Credential Stores: {len(store_findings)}")

    critical = [f for f in all_findings if f.get("severity") == "CRITICAL"]
    if critical:
        print(f"\n  CRITICAL FINDINGS ({len(critical)}):")
        for f in critical:
            print(f"    [{f['type']}] {f.get('description', f.get('path', ''))}")

    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    return severity_counts


def main():
    parser = argparse.ArgumentParser(
        description="LaZagne credential access detection agent (defensive use)"
    )
    parser.add_argument("--search-paths", nargs="+", help="Paths to scan for artifacts")
    parser.add_argument("--skip-events", action="store_true", help="Skip Windows event log check")
    parser.add_argument("--skip-stores", action="store_true", help="Skip credential store check")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    all_findings = []
    all_findings.extend(scan_filesystem_indicators(args.search_paths))
    if not args.skip_events:
        all_findings.extend(check_windows_event_logs())
    if not args.skip_stores:
        all_findings.extend(check_credential_store_integrity())

    severity_counts = format_summary(all_findings)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "LaZagne Detection",
        "findings": all_findings,
        "severity_counts": severity_counts,
        "risk_level": (
            "CRITICAL" if severity_counts.get("CRITICAL", 0) > 0
            else "HIGH" if severity_counts.get("HIGH", 0) > 0
            else "LOW"
        ),
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
