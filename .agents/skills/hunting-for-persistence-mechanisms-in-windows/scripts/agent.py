#!/usr/bin/env python3
"""Agent for hunting Windows persistence mechanisms across registry, services, and scheduled tasks."""

import json
import argparse
import subprocess
import re
from datetime import datetime
from pathlib import Path

REGISTRY_PERSISTENCE_KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    r"HKCU\Environment",
]

SUSPICIOUS_INDICATORS = [
    r"\\temp\\", r"\\tmp\\", r"\\appdata\\local\\temp\\",
    r"powershell.*-enc", r"cmd\.exe.*/c\s+",
    r"\\users\\public\\", r"\\programdata\\",
    r"mshta\.exe", r"rundll32\.exe", r"regsvr32\.exe",
    r"wscript\.exe", r"cscript\.exe",
    r"base64", r"iex\s*\(", r"downloadstring",
]


def enumerate_registry_persistence():
    """Enumerate common Windows registry persistence locations using reg query."""
    findings = []
    for key in REGISTRY_PERSISTENCE_KEYS:
        try:
            result = subprocess.run(
                ["reg", "query", key], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                entries = parse_reg_output(result.stdout, key)
                for entry in entries:
                    entry["suspicious"] = any(
                        re.search(p, entry.get("value", ""), re.I)
                        for p in SUSPICIOUS_INDICATORS
                    )
                    findings.append(entry)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "total_entries": len(findings),
        "suspicious_entries": sum(1 for f in findings if f.get("suspicious")),
        "findings": findings,
    }


def parse_reg_output(output, parent_key):
    """Parse reg query output into structured entries."""
    entries = []
    current_key = parent_key
    for line in output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.startswith("HK"):
            current_key = line
            continue
        parts = re.split(r"\s{2,}", line, maxsplit=2)
        if len(parts) >= 3:
            entries.append({
                "key": current_key,
                "name": parts[0],
                "type": parts[1],
                "value": parts[2],
            })
    return entries


def enumerate_scheduled_tasks():
    """List scheduled tasks and flag suspicious ones."""
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True, text=True, timeout=30
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"error": "schtasks not available"}
    findings = []
    import csv
    from io import StringIO
    reader = csv.DictReader(StringIO(result.stdout))
    for row in reader:
        task_name = row.get("TaskName", "")
        action = row.get("Task To Run", "")
        author = row.get("Author", "")
        suspicious = any(re.search(p, action, re.I) for p in SUSPICIOUS_INDICATORS)
        if suspicious or "\\Microsoft\\" not in task_name:
            findings.append({
                "task_name": task_name,
                "action": action[:500],
                "author": author,
                "status": row.get("Status", ""),
                "next_run": row.get("Next Run Time", ""),
                "suspicious": suspicious,
            })
    return {
        "total_tasks": len(findings),
        "suspicious_tasks": sum(1 for f in findings if f["suspicious"]),
        "findings": findings,
    }


def enumerate_services():
    """List Windows services and flag those running from unusual paths."""
    try:
        result = subprocess.run(
            ["wmic", "service", "get", "Name,PathName,StartMode,State", "/format:csv"],
            capture_output=True, text=True, timeout=30
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"error": "wmic not available"}
    findings = []
    for line in result.stdout.strip().split("\n")[1:]:
        parts = line.strip().split(",")
        if len(parts) >= 5:
            path = parts[3]
            suspicious = any(re.search(p, path, re.I) for p in SUSPICIOUS_INDICATORS)
            findings.append({
                "name": parts[1], "path": path,
                "start_mode": parts[4] if len(parts) > 4 else "",
                "state": parts[2], "suspicious": suspicious,
            })
    return {
        "total_services": len(findings),
        "suspicious_services": sum(1 for f in findings if f["suspicious"]),
        "findings": [f for f in findings if f["suspicious"]],
    }


def main():
    parser = argparse.ArgumentParser(description="Hunt for Windows persistence mechanisms")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("registry", help="Enumerate registry persistence keys")
    sub.add_parser("tasks", help="Enumerate scheduled tasks")
    sub.add_parser("services", help="Enumerate suspicious services")
    sub.add_parser("all", help="Run all persistence hunts")
    args = parser.parse_args()
    if args.command == "registry":
        result = enumerate_registry_persistence()
    elif args.command == "tasks":
        result = enumerate_scheduled_tasks()
    elif args.command == "services":
        result = enumerate_services()
    elif args.command == "all":
        result = {
            "registry": enumerate_registry_persistence(),
            "scheduled_tasks": enumerate_scheduled_tasks(),
            "services": enumerate_services(),
            "timestamp": datetime.utcnow().isoformat(),
        }
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
