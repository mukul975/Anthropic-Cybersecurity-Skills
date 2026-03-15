#!/usr/bin/env python3
"""Agent for hunting registry-based persistence mechanisms on Windows."""

import json
import argparse
import subprocess
import re
from datetime import datetime

PERSISTENCE_KEYS = {
    "run_keys": [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
    ],
    "winlogon": [
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ],
    "ifeo": [
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    ],
    "appinit": [
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    ],
    "shell_extensions": [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
    ],
    "browser_helpers": [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    ],
    "com_hijack": [
        r"HKCU\SOFTWARE\Classes\CLSID",
    ],
    "boot_execute": [
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
    ],
}

SUSPICIOUS_PATTERNS = [
    r"\\temp\\", r"\\tmp\\", r"\\appdata\\local\\temp",
    r"powershell.*-enc", r"powershell.*-nop",
    r"cmd\.exe\s+/c\s+", r"mshta\.exe", r"rundll32\.exe.*javascript",
    r"regsvr32\.exe.*/s\s+/n\s+/u\s+/i:",
    r"\\users\\public\\", r"\\programdata\\[^m]",
    r"certutil.*-decode", r"bitsadmin.*transfer",
    r"base64", r"downloadstring", r"iex\s*\(",
]


def scan_persistence_keys(categories=None):
    """Scan specified registry persistence key categories."""
    if categories is None:
        categories = list(PERSISTENCE_KEYS.keys())
    results = {"timestamp": datetime.utcnow().isoformat(), "categories": {}, "all_suspicious": []}
    for category in categories:
        keys = PERSISTENCE_KEYS.get(category, [])
        category_findings = []
        for key in keys:
            try:
                proc = subprocess.run(
                    ["reg", "query", key, "/s"], capture_output=True, text=True, timeout=10
                )
                if proc.returncode == 0:
                    entries = _parse_reg(proc.stdout, key)
                    for entry in entries:
                        entry["suspicious"] = _check_suspicious(entry.get("value", ""))
                        entry["category"] = category
                        if entry["suspicious"]:
                            results["all_suspicious"].append(entry)
                    category_findings.extend(entries)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        results["categories"][category] = {
            "total": len(category_findings),
            "suspicious": sum(1 for f in category_findings if f.get("suspicious")),
            "entries": category_findings,
        }
    results["total_suspicious"] = len(results["all_suspicious"])
    return results


def _parse_reg(output, default_key):
    entries = []
    current_key = default_key
    for line in output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.startswith("HK"):
            current_key = line
            continue
        parts = re.split(r"\s{2,}", line, maxsplit=2)
        if len(parts) >= 3:
            entries.append({"key": current_key, "name": parts[0], "type": parts[1], "value": parts[2]})
    return entries


def _check_suspicious(value):
    return any(re.search(p, value, re.I) for p in SUSPICIOUS_PATTERNS)


def compare_baseline(baseline_file, current_scan=None):
    """Compare current registry state against a known-good baseline."""
    with open(baseline_file, "r") as f:
        baseline = json.load(f)
    if current_scan is None:
        current_scan = scan_persistence_keys()
    baseline_set = set()
    for cat_data in baseline.get("categories", {}).values():
        for entry in cat_data.get("entries", []):
            baseline_set.add((entry.get("key", ""), entry.get("name", ""), entry.get("value", "")))
    new_entries = []
    for cat_name, cat_data in current_scan["categories"].items():
        for entry in cat_data.get("entries", []):
            key_tuple = (entry.get("key", ""), entry.get("name", ""), entry.get("value", ""))
            if key_tuple not in baseline_set:
                entry["status"] = "NEW"
                new_entries.append(entry)
    return {
        "baseline_entries": len(baseline_set),
        "new_entries": len(new_entries),
        "findings": new_entries,
    }


def main():
    parser = argparse.ArgumentParser(description="Hunt for registry persistence mechanisms")
    sub = parser.add_subparsers(dest="command")
    s = sub.add_parser("scan", help="Scan registry persistence keys")
    s.add_argument("--categories", nargs="*", choices=list(PERSISTENCE_KEYS.keys()),
                   help="Categories to scan (default: all)")
    s.add_argument("--save-baseline", help="Save scan as baseline JSON file")
    c = sub.add_parser("compare", help="Compare against baseline")
    c.add_argument("--baseline", required=True, help="Baseline JSON file")
    args = parser.parse_args()
    if args.command == "scan":
        result = scan_persistence_keys(args.categories)
        if args.save_baseline:
            with open(args.save_baseline, "w") as f:
                json.dump(result, f, indent=2)
    elif args.command == "compare":
        result = compare_baseline(args.baseline)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
