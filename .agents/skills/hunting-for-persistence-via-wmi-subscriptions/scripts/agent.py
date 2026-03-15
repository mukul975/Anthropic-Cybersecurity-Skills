#!/usr/bin/env python3
"""Agent for hunting WMI event subscription persistence (T1546.003)."""

import json
import argparse
import subprocess
import re
from datetime import datetime

WMI_CLASSES = {
    "EventFilter": {
        "wmic_cmd": ["wmic", "/namespace:\\\\root\\subscription", "path", "__EventFilter", "get", "/format:list"],
        "description": "WMI event filters that trigger on system events",
    },
    "EventConsumer": {
        "wmic_cmd": ["wmic", "/namespace:\\\\root\\subscription", "path", "CommandLineEventConsumer", "get", "/format:list"],
        "description": "Command-line consumers that execute when filters trigger",
    },
    "ActiveScriptEventConsumer": {
        "wmic_cmd": ["wmic", "/namespace:\\\\root\\subscription", "path", "ActiveScriptEventConsumer", "get", "/format:list"],
        "description": "Script-based consumers (VBScript/JScript) for WMI persistence",
    },
    "FilterToConsumerBinding": {
        "wmic_cmd": ["wmic", "/namespace:\\\\root\\subscription", "path", "__FilterToConsumerBinding", "get", "/format:list"],
        "description": "Bindings linking event filters to consumers",
    },
}

SUSPICIOUS_WMI_PATTERNS = [
    r"powershell", r"cmd\.exe", r"mshta", r"rundll32",
    r"certutil", r"bitsadmin", r"regsvr32",
    r"base64", r"IEX", r"DownloadString", r"Net\.WebClient",
    r"invoke-expression", r"new-object.*net\.webclient",
    r"\\temp\\", r"\\appdata\\", r"\\users\\public\\",
    r"wscript", r"cscript", r"javascript:", r"vbscript:",
]


def enumerate_wmi_subscriptions():
    """Enumerate all WMI event subscriptions on the local system."""
    results = {"timestamp": datetime.utcnow().isoformat(), "classes": {}, "suspicious": []}
    for class_name, info in WMI_CLASSES.items():
        try:
            proc = subprocess.run(info["wmic_cmd"], capture_output=True, text=True, timeout=15)
            entries = parse_wmic_list(proc.stdout)
            suspicious_entries = []
            for entry in entries:
                entry_text = json.dumps(entry).lower()
                matched = [p for p in SUSPICIOUS_WMI_PATTERNS if re.search(p, entry_text, re.I)]
                if matched:
                    entry["matched_patterns"] = matched
                    suspicious_entries.append(entry)
            results["classes"][class_name] = {
                "description": info["description"],
                "total_entries": len(entries),
                "entries": entries,
            }
            results["suspicious"].extend([{**e, "class": class_name} for e in suspicious_entries])
        except (subprocess.TimeoutExpired, FileNotFoundError):
            results["classes"][class_name] = {"error": "command failed"}
    results["total_suspicious"] = len(results["suspicious"])
    return results


def parse_wmic_list(output):
    """Parse WMIC /format:list output into list of dicts."""
    entries = []
    current = {}
    for line in output.strip().split("\n"):
        line = line.strip()
        if not line:
            if current:
                entries.append(current)
                current = {}
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            current[key.strip()] = value.strip()
    if current:
        entries.append(current)
    return entries


def scan_sysmon_wmi_events(evtx_file):
    """Parse Sysmon EVTX for WMI events (Event IDs 19, 20, 21)."""
    try:
        import Evtx.Evtx as evtx_lib
    except ImportError:
        return {"error": "python-evtx not installed"}
    findings = []
    wmi_event_ids = {"19", "20", "21"}
    with evtx_lib.Evtx(evtx_file) as log:
        for record in log.records():
            xml = record.xml()
            for eid in wmi_event_ids:
                if f"<EventID>{eid}</EventID>" in xml:
                    suspicious = any(re.search(p, xml, re.I) for p in SUSPICIOUS_WMI_PATTERNS)
                    findings.append({
                        "record_id": record.record_num(),
                        "event_id": int(eid),
                        "event_type": {
                            "19": "WmiEventFilter", "20": "WmiEventConsumer", "21": "WmiEventBinding"
                        }[eid],
                        "suspicious": suspicious,
                        "xml_snippet": xml[:800],
                    })
                    break
    return {
        "file": evtx_file,
        "total_wmi_events": len(findings),
        "suspicious_events": sum(1 for f in findings if f["suspicious"]),
        "findings": findings[:300],
    }


def query_powershell_wmi():
    """Use PowerShell Get-WMIObject to enumerate WMI subscriptions."""
    ps_script = """
    $filters = Get-WMIObject -Namespace root\\Subscription -Class __EventFilter | Select Name,Query
    $consumers = Get-WMIObject -Namespace root\\Subscription -Class CommandLineEventConsumer | Select Name,CommandLineTemplate
    $bindings = Get-WMIObject -Namespace root\\Subscription -Class __FilterToConsumerBinding | Select Filter,Consumer
    @{Filters=$filters;Consumers=$consumers;Bindings=$bindings} | ConvertTo-Json -Depth 5
    """
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
        return {"error": result.stderr[:500]}
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
        return {"error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Hunt for WMI event subscription persistence")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("enumerate", help="Enumerate WMI subscriptions via WMIC")
    sub.add_parser("powershell", help="Enumerate via PowerShell Get-WMIObject")
    s = sub.add_parser("sysmon", help="Scan Sysmon EVTX for WMI events (19/20/21)")
    s.add_argument("--evtx-file", required=True)
    args = parser.parse_args()
    if args.command == "enumerate":
        result = enumerate_wmi_subscriptions()
    elif args.command == "powershell":
        result = query_powershell_wmi()
    elif args.command == "sysmon":
        result = scan_sysmon_wmi_events(args.evtx_file)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
