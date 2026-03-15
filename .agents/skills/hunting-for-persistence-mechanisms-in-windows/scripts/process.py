#!/usr/bin/env python3
"""
Windows Persistence Mechanism Hunter
Analyzes logs for registry, service, scheduled task, WMI, and COM persistence.
"""

import json
import csv
import argparse
import datetime
import re
from collections import defaultdict
from pathlib import Path

# Registry persistence locations to monitor
REGISTRY_PERSISTENCE_KEYS = {
    "run_keys": {
        "patterns": [
            r"\\CurrentVersion\\Run($|\\)",
            r"\\CurrentVersion\\RunOnce($|\\)",
            r"\\CurrentVersion\\RunServices($|\\)",
            r"\\Policies\\Explorer\\Run($|\\)",
        ],
        "technique": "T1547.001",
        "risk_base": 40,
    },
    "winlogon": {
        "patterns": [
            r"\\Winlogon\\(Shell|Userinit|Notify|VmApplet|AppSetup)",
        ],
        "technique": "T1547.004",
        "risk_base": 60,
    },
    "ifeo": {
        "patterns": [
            r"\\Image File Execution Options\\.*\\Debugger",
            r"\\SilentProcessExit\\.*\\MonitorProcess",
        ],
        "technique": "T1546.012",
        "risk_base": 70,
    },
    "lsa_packages": {
        "patterns": [
            r"\\Control\\Lsa\\(Security Packages|Authentication Packages)",
        ],
        "technique": "T1547.005",
        "risk_base": 80,
    },
    "appinit_dlls": {
        "patterns": [
            r"\\Windows\\CurrentVersion\\Windows\\AppInit_DLLs",
            r"\\Windows\\CurrentVersion\\Windows\\LoadAppInit_DLLs",
        ],
        "technique": "T1546.010",
        "risk_base": 70,
    },
    "com_hijack": {
        "patterns": [
            r"\\InprocServer32\\?$",
            r"\\InprocServer32\\\\$",
        ],
        "technique": "T1546.015",
        "risk_base": 50,
    },
    "active_setup": {
        "patterns": [
            r"\\Active Setup\\Installed Components\\.*\\StubPath",
        ],
        "technique": "T1547.014",
        "risk_base": 60,
    },
    "screensaver": {
        "patterns": [
            r"\\Control Panel\\Desktop\\SCRNSAVE\.EXE",
        ],
        "technique": "T1546.002",
        "risk_base": 50,
    },
    "netsh_helper": {
        "patterns": [
            r"\\Netsh\\.*\\(DLL|HelperDll)",
        ],
        "technique": "T1546.007",
        "risk_base": 60,
    },
    "print_monitor": {
        "patterns": [
            r"\\Control\\Print\\Monitors\\.*\\Driver",
        ],
        "technique": "T1547.010",
        "risk_base": 70,
    },
    "boot_execute": {
        "patterns": [
            r"\\Session Manager\\BootExecute",
        ],
        "technique": "T1547.001",
        "risk_base": 80,
    },
}

# Suspicious service binary paths
SUSPICIOUS_SERVICE_PATHS = [
    r"\\temp\\", r"\\tmp\\", r"\\appdata\\", r"\\programdata\\",
    r"\\public\\", r"\\downloads\\", r"\\users\\.*\\desktop\\",
    r"powershell", r"cmd\.exe.*\/c", r"wscript", r"cscript",
    r"mshta", r"rundll32", r"regsvr32",
]

# Legitimate system paths for services
LEGITIMATE_SERVICE_PATHS = [
    r"^\"?C:\\Windows\\",
    r"^\"?C:\\Program Files",
    r"^\"?C:\\ProgramData\\Microsoft",
    r"^\"?\"?svchost\.exe",
]


def parse_logs(input_path: str) -> list[dict]:
    """Parse input log files."""
    path = Path(input_path)
    if path.suffix == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else data.get("events", [])
    elif path.suffix == ".csv":
        with open(path, "r", encoding="utf-8-sig") as f:
            return [dict(row) for row in csv.DictReader(f)]
    return []


def normalize_event(event: dict) -> dict:
    """Normalize event fields."""
    field_map = {
        "event_id": ["EventCode", "EventID", "event_id", "event.code"],
        "registry_key": ["TargetObject", "RegistryKey", "registry.key", "registry_key"],
        "registry_value": ["Details", "RegistryValueData", "registry.data", "registry_value"],
        "image": ["Image", "image", "process.executable", "InitiatingProcessFileName"],
        "command_line": ["CommandLine", "command_line", "ProcessCommandLine"],
        "user": ["User", "user", "AccountName", "user.name"],
        "hostname": ["Computer", "hostname", "DeviceName", "host.name"],
        "timestamp": ["UtcTime", "timestamp", "Timestamp", "@timestamp"],
        "service_name": ["Service_Name", "ServiceName", "service.name"],
        "service_path": ["Service_File_Name", "ServiceFileName", "ImagePath"],
        "task_name": ["Task_Name", "TaskName"],
        "task_content": ["Task_Content", "TaskContent"],
        "event_type": ["EventType", "ActionType", "event_type"],
        "wmi_operation": ["Operation", "wmi_operation"],
        "wmi_destination": ["Destination", "Consumer", "wmi_destination"],
    }
    normalized = {}
    for target, sources in field_map.items():
        for src in sources:
            if src in event and event[src]:
                normalized[target] = str(event[src])
                break
        if target not in normalized:
            normalized[target] = ""
    return normalized


def analyze_registry_persistence(event: dict) -> dict | None:
    """Check registry events for persistence indicators."""
    event_id = event.get("event_id", "")
    if event_id not in ("12", "13", "14"):
        return None

    reg_key = event.get("registry_key", "")
    if not reg_key:
        return None

    for category, info in REGISTRY_PERSISTENCE_KEYS.items():
        for pattern in info["patterns"]:
            if re.search(pattern, reg_key, re.IGNORECASE):
                value = event.get("registry_value", "")
                risk = info["risk_base"]

                # Increase risk for suspicious paths in value
                if value:
                    for susp in SUSPICIOUS_SERVICE_PATHS:
                        if re.search(susp, value, re.IGNORECASE):
                            risk += 20
                            break

                    # Decrease risk for legitimate paths
                    for legit in LEGITIMATE_SERVICE_PATHS:
                        if re.search(legit, value, re.IGNORECASE):
                            risk -= 20
                            break

                risk_level = (
                    "CRITICAL" if risk >= 80 else
                    "HIGH" if risk >= 60 else
                    "MEDIUM" if risk >= 40 else "LOW"
                )

                return {
                    "persistence_type": "REGISTRY",
                    "category": category,
                    "technique": info["technique"],
                    "registry_key": reg_key,
                    "value": value,
                    "modifying_process": event.get("image", ""),
                    "hostname": event.get("hostname", "unknown"),
                    "user": event.get("user", "unknown"),
                    "timestamp": event.get("timestamp", "unknown"),
                    "risk_score": risk,
                    "risk_level": risk_level,
                }
    return None


def analyze_service_persistence(event: dict) -> dict | None:
    """Check for suspicious service installations."""
    event_id = event.get("event_id", "")
    if event_id not in ("7045", "4697"):
        return None

    service_path = event.get("service_path", "")
    service_name = event.get("service_name", "")
    if not service_path:
        return None

    risk = 30
    indicators = []

    for pattern in SUSPICIOUS_SERVICE_PATHS:
        if re.search(pattern, service_path, re.IGNORECASE):
            risk += 25
            indicators.append(f"Suspicious service path: {pattern}")

    is_legitimate = False
    for pattern in LEGITIMATE_SERVICE_PATHS:
        if re.search(pattern, service_path, re.IGNORECASE):
            is_legitimate = True
            break

    if not is_legitimate:
        risk += 15
        indicators.append("Service binary outside standard paths")

    if not indicators:
        return None

    risk_level = (
        "CRITICAL" if risk >= 80 else
        "HIGH" if risk >= 60 else
        "MEDIUM" if risk >= 40 else "LOW"
    )

    return {
        "persistence_type": "SERVICE",
        "technique": "T1543.003",
        "service_name": service_name,
        "service_path": service_path,
        "hostname": event.get("hostname", "unknown"),
        "user": event.get("user", "unknown"),
        "timestamp": event.get("timestamp", "unknown"),
        "risk_score": risk,
        "risk_level": risk_level,
        "indicators": indicators,
    }


def analyze_wmi_persistence(event: dict) -> dict | None:
    """Check for WMI event subscription persistence."""
    event_id = event.get("event_id", "")
    if event_id not in ("19", "20", "21"):
        return None

    operation = event.get("wmi_operation", "")
    destination = event.get("wmi_destination", "")

    wmi_type = {
        "19": "EventFilter",
        "20": "EventConsumer",
        "21": "ConsumerToFilter",
    }.get(event_id, "Unknown")

    return {
        "persistence_type": "WMI_EVENT_SUBSCRIPTION",
        "technique": "T1546.003",
        "wmi_type": wmi_type,
        "operation": operation,
        "destination": destination,
        "hostname": event.get("hostname", "unknown"),
        "user": event.get("user", "unknown"),
        "timestamp": event.get("timestamp", "unknown"),
        "risk_score": 70,
        "risk_level": "HIGH",
        "indicators": [f"WMI {wmi_type} created"],
    }


def analyze_scheduled_task(event: dict) -> dict | None:
    """Check for scheduled task persistence."""
    event_id = event.get("event_id", "")
    if event_id not in ("4698", "106"):
        return None

    task_name = event.get("task_name", "")
    task_content = event.get("task_content", "")

    risk = 40
    indicators = []

    suspicious_task_patterns = [
        r"powershell", r"cmd\.exe", r"wscript", r"cscript",
        r"mshta", r"http[s]?://", r"-enc\s", r"iex\s",
        r"downloadstring", r"\\temp\\", r"\\appdata\\",
    ]

    for pattern in suspicious_task_patterns:
        if re.search(pattern, task_content, re.IGNORECASE):
            risk += 15
            indicators.append(f"Suspicious content: {pattern}")

    if not indicators:
        return None

    risk_level = (
        "CRITICAL" if risk >= 80 else
        "HIGH" if risk >= 60 else
        "MEDIUM" if risk >= 40 else "LOW"
    )

    return {
        "persistence_type": "SCHEDULED_TASK",
        "technique": "T1053.005",
        "task_name": task_name,
        "task_content": task_content[:500],
        "hostname": event.get("hostname", "unknown"),
        "user": event.get("user", "unknown"),
        "timestamp": event.get("timestamp", "unknown"),
        "risk_score": risk,
        "risk_level": risk_level,
        "indicators": indicators,
    }


def run_hunt(input_path: str, output_dir: str) -> None:
    """Execute persistence mechanism hunt."""
    print(f"[*] Windows Persistence Hunt - {datetime.datetime.now().isoformat()}")

    events = parse_logs(input_path)
    print(f"[*] Loaded {len(events)} events")

    findings = []
    stats = defaultdict(int)

    analyzers = [
        analyze_registry_persistence,
        analyze_service_persistence,
        analyze_wmi_persistence,
        analyze_scheduled_task,
    ]

    for raw_event in events:
        event = normalize_event(raw_event)
        for analyzer in analyzers:
            result = analyzer(event)
            if result:
                findings.append(result)
                stats[result["persistence_type"]] += 1
                stats[result["risk_level"]] += 1

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    with open(output_path / "persistence_findings.json", "w", encoding="utf-8") as f:
        json.dump({
            "hunt_id": f"TH-PERSIST-{datetime.date.today().isoformat()}",
            "total_events": len(events),
            "total_findings": len(findings),
            "statistics": dict(stats),
            "findings": findings,
        }, f, indent=2)

    with open(output_path / "hunt_report.md", "w", encoding="utf-8") as f:
        f.write(f"# Windows Persistence Hunt Report\n\n")
        f.write(f"**Date**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Findings**: {len(findings)}\n\n")
        for finding in sorted(findings, key=lambda x: x.get("risk_score", 0), reverse=True)[:30]:
            f.write(f"### [{finding['risk_level']}] {finding['persistence_type']} - {finding.get('technique','')}\n")
            f.write(f"- **Host**: {finding['hostname']}\n")
            if finding.get("registry_key"):
                f.write(f"- **Key**: `{finding['registry_key']}`\n")
            if finding.get("service_name"):
                f.write(f"- **Service**: {finding['service_name']}\n")
            if finding.get("task_name"):
                f.write(f"- **Task**: {finding['task_name']}\n")
            f.write("\n")

    print(f"[+] {len(findings)} findings written to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="Windows Persistence Mechanism Hunter")
    subparsers = parser.add_subparsers(dest="command")

    hunt_p = subparsers.add_parser("hunt")
    hunt_p.add_argument("--input", "-i", required=True)
    hunt_p.add_argument("--output", "-o", default="./persistence_output")

    query_p = subparsers.add_parser("queries")
    query_p.add_argument("--platform", "-p", choices=["splunk", "kql", "all"], default="all")

    args = parser.parse_args()

    if args.command == "hunt":
        run_hunt(args.input, args.output)
    elif args.command == "queries":
        print("=== Registry Persistence ===")
        print("""index=sysmon (EventCode=12 OR EventCode=13)
| where match(TargetObject, "(?i)\\\\CurrentVersion\\\\(Run|RunOnce)")
| table _time Computer User TargetObject Details Image""")
        print("\n=== Service Persistence ===")
        print("""index=wineventlog (EventCode=7045 OR EventCode=4697)
| table _time Computer Service_Name Service_File_Name""")
        print("\n=== WMI Persistence ===")
        print("""index=sysmon (EventCode=19 OR EventCode=20 OR EventCode=21)
| table _time Computer User EventType Operation Destination""")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
