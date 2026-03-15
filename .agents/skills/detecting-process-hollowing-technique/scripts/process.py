#!/usr/bin/env python3
"""
Process Hollowing Detection Script
Analyzes process creation, memory events, and parent-child relationships
to detect process hollowing (T1055.012) indicators.
"""

import json
import csv
import argparse
import datetime
import re
from collections import defaultdict
from pathlib import Path

# Legitimate parent-child process relationships on Windows
VALID_PARENT_CHILD = {
    "smss.exe": {"parents": ["system", "smss.exe"], "user": "NT AUTHORITY\\SYSTEM"},
    "csrss.exe": {"parents": ["smss.exe"], "user": "NT AUTHORITY\\SYSTEM"},
    "wininit.exe": {"parents": ["smss.exe"], "user": "NT AUTHORITY\\SYSTEM"},
    "winlogon.exe": {"parents": ["smss.exe"], "user": "NT AUTHORITY\\SYSTEM"},
    "services.exe": {"parents": ["wininit.exe"], "user": "NT AUTHORITY\\SYSTEM"},
    "lsass.exe": {"parents": ["wininit.exe"], "user": "NT AUTHORITY\\SYSTEM"},
    "svchost.exe": {"parents": ["services.exe", "MsMpEng.exe"], "user": "NT AUTHORITY\\*"},
    "taskhost.exe": {"parents": ["svchost.exe"], "user": "*"},
    "taskhostw.exe": {"parents": ["svchost.exe"], "user": "*"},
    "userinit.exe": {"parents": ["winlogon.exe"], "user": "*"},
    "explorer.exe": {"parents": ["userinit.exe", "explorer.exe"], "user": "*"},
    "dllhost.exe": {"parents": ["svchost.exe", "services.exe"], "user": "*"},
    "conhost.exe": {"parents": ["csrss.exe"], "user": "*"},
    "RuntimeBroker.exe": {"parents": ["svchost.exe"], "user": "*"},
    "SearchIndexer.exe": {"parents": ["services.exe"], "user": "NT AUTHORITY\\SYSTEM"},
    "spoolsv.exe": {"parents": ["services.exe"], "user": "NT AUTHORITY\\SYSTEM"},
}

# Common hollowing target processes
HOLLOWING_TARGETS = {
    "svchost.exe", "explorer.exe", "rundll32.exe", "dllhost.exe",
    "conhost.exe", "taskhost.exe", "taskhostw.exe", "RuntimeBroker.exe",
    "RegAsm.exe", "MSBuild.exe", "RegSvcs.exe", "vbc.exe",
    "AppLaunch.exe", "InstallUtil.exe", "aspnet_compiler.exe",
}

# Process behavior indicators that suggest hollowing
ANOMALOUS_BEHAVIORS = {
    "svchost.exe": {
        "no_cmdline_flag": True,  # svchost should have -k flag
        "required_arg": "-k",
        "no_external_network": True,  # unusual ports
    },
    "explorer.exe": {
        "no_cmdline_flag": False,
        "no_external_network": False,
        "single_instance": True,
    },
    "dllhost.exe": {
        "no_cmdline_flag": True,
        "required_arg": "/Processid:",
    },
}


def parse_logs(input_path: str) -> list[dict]:
    """Parse log files."""
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
    """Normalize process event fields."""
    field_map = {
        "event_id": ["EventCode", "EventID", "event_id"],
        "image": ["Image", "FileName", "image", "process.executable"],
        "command_line": ["CommandLine", "ProcessCommandLine", "command_line"],
        "parent_image": ["ParentImage", "InitiatingProcessFileName", "parent_image"],
        "parent_cmd": ["ParentCommandLine", "InitiatingProcessCommandLine", "parent_command_line"],
        "user": ["User", "AccountName", "user.name"],
        "hostname": ["Computer", "DeviceName", "host.name"],
        "timestamp": ["UtcTime", "Timestamp", "@timestamp"],
        "pid": ["ProcessId", "ProcessId", "process.pid"],
        "parent_pid": ["ParentProcessId", "ppid", "process.parent.pid"],
        "integrity": ["IntegrityLevel", "integrity_level"],
        "hashes": ["Hashes", "SHA256", "hashes"],
        "action_type": ["ActionType", "event_type"],
        "dest_ip": ["DestinationIp", "RemoteIP"],
        "dest_port": ["DestinationPort", "RemotePort"],
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


def get_process_name(path: str) -> str:
    """Extract process name from full path."""
    if not path:
        return ""
    return path.split("\\")[-1].split("/")[-1].lower()


def check_parent_child(event: dict) -> dict | None:
    """Check for invalid parent-child process relationships."""
    image = get_process_name(event.get("image", ""))
    parent = get_process_name(event.get("parent_image", ""))

    if image not in VALID_PARENT_CHILD:
        return None

    expected = VALID_PARENT_CHILD[image]
    valid_parents = [p.lower() for p in expected["parents"]]

    if parent and parent not in valid_parents:
        return {
            "detection_type": "INVALID_PARENT_CHILD",
            "technique": "T1055.012",
            "process": image,
            "parent": parent,
            "expected_parents": expected["parents"],
            "full_image_path": event.get("image", ""),
            "full_parent_path": event.get("parent_image", ""),
            "command_line": event.get("command_line", ""),
            "hostname": event.get("hostname", "unknown"),
            "user": event.get("user", "unknown"),
            "timestamp": event.get("timestamp", "unknown"),
            "risk_score": 70,
            "risk_level": "HIGH",
            "indicators": [
                f"Invalid parent: {parent} (expected: {', '.join(expected['parents'])})"
            ],
        }
    return None


def check_process_tampering(event: dict) -> dict | None:
    """Check for Sysmon Event ID 25 (ProcessTampering)."""
    if event.get("event_id") != "25":
        return None

    return {
        "detection_type": "PROCESS_TAMPERING",
        "technique": "T1055.012",
        "process": get_process_name(event.get("image", "")),
        "full_image_path": event.get("image", ""),
        "hostname": event.get("hostname", "unknown"),
        "user": event.get("user", "unknown"),
        "timestamp": event.get("timestamp", "unknown"),
        "risk_score": 90,
        "risk_level": "CRITICAL",
        "indicators": ["Sysmon ProcessTampering event detected - image replaced in memory"],
    }


def check_behavioral_anomaly(event: dict) -> dict | None:
    """Check for behavioral mismatches suggesting hollowing."""
    if event.get("event_id") != "1":
        return None

    image = get_process_name(event.get("image", ""))
    cmd = event.get("command_line", "")

    if image not in ANOMALOUS_BEHAVIORS:
        return None

    behavior = ANOMALOUS_BEHAVIORS[image]
    indicators = []

    if behavior.get("required_arg") and behavior["required_arg"] not in cmd:
        indicators.append(f"Missing required argument '{behavior['required_arg']}'")

    if image in HOLLOWING_TARGETS:
        # Check if process path is from unexpected location
        expected_paths = ["\\windows\\system32\\", "\\windows\\syswow64\\"]
        image_path = event.get("image", "").lower()
        if not any(ep in image_path for ep in expected_paths):
            indicators.append(f"Process running from unexpected path: {image_path}")

    if not indicators:
        return None

    return {
        "detection_type": "BEHAVIORAL_ANOMALY",
        "technique": "T1055.012",
        "process": image,
        "full_image_path": event.get("image", ""),
        "command_line": cmd,
        "parent_process": get_process_name(event.get("parent_image", "")),
        "hostname": event.get("hostname", "unknown"),
        "user": event.get("user", "unknown"),
        "timestamp": event.get("timestamp", "unknown"),
        "risk_score": 50,
        "risk_level": "MEDIUM",
        "indicators": indicators,
    }


def check_hollowing_target_network(event: dict) -> dict | None:
    """Detect hollowing targets making unusual network connections."""
    if event.get("event_id") != "3":
        return None

    image = get_process_name(event.get("image", ""))
    if image not in HOLLOWING_TARGETS:
        return None

    dest_ip = event.get("dest_ip", "")
    dest_port = event.get("dest_port", "")

    # Check for external connections from commonly hollowed processes
    if dest_ip and not re.match(r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)", dest_ip):
        suspicious_ports = {"4444", "5555", "6666", "8888", "9090", "1234", "31337", "50050"}
        risk = 40
        indicators = [f"Hollowing target {image} connecting externally to {dest_ip}:{dest_port}"]

        if dest_port in suspicious_ports:
            risk += 20
            indicators.append(f"Suspicious port: {dest_port}")

        return {
            "detection_type": "HOLLOWED_PROCESS_NETWORK",
            "technique": "T1055.012",
            "process": image,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "hostname": event.get("hostname", "unknown"),
            "timestamp": event.get("timestamp", "unknown"),
            "risk_score": risk,
            "risk_level": "HIGH" if risk >= 50 else "MEDIUM",
            "indicators": indicators,
        }
    return None


def run_hunt(input_path: str, output_dir: str) -> None:
    """Execute process hollowing hunt."""
    print(f"[*] Process Hollowing Hunt - {datetime.datetime.now().isoformat()}")

    events = parse_logs(input_path)
    print(f"[*] Loaded {len(events)} events")

    findings = []
    stats = defaultdict(int)

    detectors = [
        check_process_tampering,
        check_parent_child,
        check_behavioral_anomaly,
        check_hollowing_target_network,
    ]

    for raw_event in events:
        event = normalize_event(raw_event)
        for detector in detectors:
            result = detector(event)
            if result:
                findings.append(result)
                stats[result["detection_type"]] += 1

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    with open(output_path / "hollowing_findings.json", "w", encoding="utf-8") as f:
        json.dump({
            "hunt_id": f"TH-HOLLOW-{datetime.date.today().isoformat()}",
            "total_events": len(events),
            "total_findings": len(findings),
            "statistics": dict(stats),
            "findings": sorted(findings, key=lambda x: x["risk_score"], reverse=True),
        }, f, indent=2)

    with open(output_path / "hunt_report.md", "w", encoding="utf-8") as f:
        f.write(f"# Process Hollowing Hunt Report\n\n")
        f.write(f"**Date**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Findings**: {len(findings)}\n\n")
        for finding in sorted(findings, key=lambda x: x["risk_score"], reverse=True)[:20]:
            f.write(f"### [{finding['risk_level']}] {finding['detection_type']}\n")
            f.write(f"- **Process**: {finding.get('process', '')}\n")
            f.write(f"- **Host**: {finding['hostname']}\n")
            f.write(f"- **Indicators**: {', '.join(finding['indicators'])}\n\n")

    print(f"[+] {len(findings)} findings written to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="Process Hollowing Detection")
    subparsers = parser.add_subparsers(dest="command")

    hunt_p = subparsers.add_parser("hunt")
    hunt_p.add_argument("--input", "-i", required=True)
    hunt_p.add_argument("--output", "-o", default="./hollowing_output")

    subparsers.add_parser("queries")

    args = parser.parse_args()

    if args.command == "hunt":
        run_hunt(args.input, args.output)
    elif args.command == "queries":
        print("=== Sysmon Queries ===")
        print("--- Process Tampering ---")
        print('index=sysmon EventCode=25\n| table _time Computer User Image Type')
        print("\n--- Invalid Parent-Child ---")
        print('index=sysmon EventCode=1 Image="*\\\\svchost.exe"\n| where NOT match(ParentImage, "(?i)services\\.exe")\n| table _time Computer Image ParentImage CommandLine')
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
