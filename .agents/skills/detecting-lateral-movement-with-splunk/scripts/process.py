#!/usr/bin/env python3
"""
Lateral Movement Detection Script
Analyzes Windows authentication logs to detect lateral movement patterns
including RDP, SMB, WinRM, PsExec, and WMI-based movement.
"""

import json
import csv
import argparse
import datetime
import re
from collections import defaultdict
from pathlib import Path

# Lateral movement logon types
LATERAL_LOGON_TYPES = {
    "3": {"name": "Network", "techniques": ["T1021.002", "T1021.006", "T1047"], "risk_base": 20},
    "10": {"name": "RemoteInteractive", "techniques": ["T1021.001"], "risk_base": 25},
}

# Suspicious account patterns
SYSTEM_ACCOUNTS = {"system", "anonymous logon", "anonymous", "local service", "network service", "dwm-1", "umfd-0"}

# Admin share indicators
ADMIN_SHARES = {"admin$", "c$", "ipc$", "d$", "e$"}

# PsExec and service-based indicators
SERVICE_LATERAL_PATTERNS = [
    r"psexec", r"PSEXESVC", r"csexec", r"remcom",
    r"cmd\.exe\s+/c", r"powershell.*-enc",
]


def parse_logs(input_path: str) -> list[dict]:
    """Parse JSON or CSV log files."""
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
    """Normalize authentication event fields."""
    field_map = {
        "event_id": ["EventCode", "EventID", "event_id"],
        "logon_type": ["Logon_Type", "LogonType", "logon_type"],
        "account": ["Account_Name", "TargetUserName", "account_name", "user.name"],
        "source_ip": ["Source_Network_Address", "IpAddress", "source_ip", "source.ip"],
        "source_host": ["Workstation_Name", "WorkstationName", "source_host"],
        "dest_host": ["Computer", "hostname", "DeviceName", "host.name"],
        "logon_process": ["Logon_Process", "LogonProcessName", "logon_process"],
        "auth_package": ["Authentication_Package", "AuthenticationPackageName", "auth_package"],
        "share_name": ["Share_Name", "ShareName", "share_name"],
        "service_name": ["Service_Name", "ServiceName", "service_name"],
        "service_path": ["Service_File_Name", "ServiceFileName", "service_path"],
        "process_name": ["Process_Name", "ProcessName", "process_name"],
        "timestamp": ["_time", "timestamp", "Timestamp", "@timestamp", "UtcTime"],
    }
    normalized = {}
    for target, sources in field_map.items():
        for src in sources:
            if src in event and event[src]:
                normalized[target] = str(event[src]).strip()
                break
        if target not in normalized:
            normalized[target] = ""
    return normalized


def detect_network_logon(event: dict) -> dict | None:
    """Detect lateral movement via network logon events."""
    event_id = event.get("event_id", "")
    logon_type = event.get("logon_type", "")

    if event_id != "4624" or logon_type not in LATERAL_LOGON_TYPES:
        return None

    account = event.get("account", "").lower()
    if account in SYSTEM_ACCOUNTS or account.endswith("$"):
        return None

    source_ip = event.get("source_ip", "")
    if not source_ip or source_ip in ("-", "::1", "127.0.0.1"):
        return None

    lt_info = LATERAL_LOGON_TYPES[logon_type]
    risk = lt_info["risk_base"]
    indicators = [f"Logon Type {logon_type} ({lt_info['name']})"]

    auth_pkg = event.get("auth_package", "").lower()
    if "ntlm" in auth_pkg:
        risk += 10
        indicators.append("NTLM authentication (potential Pass-the-Hash)")
    if "negotiate" in auth_pkg and logon_type == "3":
        indicators.append("Negotiate authentication package")

    return {
        "detection_type": "NETWORK_LOGON",
        "technique": lt_info["techniques"][0],
        "account": event.get("account", ""),
        "source_ip": source_ip,
        "source_host": event.get("source_host", ""),
        "dest_host": event.get("dest_host", ""),
        "logon_type": logon_type,
        "auth_package": event.get("auth_package", ""),
        "timestamp": event.get("timestamp", ""),
        "risk_score": risk,
        "indicators": indicators,
    }


def detect_explicit_creds(event: dict) -> dict | None:
    """Detect explicit credential usage (Event 4648)."""
    if event.get("event_id") != "4648":
        return None

    account = event.get("account", "").lower()
    if account in SYSTEM_ACCOUNTS or account.endswith("$"):
        return None

    return {
        "detection_type": "EXPLICIT_CREDENTIAL",
        "technique": "T1021",
        "account": event.get("account", ""),
        "source_host": event.get("source_host", event.get("dest_host", "")),
        "dest_host": event.get("dest_host", ""),
        "process_name": event.get("process_name", ""),
        "timestamp": event.get("timestamp", ""),
        "risk_score": 35,
        "indicators": ["Explicit credential logon (4648) - possible PsExec/RunAs"],
    }


def detect_share_access(event: dict) -> dict | None:
    """Detect admin share access."""
    if event.get("event_id") != "5140":
        return None

    share = event.get("share_name", "").lower()
    share_name = share.split("\\")[-1] if "\\" in share else share

    if share_name not in ADMIN_SHARES:
        return None

    account = event.get("account", "").lower()
    if account in SYSTEM_ACCOUNTS or account.endswith("$"):
        return None

    risk = 40 if share_name in ("admin$", "c$") else 25

    return {
        "detection_type": "ADMIN_SHARE_ACCESS",
        "technique": "T1021.002",
        "account": event.get("account", ""),
        "source_ip": event.get("source_ip", ""),
        "dest_host": event.get("dest_host", ""),
        "share": share,
        "timestamp": event.get("timestamp", ""),
        "risk_score": risk,
        "indicators": [f"Admin share accessed: {share_name}"],
    }


def detect_service_lateral(event: dict) -> dict | None:
    """Detect service-based lateral movement (PsExec)."""
    if event.get("event_id") not in ("7045", "4697"):
        return None

    service_path = event.get("service_path", "")
    for pattern in SERVICE_LATERAL_PATTERNS:
        if re.search(pattern, service_path, re.IGNORECASE):
            return {
                "detection_type": "SERVICE_LATERAL",
                "technique": "T1569.002",
                "service_name": event.get("service_name", ""),
                "service_path": service_path,
                "dest_host": event.get("dest_host", ""),
                "timestamp": event.get("timestamp", ""),
                "risk_score": 60,
                "indicators": [f"Suspicious service for lateral movement: {pattern}"],
            }
    return None


def build_movement_graph(findings: list[dict]) -> dict:
    """Build a graph of lateral movement paths."""
    graph = defaultdict(lambda: defaultdict(list))
    for finding in findings:
        src = finding.get("source_ip") or finding.get("source_host", "unknown")
        dst = finding.get("dest_host", "unknown")
        if src and dst and src != dst:
            graph[src][dst].append({
                "account": finding.get("account", ""),
                "technique": finding.get("technique", ""),
                "timestamp": finding.get("timestamp", ""),
                "type": finding.get("detection_type", ""),
            })
    return dict(graph)


def analyze_velocity(findings: list[dict], window_minutes: int = 10, threshold: int = 5) -> list[dict]:
    """Detect rapid multi-host access patterns."""
    account_events = defaultdict(list)
    for f in findings:
        if f.get("account") and f.get("timestamp"):
            account_events[f["account"]].append(f)

    velocity_alerts = []
    for account, events in account_events.items():
        events.sort(key=lambda x: x.get("timestamp", ""))
        unique_dests = set()
        window_start = 0

        for i, event in enumerate(events):
            unique_dests.add(event.get("dest_host", ""))
            if len(unique_dests) >= threshold:
                velocity_alerts.append({
                    "detection_type": "VELOCITY_ANOMALY",
                    "account": account,
                    "unique_destinations": len(unique_dests),
                    "destinations": list(unique_dests),
                    "risk_score": 80,
                    "risk_level": "CRITICAL",
                    "indicators": [f"Account accessed {len(unique_dests)} hosts rapidly"],
                })
                break

    return velocity_alerts


def run_hunt(input_path: str, output_dir: str) -> None:
    """Execute lateral movement hunt."""
    print(f"[*] Lateral Movement Hunt - {datetime.datetime.now().isoformat()}")

    events = parse_logs(input_path)
    print(f"[*] Loaded {len(events)} events")

    findings = []
    stats = defaultdict(int)

    detectors = [
        detect_network_logon,
        detect_explicit_creds,
        detect_share_access,
        detect_service_lateral,
    ]

    for raw_event in events:
        event = normalize_event(raw_event)
        for detector in detectors:
            result = detector(event)
            if result:
                risk = result["risk_score"]
                result["risk_level"] = (
                    "CRITICAL" if risk >= 70 else "HIGH" if risk >= 50
                    else "MEDIUM" if risk >= 30 else "LOW"
                )
                findings.append(result)
                stats[result["detection_type"]] += 1

    # Velocity analysis
    velocity_alerts = analyze_velocity(findings)
    findings.extend(velocity_alerts)
    stats["VELOCITY_ANOMALY"] = len(velocity_alerts)

    # Build movement graph
    graph = build_movement_graph(findings)

    # Write output
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    with open(output_path / "lateral_movement_findings.json", "w", encoding="utf-8") as f:
        json.dump({
            "hunt_id": f"TH-LATMOV-{datetime.date.today().isoformat()}",
            "total_events": len(events),
            "total_findings": len(findings),
            "statistics": dict(stats),
            "movement_graph": {src: dict(dsts) for src, dsts in graph.items()},
            "findings": findings,
        }, f, indent=2)

    with open(output_path / "hunt_report.md", "w", encoding="utf-8") as f:
        f.write(f"# Lateral Movement Hunt Report\n\n")
        f.write(f"**Date**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Events**: {len(events)} | **Findings**: {len(findings)}\n\n")
        f.write("## Movement Graph\n\n")
        for src, dests in graph.items():
            for dst, connections in dests.items():
                f.write(f"- `{src}` -> `{dst}` ({len(connections)} connections)\n")
        f.write("\n## Velocity Anomalies\n\n")
        for alert in velocity_alerts:
            f.write(f"- **{alert['account']}**: {alert['unique_destinations']} hosts in short window\n")

    print(f"[+] {len(findings)} findings, {len(graph)} source nodes in movement graph")


def main():
    parser = argparse.ArgumentParser(description="Lateral Movement Detection")
    subparsers = parser.add_subparsers(dest="command")

    hunt_p = subparsers.add_parser("hunt")
    hunt_p.add_argument("--input", "-i", required=True)
    hunt_p.add_argument("--output", "-o", default="./latmov_output")

    subparsers.add_parser("queries", help="Print Splunk SPL queries")

    args = parser.parse_args()

    if args.command == "hunt":
        run_hunt(args.input, args.output)
    elif args.command == "queries":
        print("=== Splunk Lateral Movement Queries ===\n")
        queries = {
            "Network Logons": 'index=wineventlog EventCode=4624 Logon_Type=3\n| where NOT match(Account_Name, "(?i)(SYSTEM|ANONYMOUS|\\\\$)")\n| stats count dc(Computer) by Account_Name Source_Network_Address\n| where count > 3',
            "RDP Sessions": 'index=wineventlog EventCode=4624 Logon_Type=10\n| stats count by Account_Name Source_Network_Address Computer',
            "Admin Shares": 'index=wineventlog EventCode=5140 Share_Name IN ("*ADMIN$","*C$")\n| stats count by Account_Name Source_Address Computer Share_Name',
            "PsExec Services": 'index=wineventlog EventCode=7045\n| where match(Service_File_Name, "(?i)(psexec|PSEXESVC)")\n| table _time Computer Service_Name Service_File_Name',
        }
        for name, query in queries.items():
            print(f"--- {name} ---")
            print(query)
            print()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
