#!/usr/bin/env python3
"""
Credential Dumping Detection Script
Analyzes process access logs for LSASS memory access, SAM extraction,
DCSync activity, and other credential theft indicators.
"""

import json
import csv
import argparse
import datetime
import re
import sys
from collections import defaultdict
from pathlib import Path

# Suspicious LSASS access masks indicating credential dumping
SUSPICIOUS_ACCESS_MASKS = {
    "0x1FFFFF": {"risk": "CRITICAL", "description": "PROCESS_ALL_ACCESS - full process access"},
    "0x1010": {"risk": "HIGH", "description": "PROCESS_VM_READ + PROCESS_QUERY_INFORMATION (Mimikatz default)"},
    "0x1038": {"risk": "HIGH", "description": "Common credential dumping access mask"},
    "0x0410": {"risk": "MEDIUM", "description": "PROCESS_QUERY_INFORMATION + PROCESS_VM_READ"},
    "0x1400": {"risk": "MEDIUM", "description": "PROCESS_QUERY_INFORMATION + PROCESS_QUERY_LIMITED"},
    "0x0040": {"risk": "HIGH", "description": "PROCESS_DUP_HANDLE - handle duplication"},
    "0x0810": {"risk": "HIGH", "description": "PROCESS_SUSPEND_RESUME + PROCESS_VM_READ"},
    "0x1fffff": {"risk": "CRITICAL", "description": "PROCESS_ALL_ACCESS (lowercase)"},
}

# Legitimate processes that commonly access LSASS
LSASS_WHITELIST = {
    "csrss.exe", "svchost.exe", "services.exe", "lsass.exe", "wininit.exe",
    "smss.exe", "wmiprvse.exe", "taskmgr.exe", "procexp.exe", "procexp64.exe",
    "msmpsvc.exe", "msmpeng.exe", "nissrv.exe", "mssense.exe", "sensecncproxy.exe",
    "csfalconservice.exe", "csfalconcontainer.exe",
    "sentinelagent.exe", "sentinelone.exe",
    "cb.exe", "carbonblack.exe",
    "logrhythmagent.exe",
}

# Known credential dumping tool command-line patterns
CRED_DUMP_TOOL_PATTERNS = {
    "mimikatz": {
        "patterns": [
            r"sekurlsa::",
            r"lsadump::",
            r"kerberos::list",
            r"crypto::cng",
            r"privilege::debug",
            r"token::elevate",
            r"dpapi::",
            r"vault::cred",
        ],
        "technique": "T1003.001/T1003.006",
    },
    "comsvcs_minidump": {
        "patterns": [
            r"comsvcs\.dll.*MiniDump",
            r"comsvcs\.dll.*#24",
        ],
        "technique": "T1003.001",
    },
    "procdump": {
        "patterns": [
            r"procdump.*-ma.*lsass",
            r"procdump.*lsass.*-ma",
            r"procdump.*-accepteula.*lsass",
        ],
        "technique": "T1003.001",
    },
    "reg_save": {
        "patterns": [
            r"reg\s+(save|export)\s+HKLM\\SAM",
            r"reg\s+(save|export)\s+HKLM\\SECURITY",
            r"reg\s+(save|export)\s+HKLM\\SYSTEM",
        ],
        "technique": "T1003.002",
    },
    "ntdsutil": {
        "patterns": [
            r"ntdsutil.*ifm",
            r"ntdsutil.*\"activate instance ntds\"",
            r"ntdsutil.*create full",
        ],
        "technique": "T1003.003",
    },
    "vssadmin_shadow": {
        "patterns": [
            r"vssadmin.*create\s+shadow",
            r"copy.*GLOBALROOT.*Device.*HarddiskVolumeShadowCopy",
            r"wmic.*shadowcopy.*create",
        ],
        "technique": "T1003.003",
    },
    "secretsdump": {
        "patterns": [
            r"secretsdump",
            r"impacket.*dump",
        ],
        "technique": "T1003.002/T1003.003/T1003.006",
    },
    "lazagne": {
        "patterns": [
            r"lazagne",
            r"LaZagne\.exe",
        ],
        "technique": "T1003.001/T1555",
    },
    "sharpdump": {
        "patterns": [
            r"SharpDump",
            r"sharpdump",
        ],
        "technique": "T1003.001",
    },
    "nanodump": {
        "patterns": [
            r"nanodump",
        ],
        "technique": "T1003.001",
    },
}

# DCSync detection GUIDs
DCSYNC_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}


def parse_logs(input_path: str) -> list[dict]:
    """Parse log files in JSON or CSV format."""
    events = []
    path = Path(input_path)
    if path.suffix == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            events = data if isinstance(data, list) else data.get("events", data.get("hits", {}).get("hits", []))
            if events and isinstance(events[0], dict) and "_source" in events[0]:
                events = [e["_source"] for e in events]
    elif path.suffix == ".csv":
        with open(path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            events = [dict(row) for row in reader]
    return events


def normalize_event(event: dict) -> dict:
    """Normalize event field names."""
    field_map = {
        "source_image": ["SourceImage", "source_image", "InitiatingProcessFileName", "process.executable"],
        "target_image": ["TargetImage", "target_image", "FileName", "target.process.executable"],
        "granted_access": ["GrantedAccess", "granted_access", "AccessMask"],
        "command_line": ["CommandLine", "command_line", "ProcessCommandLine", "process.command_line"],
        "user": ["User", "user", "AccountName", "SubjectUserName", "user.name"],
        "hostname": ["Computer", "hostname", "DeviceName", "host.name"],
        "timestamp": ["UtcTime", "timestamp", "Timestamp", "@timestamp"],
        "event_id": ["EventID", "EventCode", "event_id", "event.code"],
        "parent_image": ["ParentImage", "parent_image", "InitiatingProcessParentFileName"],
        "properties": ["Properties", "properties", "ObjectType"],
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


def detect_lsass_access(event: dict) -> dict | None:
    """Detect suspicious LSASS process access."""
    target = event.get("target_image", "").lower()
    if "lsass.exe" not in target:
        return None

    source = event.get("source_image", "").lower()
    source_name = source.split("\\")[-1].split("/")[-1]
    access = event.get("granted_access", "").lower()

    # Skip whitelisted processes
    if source_name in LSASS_WHITELIST:
        return None

    risk_info = SUSPICIOUS_ACCESS_MASKS.get(access, SUSPICIOUS_ACCESS_MASKS.get(access.upper()))
    if not risk_info:
        risk_info = {"risk": "LOW", "description": f"Unknown access mask: {access}"}

    return {
        "detection_type": "LSASS_ACCESS",
        "technique": "T1003.001",
        "source_process": event.get("source_image", ""),
        "target_process": event.get("target_image", ""),
        "granted_access": access,
        "access_description": risk_info["description"],
        "risk_level": risk_info["risk"],
        "user": event.get("user", "unknown"),
        "hostname": event.get("hostname", "unknown"),
        "timestamp": event.get("timestamp", "unknown"),
        "indicators": [f"LSASS access from {source_name} with mask {access}"],
    }


def detect_credential_tool(event: dict) -> dict | None:
    """Detect known credential dumping tool execution."""
    cmd = event.get("command_line", "")
    if not cmd:
        return None

    for tool_name, tool_info in CRED_DUMP_TOOL_PATTERNS.items():
        for pattern in tool_info["patterns"]:
            if re.search(pattern, cmd, re.IGNORECASE):
                return {
                    "detection_type": "CREDENTIAL_TOOL",
                    "technique": tool_info["technique"],
                    "tool": tool_name,
                    "command_line": cmd,
                    "source_process": event.get("source_image", ""),
                    "parent_process": event.get("parent_image", ""),
                    "risk_level": "CRITICAL",
                    "user": event.get("user", "unknown"),
                    "hostname": event.get("hostname", "unknown"),
                    "timestamp": event.get("timestamp", "unknown"),
                    "indicators": [f"Credential tool detected: {tool_name}", f"Pattern matched: {pattern}"],
                }
    return None


def detect_dcsync(event: dict) -> dict | None:
    """Detect DCSync activity from non-DC sources."""
    props = event.get("properties", "")
    for guid, name in DCSYNC_GUIDS.items():
        if guid.lower() in props.lower():
            return {
                "detection_type": "DCSYNC",
                "technique": "T1003.006",
                "replication_right": name,
                "guid": guid,
                "risk_level": "CRITICAL",
                "user": event.get("user", "unknown"),
                "hostname": event.get("hostname", "unknown"),
                "timestamp": event.get("timestamp", "unknown"),
                "indicators": [f"DCSync activity: {name}", f"GUID: {guid}"],
            }
    return None


def run_hunt(input_path: str, output_dir: str, dc_list: list[str] | None = None) -> None:
    """Execute credential dumping hunt."""
    print(f"[*] Credential Dumping Hunt - {datetime.datetime.now().isoformat()}")
    print(f"[*] Input: {input_path}")

    events = parse_logs(input_path)
    print(f"[*] Loaded {len(events)} events")

    findings = []
    stats = defaultdict(int)

    for raw_event in events:
        event = normalize_event(raw_event)

        # Check for LSASS access
        result = detect_lsass_access(event)
        if result:
            findings.append(result)
            stats["LSASS_ACCESS"] += 1
            stats[result["risk_level"]] += 1

        # Check for credential dumping tools
        result = detect_credential_tool(event)
        if result:
            findings.append(result)
            stats["CREDENTIAL_TOOL"] += 1
            stats[result["risk_level"]] += 1

        # Check for DCSync
        result = detect_dcsync(event)
        if result:
            if dc_list and result["hostname"].lower() in [dc.lower() for dc in dc_list]:
                continue  # Skip legitimate DC replication
            findings.append(result)
            stats["DCSYNC"] += 1
            stats[result["risk_level"]] += 1

    # Write output
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    findings_file = output_path / "credential_dump_findings.json"
    with open(findings_file, "w", encoding="utf-8") as f:
        json.dump({
            "hunt_id": f"TH-CRED-DUMP-{datetime.date.today().isoformat()}",
            "timestamp": datetime.datetime.now().isoformat(),
            "total_events": len(events),
            "total_findings": len(findings),
            "statistics": dict(stats),
            "findings": findings,
        }, f, indent=2)

    # Write report
    report_file = output_path / "hunt_report.md"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(f"# Credential Dumping Hunt Report\n\n")
        f.write(f"**Date**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Events Analyzed**: {len(events)}\n")
        f.write(f"**Findings**: {len(findings)}\n\n")
        f.write("## Detection Breakdown\n\n")
        for key, count in sorted(stats.items()):
            f.write(f"- {key}: {count}\n")
        f.write("\n## Critical Findings\n\n")
        for finding in sorted(findings, key=lambda x: ("CRITICAL", "HIGH", "MEDIUM", "LOW").index(x["risk_level"])):
            if finding["risk_level"] in ("CRITICAL", "HIGH"):
                f.write(f"### [{finding['risk_level']}] {finding['detection_type']} - {finding['technique']}\n")
                f.write(f"- **Host**: {finding['hostname']}\n")
                f.write(f"- **User**: {finding['user']}\n")
                f.write(f"- **Indicators**: {', '.join(finding['indicators'])}\n\n")

    print(f"[+] Output written to {output_dir}")
    print(f"\n{'='*60}")
    print(f"FINDINGS: {len(findings)} | CRITICAL: {stats.get('CRITICAL',0)} | HIGH: {stats.get('HIGH',0)}")
    print(f"{'='*60}")


def generate_queries(platform: str) -> None:
    """Generate hunting queries for specified platform."""
    if platform in ("splunk", "all"):
        print("\n=== SPLUNK QUERIES ===\n")
        print("--- LSASS Access Detection ---")
        print("""index=sysmon EventCode=10 TargetImage="*\\\\lsass.exe"
| where NOT match(SourceImage, "(?i)(csrss|svchost|services|lsass|wininit|MsMpEng)")
| stats count by SourceImage GrantedAccess Computer User
| sort -count""")
        print("\n--- Credential Tool Detection ---")
        print("""index=sysmon EventCode=1
| where match(CommandLine, "(?i)(sekurlsa|lsadump|comsvcs.*MiniDump|procdump.*lsass|reg save.*SAM)")
| table _time Computer User Image CommandLine ParentImage""")
        print("\n--- DCSync Detection ---")
        print("""index=wineventlog EventCode=4662
| where match(Properties, "(?i)(1131f6aa|1131f6ad|89e95b76)")
| table _time SubjectUserName SubjectDomainName Computer Properties""")

    if platform in ("kql", "all"):
        print("\n=== KQL QUERIES ===\n")
        print("--- LSASS Access ---")
        print("""DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where FileName == "lsass.exe"
| where InitiatingProcessFileName !in~ ("csrss.exe","svchost.exe","MsMpEng.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, AdditionalFields""")


def main():
    parser = argparse.ArgumentParser(description="Credential Dumping Detection Hunt")
    subparsers = parser.add_subparsers(dest="command")

    hunt_parser = subparsers.add_parser("hunt", help="Run credential dumping hunt")
    hunt_parser.add_argument("--input", "-i", required=True, help="Log file path")
    hunt_parser.add_argument("--output", "-o", default="./cred_dump_output", help="Output directory")
    hunt_parser.add_argument("--dc-list", nargs="*", help="List of known DCs to exclude from DCSync alerts")

    query_parser = subparsers.add_parser("queries", help="Generate hunting queries")
    query_parser.add_argument("--platform", "-p", choices=["splunk", "kql", "all"], default="all")

    subparsers.add_parser("signatures", help="List detection signatures")

    args = parser.parse_args()

    if args.command == "hunt":
        run_hunt(args.input, args.output, args.dc_list)
    elif args.command == "queries":
        generate_queries(args.platform)
    elif args.command == "signatures":
        print("\n=== Credential Dumping Tool Signatures ===\n")
        for tool, info in CRED_DUMP_TOOL_PATTERNS.items():
            print(f"{tool:<25} {info['technique']:<25} Patterns: {len(info['patterns'])}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
