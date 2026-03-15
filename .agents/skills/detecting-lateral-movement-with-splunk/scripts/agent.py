#!/usr/bin/env python3
"""Lateral movement detection agent using Splunk SPL query generation.

Generates and analyzes SPL queries for detecting lateral movement techniques
including pass-the-hash, RDP pivoting, WMI/PSExec execution, and SMB abuse.
"""

import argparse
import json
import sys
from datetime import datetime

LATERAL_MOVEMENT_QUERIES = {
    "pass_the_hash": {
        "mitre": "T1550.002",
        "severity": "CRITICAL",
        "spl": """index=wineventlog EventCode=4624 Logon_Type=3
| where Authentication_Package="NTLM" AND Logon_Process="NtLmSsp"
| where NOT match(Source_Network_Address, "^(127\\.0\\.0\\.1|::1|-)")
| stats count dc(Computer) as target_count values(Computer) as targets by Source_Network_Address Account_Name
| where target_count > 3
| sort -target_count"""
    },
    "psexec_execution": {
        "mitre": "T1569.002",
        "severity": "HIGH",
        "spl": """index=sysmon EventCode=1
| where (ParentImage="*\\services.exe" AND Image="*\\PSEXESVC.exe")
   OR (Image="*\\psexec.exe" OR Image="*\\psexec64.exe")
| stats count by Image, ParentImage, CommandLine, Computer, User
| sort -count"""
    },
    "wmi_remote_execution": {
        "mitre": "T1047",
        "severity": "HIGH",
        "spl": """index=sysmon EventCode=1
| where (Image="*\\wmiprvse.exe" AND ParentImage="*\\svchost.exe")
| where CommandLine!=""
| stats count by CommandLine, Computer, User
| sort -count"""
    },
    "rdp_pivoting": {
        "mitre": "T1021.001",
        "severity": "MEDIUM",
        "spl": """index=wineventlog EventCode=4624 Logon_Type=10
| stats count dc(Computer) as rdp_targets values(Computer) as targets by Source_Network_Address Account_Name
| where rdp_targets > 3
| sort -rdp_targets"""
    },
    "smb_lateral": {
        "mitre": "T1021.002",
        "severity": "HIGH",
        "spl": """index=network dest_port=445
| stats count dc(dest_ip) as smb_targets values(dest_ip) as targets by src_ip
| where smb_targets > 5
| sort -smb_targets"""
    },
    "winrm_execution": {
        "mitre": "T1021.006",
        "severity": "HIGH",
        "spl": """index=sysmon EventCode=1
| where Image="*\\wsmprovhost.exe" OR (ParentImage="*\\winrshost.exe")
| stats count by Image, CommandLine, Computer, User
| sort -count"""
    },
    "service_creation": {
        "mitre": "T1543.003",
        "severity": "HIGH",
        "spl": """index=wineventlog EventCode=7045
| where Service_Type="user mode service"
| stats count by Service_Name, Service_File_Name, Computer
| where match(Service_File_Name, "(cmd|powershell|\\\\\\\\|%COMSPEC%)")
| sort -count"""
    },
    "scheduled_task_remote": {
        "mitre": "T1053.005",
        "severity": "HIGH",
        "spl": """index=sysmon EventCode=1 Image="*\\schtasks.exe"
| where match(CommandLine, "/create.*/s\\s")
| stats count by CommandLine, Computer, User
| sort -count"""
    },
}


def generate_queries(techniques=None):
    if techniques:
        selected = {k: v for k, v in LATERAL_MOVEMENT_QUERIES.items() if k in techniques}
    else:
        selected = LATERAL_MOVEMENT_QUERIES

    return [{"technique": name, **details} for name, details in selected.items()]


def parse_splunk_results(filepath):
    findings = []
    with open(filepath, "r") as f:
        try:
            data = json.load(f)
            results = data.get("results", data if isinstance(data, list) else [data])
        except json.JSONDecodeError:
            f.seek(0)
            import csv
            reader = csv.DictReader(f)
            results = list(reader)

    for row in results:
        target_count = int(row.get("target_count", row.get("dc(Computer)", 0)))
        if target_count >= 3:
            findings.append({
                "source": row.get("Source_Network_Address", row.get("src_ip", "")),
                "user": row.get("Account_Name", row.get("User", "")),
                "target_count": target_count,
                "targets": row.get("targets", row.get("Computer", "")),
                "severity": "CRITICAL" if target_count >= 10 else "HIGH",
            })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Lateral Movement Detector (Splunk SPL)")
    parser.add_argument("--generate-queries", action="store_true", help="Generate SPL queries")
    parser.add_argument("--techniques", nargs="+", choices=list(LATERAL_MOVEMENT_QUERIES.keys()),
                        help="Specific techniques to query")
    parser.add_argument("--parse-results", help="Parse Splunk JSON/CSV results file")
    args = parser.parse_args()

    results = {"timestamp": datetime.utcnow().isoformat() + "Z"}

    if args.generate_queries:
        results["queries"] = generate_queries(args.techniques)
        results["total_queries"] = len(results["queries"])

    if args.parse_results:
        findings = parse_splunk_results(args.parse_results)
        results["findings"] = findings
        results["total_findings"] = len(findings)

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
