#!/usr/bin/env python3
"""Agent for analyzing security logs with Splunk using splunk-sdk."""

import os
import sys
import json
import time
import argparse
from datetime import datetime, timedelta

import splunklib.client as client
import splunklib.results as results


def connect_splunk(host, port, username, password):
    """Establish connection to Splunk instance."""
    service = client.connect(
        host=host,
        port=port,
        username=username,
        password=password,
        autologin=True,
    )
    return service


def run_search(service, query, earliest="-24h", latest="now"):
    """Execute a Splunk search and return parsed results."""
    kwargs_search = {
        "earliest_time": earliest,
        "latest_time": latest,
        "search_mode": "normal",
        "exec_mode": "blocking",
    }
    job = service.jobs.create(f"search {query}", **kwargs_search)
    reader = results.JSONResultsReader(job.results(output_mode="json"))
    rows = [row for row in reader if isinstance(row, dict)]
    job.cancel()
    return rows


def detect_brute_force(service, threshold=10, earliest="-24h"):
    """Detect brute force attacks via failed logon events (EventCode 4625)."""
    query = (
        'index=windows sourcetype="WinEventLog:Security" EventCode=4625 '
        f"| stats count as failed_attempts, dc(src_ip) as unique_sources, "
        f"values(src_ip) as source_ips by TargetUserName "
        f"| where failed_attempts > {threshold} "
        f"| sort -failed_attempts"
    )
    return run_search(service, query, earliest=earliest)


def detect_lateral_movement(service, earliest="-24h"):
    """Detect lateral movement via Type 3 network logons to multiple hosts."""
    query = (
        'index=windows sourcetype="WinEventLog:Security" EventCode=4624 '
        "Logon_Type=3 "
        "| stats dc(ComputerName) as unique_targets, values(ComputerName) as targets "
        "by TargetUserName, src_ip "
        "| where unique_targets > 3 "
        "| sort -unique_targets"
    )
    return run_search(service, query, earliest=earliest)


def detect_suspicious_powershell(service, earliest="-24h"):
    """Detect encoded or download-cradle PowerShell execution via Sysmon."""
    query = (
        'index=sysmon EventCode=1 Image="*\\\\powershell.exe" '
        '(CommandLine="*-enc*" OR CommandLine="*-encodedcommand*" '
        'OR CommandLine="*downloadstring*" OR CommandLine="*iex*") '
        "| table _time, host, User, ParentImage, CommandLine "
        "| sort _time"
    )
    return run_search(service, query, earliest=earliest)


def detect_lsass_access(service, earliest="-24h"):
    """Detect credential dumping via LSASS process access (Sysmon Event 10)."""
    query = (
        'index=sysmon EventCode=10 TargetImage="*\\\\lsass.exe" '
        "GrantedAccess=0x1010 "
        "| table _time, host, SourceImage, SourceUser, GrantedAccess"
    )
    return run_search(service, query, earliest=earliest)


def build_incident_timeline(service, hosts, users, earliest="-24h", latest="now"):
    """Build a unified incident timeline across multiple log sources."""
    host_filter = " OR ".join(f'host="{h}"' for h in hosts)
    user_filter = " OR ".join(f'user="{u}"' for u in users)
    query = (
        f"index=windows OR index=sysmon OR index=proxy OR index=firewall "
        f"({host_filter} OR {user_filter}) "
        '| eval event_summary=case('
        '    sourcetype=="WinEventLog:Security" AND EventCode==4624, '
        '    "Logon: ".TargetUserName." from ".src_ip, '
        '    sourcetype=="WinEventLog:Security" AND EventCode==4625, '
        '    "Failed logon: ".TargetUserName, '
        '    EventCode==1, "Process: ".Image." by ".User, '
        '    1==1, sourcetype.": ".EventCode) '
        "| table _time, sourcetype, host, event_summary "
        "| sort _time"
    )
    return run_search(service, query, earliest=earliest, latest=latest)


def generate_report(findings):
    """Format investigation findings into a structured report."""
    report = {
        "report_type": "SPLUNK INVESTIGATION REPORT",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "findings": findings,
    }
    return json.dumps(report, indent=2, default=str)


def main():
    parser = argparse.ArgumentParser(description="Splunk Security Log Analysis Agent")
    parser.add_argument("--host", default=os.getenv("SPLUNK_HOST", "localhost"))
    parser.add_argument("--port", type=int, default=int(os.getenv("SPLUNK_PORT", "8089")))
    parser.add_argument("--username", default=os.getenv("SPLUNK_USERNAME", "admin"))
    parser.add_argument("--password", default=os.getenv("SPLUNK_PASSWORD", ""))
    parser.add_argument("--earliest", default="-24h", help="Search earliest time")
    parser.add_argument("--action", choices=[
        "brute_force", "lateral_movement", "powershell",
        "lsass_access", "timeline", "full_investigation"
    ], default="full_investigation")
    parser.add_argument("--hosts", nargs="*", default=[], help="Target hosts for timeline")
    parser.add_argument("--users", nargs="*", default=[], help="Target users for timeline")
    parser.add_argument("--threshold", type=int, default=10)
    args = parser.parse_args()

    service = connect_splunk(args.host, args.port, args.username, args.password)
    findings = {}

    if args.action in ("brute_force", "full_investigation"):
        findings["brute_force"] = detect_brute_force(service, args.threshold, args.earliest)
        print(f"[+] Brute force: {len(findings['brute_force'])} accounts targeted")

    if args.action in ("lateral_movement", "full_investigation"):
        findings["lateral_movement"] = detect_lateral_movement(service, args.earliest)
        print(f"[+] Lateral movement: {len(findings['lateral_movement'])} suspicious paths")

    if args.action in ("powershell", "full_investigation"):
        findings["suspicious_powershell"] = detect_suspicious_powershell(service, args.earliest)
        print(f"[+] Suspicious PowerShell: {len(findings['suspicious_powershell'])} events")

    if args.action in ("lsass_access", "full_investigation"):
        findings["lsass_access"] = detect_lsass_access(service, args.earliest)
        print(f"[+] LSASS access: {len(findings['lsass_access'])} events")

    if args.action == "timeline" and args.hosts:
        findings["timeline"] = build_incident_timeline(
            service, args.hosts, args.users, args.earliest
        )
        print(f"[+] Timeline: {len(findings['timeline'])} events")

    print(generate_report(findings))


if __name__ == "__main__":
    main()
