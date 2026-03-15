#!/usr/bin/env python3
"""Agent for analyzing Windows event logs in Splunk for SOC operations."""

import os
import json
import argparse
from datetime import datetime

import splunklib.client as client
import splunklib.results as results


def connect(host, port, username, password):
    """Connect to Splunk Enterprise."""
    return client.connect(
        host=host, port=port, username=username, password=password, autologin=True
    )


def search(service, query, earliest="-24h", latest="now"):
    """Run a blocking Splunk search and return results."""
    job = service.jobs.create(
        f"search {query}",
        **{"earliest_time": earliest, "latest_time": latest, "exec_mode": "blocking"}
    )
    reader = results.JSONResultsReader(job.results(output_mode="json"))
    rows = [r for r in reader if isinstance(r, dict)]
    job.cancel()
    return rows


def detect_brute_force(service, earliest="-24h", threshold=20):
    """Detect brute force via EventCode 4625 with logon type classification."""
    query = (
        'index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625 '
        "| stats count, dc(TargetUserName) as unique_users, "
        "values(TargetUserName) as targeted_users by src_ip, Logon_Type, Status "
        f"| where count > {threshold} "
        '| eval attack_type=case(Logon_Type=3,"Network",Logon_Type=10,"RDP",'
        'Logon_Type=2,"Interactive",1=1,"Other") '
        "| sort -count"
    )
    return search(service, query, earliest)


def detect_password_spray(service, earliest="-24h"):
    """Detect password spray attacks targeting many accounts from one source."""
    query = (
        'index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625 Logon_Type=3 '
        "| bin _time span=10m "
        "| stats dc(TargetUserName) as unique_users, count as total by src_ip, _time "
        "| where unique_users > 10 AND total < unique_users * 3 "
        '| eval confidence=if(unique_users > 25, "HIGH", "MEDIUM")'
    )
    return search(service, query, earliest)


def detect_new_admin_accounts(service, earliest="-7d"):
    """Detect new accounts added to the Administrators group (T1136.001)."""
    query = (
        'index=wineventlog sourcetype="WinEventLog:Security" EventCode=4720 '
        '| join TargetUserName type=left [search index=wineventlog EventCode=4732 '
        'TargetUserName="Administrators" | rename MemberName as TargetUserName] '
        "| table _time, SubjectUserName, TargetUserName, ComputerName"
    )
    return search(service, query, earliest)


def detect_lsass_access(service, earliest="-24h"):
    """Detect LSASS credential dumping via Sysmon Event 10 (T1003.001)."""
    query = (
        'index=sysmon EventCode=10 TargetImage="*\\\\lsass.exe" '
        'GrantedAccess IN ("0x1010","0x1038","0x1fffff","0x40") '
        "| stats count by SourceImage, SourceUser, Computer, GrantedAccess "
        '| where NOT match(SourceImage, "(svchost|csrss|wininit|MsMpEng)") '
        "| sort -count"
    )
    return search(service, query, earliest)


def detect_lateral_movement_smb(service, earliest="-24h"):
    """Detect SMB lateral movement via Type 3 logons to many hosts (T1021.002)."""
    query = (
        'index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=3 '
        "| stats dc(ComputerName) as targets, values(ComputerName) as dest_hosts "
        "by src_ip, TargetUserName "
        "| where targets > 3 | sort -targets"
    )
    return search(service, query, earliest)


def detect_psexec(service, earliest="-24h"):
    """Detect PsExec execution via Sysmon process creation (T1021.002)."""
    query = (
        "index=sysmon EventCode=1 "
        '(Image="*\\\\psexec.exe" OR Image="*\\\\psexesvc.exe" '
        'OR ParentImage="*\\\\psexesvc.exe") '
        "| table _time, Computer, User, ParentImage, Image, CommandLine"
    )
    return search(service, query, earliest)


def build_forensic_timeline(service, hostname, earliest, latest="now"):
    """Build a comprehensive forensic timeline for a host."""
    query = (
        f'(index=wineventlog OR index=sysmon) Computer="{hostname}" '
        "| eval desc=case("
        '    EventCode=4624, "Logon: ".TargetUserName." (Type ".Logon_Type.")",'
        '    EventCode=4625, "Failed Logon: ".TargetUserName,'
        '    EventCode=1, "Process: ".Image," CMD: ".CommandLine,'
        '    EventCode=3, "Network: ".DestinationIp.":".DestinationPort,'
        '    EventCode=11, "File Created: ".TargetFilename,'
        '    EventCode=13, "Registry: ".TargetObject,'
        '    1=1, "Event ".EventCode) '
        "| sort _time | table _time, EventCode, desc, User, src_ip"
    )
    return search(service, query, earliest, latest)


def main():
    parser = argparse.ArgumentParser(description="Windows Event Log Splunk Analysis Agent")
    parser.add_argument("--host", default=os.getenv("SPLUNK_HOST", "localhost"))
    parser.add_argument("--port", type=int, default=int(os.getenv("SPLUNK_PORT", "8089")))
    parser.add_argument("--username", default=os.getenv("SPLUNK_USERNAME", "admin"))
    parser.add_argument("--password", default=os.getenv("SPLUNK_PASSWORD", ""))
    parser.add_argument("--earliest", default="-24h")
    parser.add_argument("--hostname", help="Target hostname for timeline")
    parser.add_argument("--action", choices=[
        "brute_force", "password_spray", "new_admin", "lsass_access",
        "lateral_smb", "psexec", "timeline", "full_hunt"
    ], default="full_hunt")
    args = parser.parse_args()

    svc = connect(args.host, args.port, args.username, args.password)
    findings = {}

    if args.action in ("brute_force", "full_hunt"):
        findings["brute_force"] = detect_brute_force(svc, args.earliest)
        print(f"[+] Brute force sources: {len(findings['brute_force'])}")

    if args.action in ("password_spray", "full_hunt"):
        findings["password_spray"] = detect_password_spray(svc, args.earliest)
        print(f"[+] Password spray events: {len(findings['password_spray'])}")

    if args.action in ("new_admin", "full_hunt"):
        findings["new_admin"] = detect_new_admin_accounts(svc)
        print(f"[+] New admin accounts: {len(findings['new_admin'])}")

    if args.action in ("lsass_access", "full_hunt"):
        findings["lsass_access"] = detect_lsass_access(svc, args.earliest)
        print(f"[+] LSASS access events: {len(findings['lsass_access'])}")

    if args.action in ("lateral_smb", "full_hunt"):
        findings["lateral_smb"] = detect_lateral_movement_smb(svc, args.earliest)
        print(f"[+] Lateral movement paths: {len(findings['lateral_smb'])}")

    if args.action == "timeline" and args.hostname:
        findings["timeline"] = build_forensic_timeline(svc, args.hostname, args.earliest)
        print(f"[+] Timeline events: {len(findings['timeline'])}")

    print(json.dumps({"generated_at": datetime.utcnow().isoformat(), "findings": findings}, indent=2, default=str))


if __name__ == "__main__":
    main()
