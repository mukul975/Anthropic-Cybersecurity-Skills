#!/usr/bin/env python3
"""Detect NTLM relay attacks via Windows Event 4624 analysis, IP-hostname correlation, and SMB signing audit."""

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone


def query_security_log(event_id, max_events=2000):
    """Query Windows Security event log for specific event ID using wevtutil."""
    cmd = [
        "wevtutil", "qe", "Security",
        "/q:*[System[(EventID={})]]".format(event_id),
        "/c:{}".format(max_events),
        "/f:xml", "/rd:true"
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return proc.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def parse_4624_events(xml_data):
    """Parse Event 4624 logon events from XML output."""
    events = []
    if not xml_data:
        return events

    blocks = re.split(r"<Event\s+xmlns=", xml_data)
    for block in blocks[1:]:
        time_match = re.search(r"<TimeCreated\s+SystemTime='([^']+)'", block)
        computer_match = re.search(r"<Computer>([^<]+)</Computer>", block)

        data_fields = {}
        for m in re.finditer(r"<Data Name='(\w+)'>([^<]*)</Data>", block):
            data_fields[m.group(1)] = m.group(2)

        logon_type = data_fields.get("LogonType", "")
        if logon_type != "3":
            continue

        auth_package = data_fields.get("AuthenticationPackageName", "")
        if "NTLM" not in auth_package.upper():
            continue

        events.append({
            "timestamp": time_match.group(1) if time_match else "",
            "computer": computer_match.group(1) if computer_match else "",
            "target_username": data_fields.get("TargetUserName", ""),
            "target_domain": data_fields.get("TargetDomainName", ""),
            "logon_type": logon_type,
            "auth_package": auth_package,
            "lm_package": data_fields.get("LmPackageName", ""),
            "workstation_name": data_fields.get("WorkstationName", ""),
            "source_ip": data_fields.get("IpAddress", ""),
            "source_port": data_fields.get("IpPort", ""),
            "logon_process": data_fields.get("LogonProcessName", ""),
            "target_sid": data_fields.get("TargetUserSid", ""),
            "logon_guid": data_fields.get("LogonGuid", ""),
            "impersonation_level": data_fields.get("ImpersonationLevel", "")
        })

    return events


def parse_5145_events(xml_data):
    """Parse Event 5145 network share access events for named pipe monitoring."""
    events = []
    if not xml_data:
        return events

    suspicious_pipes = [
        "spoolss", "netdfs", "lsarpc", "lsass", "netlogon", "samr",
        "efsrpc", "fssagentrpc", "eventlog", "winreg", "srvsvc",
        "dnsserver", "dhcpserver", "winspipe"
    ]

    blocks = re.split(r"<Event\s+xmlns=", xml_data)
    for block in blocks[1:]:
        time_match = re.search(r"<TimeCreated\s+SystemTime='([^']+)'", block)
        data_fields = {}
        for m in re.finditer(r"<Data Name='(\w+)'>([^<]*)</Data>", block):
            data_fields[m.group(1)] = m.group(2)

        share_name = data_fields.get("ShareName", "").lower()
        relative_target = data_fields.get("RelativeTargetName", "").lower()

        if any(pipe in relative_target for pipe in suspicious_pipes):
            events.append({
                "timestamp": time_match.group(1) if time_match else "",
                "subject_username": data_fields.get("SubjectUserName", ""),
                "subject_domain": data_fields.get("SubjectDomainName", ""),
                "source_ip": data_fields.get("IpAddress", ""),
                "share_name": share_name,
                "pipe_name": relative_target
            })

    return events


def detect_ip_hostname_mismatch(events):
    """Detect when WorkstationName IP doesn't match source IpAddress."""
    findings = []
    hostname_ip_map = defaultdict(set)

    # Build hostname-to-IP baseline
    for event in events:
        hostname = event.get("workstation_name", "").upper()
        ip = event.get("source_ip", "")
        if hostname and ip and ip != "-" and ip != "::1" and ip != "127.0.0.1":
            hostname_ip_map[hostname].add(ip)

    # Detect hostnames authenticating from multiple IPs
    for hostname, ips in hostname_ip_map.items():
        if len(ips) > 2:
            findings.append({
                "check": "multiple_source_ips",
                "severity": "High",
                "hostname": hostname,
                "source_ips": list(ips),
                "ip_count": len(ips),
                "description": f"Workstation '{hostname}' authenticating via NTLM from {len(ips)} different IPs — possible relay",
                "mitre": "T1557.001"
            })

    return findings


def detect_machine_account_relay(events):
    """Detect machine accounts authenticating from unexpected IPs."""
    findings = []
    machine_events = [e for e in events if e["target_username"].endswith("$")]
    machine_ip_map = defaultdict(set)

    for event in machine_events:
        machine_ip_map[event["target_username"]].add(event["source_ip"])

    for machine, ips in machine_ip_map.items():
        if len(ips) > 1:
            findings.append({
                "check": "machine_account_multi_ip",
                "severity": "Critical",
                "machine_account": machine,
                "source_ips": list(ips),
                "description": f"Machine account '{machine}' authenticated from {len(ips)} different IPs",
                "mitre": "T1557.001"
            })

    return findings


def detect_rapid_authentication(events, window_seconds=5, threshold=5):
    """Detect rapid multi-host authentication from a single account."""
    findings = []
    user_events = defaultdict(list)

    for event in events:
        user_key = f"{event['target_domain']}\\{event['target_username']}"
        user_events[user_key].append(event)

    for user, user_evts in user_events.items():
        if user.endswith("$"):
            continue
        sorted_evts = sorted(user_evts, key=lambda x: x.get("timestamp", ""))
        unique_targets = set()
        window_start = 0

        for i, evt in enumerate(sorted_evts):
            unique_targets.add(evt.get("computer", ""))
            if len(unique_targets) >= threshold:
                findings.append({
                    "check": "rapid_multi_host_auth",
                    "severity": "Critical",
                    "username": user,
                    "target_count": len(unique_targets),
                    "targets": list(unique_targets)[:10],
                    "description": f"User '{user}' authenticated to {len(unique_targets)} hosts in rapid succession",
                    "mitre": "T1557.001"
                })
                break

    return findings


def detect_null_sid_logons(events):
    """Detect logon events with NULL SID and missing LogonGUID — relay indicator."""
    findings = []
    null_events = []

    for event in events:
        sid = event.get("target_sid", "")
        guid = event.get("logon_guid", "")
        if (sid == "S-1-0-0" or sid == "NULL SID" or not sid) and (not guid or guid == "{00000000-0000-0000-0000-000000000000}"):
            null_events.append(event)

    if null_events:
        findings.append({
            "check": "null_sid_logon",
            "severity": "High",
            "event_count": len(null_events),
            "description": f"{len(null_events)} NTLM logon events with NULL SID and empty LogonGUID detected",
            "sample_events": null_events[:5],
            "mitre": "T1557.001"
        })

    return findings


def check_smb_signing(hosts=None):
    """Check SMB signing status on specified hosts using PowerShell."""
    if not hosts:
        # Get domain computers from AD
        cmd = [
            "powershell", "-NoProfile", "-Command",
            "Get-ADComputer -Filter * -Property DNSHostName | "
            "Select-Object -ExpandProperty DNSHostName | "
            "ConvertTo-Json"
        ]
    else:
        cmd = ["powershell", "-NoProfile", "-Command",
               f"'{','.join(hosts)}' -split ',' | ConvertTo-Json"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            return [{"error": "Failed to enumerate hosts", "stderr": proc.stderr.strip()}]

        host_list = json.loads(proc.stdout) if proc.stdout.strip() else []
        if isinstance(host_list, str):
            host_list = [host_list]
    except Exception as e:
        return [{"error": str(e)}]

    results = []
    for host in host_list[:50]:
        check_cmd = [
            "powershell", "-NoProfile", "-Command",
            f"try {{ $smb = Get-SmbServerConfiguration -CimSession '{host}' "
            f"-ErrorAction Stop; "
            f"@{{ Host='{host}'; RequireSecuritySignature=$smb.RequireSecuritySignature; "
            f"EnableSecuritySignature=$smb.EnableSecuritySignature }} | ConvertTo-Json "
            f"}} catch {{ @{{ Host='{host}'; Error=$_.Exception.Message }} | ConvertTo-Json }}"
        ]
        try:
            proc = subprocess.run(check_cmd, capture_output=True, text=True, timeout=10)
            if proc.stdout.strip():
                result = json.loads(proc.stdout)
                if not result.get("RequireSecuritySignature", True):
                    result["severity"] = "High"
                    result["message"] = f"SMB signing not required on {host} — vulnerable to relay"
                results.append(result)
        except Exception:
            results.append({"host": host, "error": "Connection failed"})

    return results


def run_hunt(args):
    """Run full NTLM relay detection hunt."""
    results = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "events_analyzed": 0,
        "findings": [],
        "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0}
    }

    # Parse Event 4624 NTLM logon events
    xml_4624 = query_security_log(4624, args.max_events)
    events = parse_4624_events(xml_4624)
    results["events_analyzed"] = len(events)

    # Run all detection checks
    results["findings"].extend(detect_ip_hostname_mismatch(events))
    results["findings"].extend(detect_machine_account_relay(events))
    results["findings"].extend(detect_rapid_authentication(events))
    results["findings"].extend(detect_null_sid_logons(events))

    # Parse Event 5145 for named pipe access
    if args.check_pipes:
        xml_5145 = query_security_log(5145, args.max_events)
        pipe_events = parse_5145_events(xml_5145)
        if pipe_events:
            results["findings"].append({
                "check": "suspicious_pipe_access",
                "severity": "Medium",
                "event_count": len(pipe_events),
                "description": f"{len(pipe_events)} accesses to sensitive named pipes detected",
                "sample_events": pipe_events[:5],
                "mitre": "T1557.001"
            })

    # Check SMB signing if requested
    if args.check_smb_signing:
        smb_results = check_smb_signing(args.hosts.split(",") if args.hosts else None)
        unsigned = [r for r in smb_results if r.get("severity") == "High"]
        if unsigned:
            results["findings"].append({
                "check": "smb_signing_disabled",
                "severity": "High",
                "hosts_without_signing": len(unsigned),
                "details": unsigned[:10],
                "description": f"{len(unsigned)} hosts do not require SMB signing",
                "mitre": "T1557.001"
            })

    # Calculate summary
    for f in results["findings"]:
        results["summary"]["total_findings"] += 1
        sev = f.get("severity", "").lower()
        if sev in results["summary"]:
            results["summary"][sev] += 1

    return results


def main():
    parser = argparse.ArgumentParser(description="Hunt for NTLM relay attacks in Windows event logs")
    parser.add_argument("--max-events", type=int, default=2000, help="Max events to query (default: 2000)")
    parser.add_argument("--check-pipes", action="store_true", help="Also check Event 5145 for named pipe access")
    parser.add_argument("--check-smb-signing", action="store_true", help="Audit SMB signing on domain hosts")
    parser.add_argument("--hosts", help="Comma-separated list of hosts to check SMB signing")
    parser.add_argument("--output", "-o", default="-", help="Output file (default: stdout)")
    args = parser.parse_args()

    results = run_hunt(args)
    output = json.dumps(results, indent=2, default=str)

    if args.output == "-":
        print(output)
    else:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Hunt report written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
