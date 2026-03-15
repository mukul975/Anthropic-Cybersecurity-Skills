#!/usr/bin/env python3
"""Active Directory Compromise Investigation agent - analyzes Windows Security
event logs for indicators of AD compromise including DCSync, Golden Ticket,
Kerberoasting, and lateral movement."""

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


COMPROMISE_INDICATORS = {
    4662: {"name": "DCSync Detection", "description": "Directory service object accessed with replication rights"},
    4769: {"name": "Kerberoasting", "description": "Kerberos service ticket requested with RC4 encryption"},
    4768: {"name": "Golden Ticket", "description": "Kerberos TGT requested"},
    4672: {"name": "Privileged Logon", "description": "Special privileges assigned to new logon"},
    4624: {"name": "Logon Event", "description": "Successful logon - check Type 3 for lateral movement"},
    4648: {"name": "Explicit Credential Logon", "description": "Logon using explicit credentials"},
    4720: {"name": "Account Created", "description": "New user account created"},
    4728: {"name": "Group Membership Change", "description": "Member added to global group"},
}


def parse_evtx_json(log_path: str) -> list[dict]:
    """Parse Windows event logs exported as JSON."""
    content = Path(log_path).read_text(encoding="utf-8")
    try:
        events = json.loads(content)
    except json.JSONDecodeError:
        events = [json.loads(line) for line in content.strip().splitlines() if line.strip()]
    return events


def detect_dcsync(events: list[dict]) -> list[dict]:
    """Detect DCSync attacks via Event ID 4662 with replication GUIDs."""
    replication_guids = {
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
        "89e95b76-444d-4c62-991a-0facbeda640c",
    }
    findings = []
    for evt in events:
        eid = evt.get("EventID") or evt.get("event_id")
        if eid != 4662:
            continue
        data = evt.get("EventData", evt.get("event_data", {}))
        obj_type = str(data.get("ObjectType", "")).lower().strip("{}")
        if obj_type in replication_guids:
            subject = data.get("SubjectUserName", "unknown")
            findings.append({
                "type": "dcsync_detected",
                "severity": "critical",
                "event_id": 4662,
                "subject": subject,
                "object_type": obj_type,
                "timestamp": evt.get("TimeCreated", evt.get("timestamp", "")),
                "detail": f"DCSync replication by {subject}",
            })
    return findings


def detect_kerberoasting(events: list[dict]) -> list[dict]:
    """Detect Kerberoasting via Event ID 4769 with RC4 encryption."""
    findings = []
    for evt in events:
        eid = evt.get("EventID") or evt.get("event_id")
        if eid != 4769:
            continue
        data = evt.get("EventData", evt.get("event_data", {}))
        ticket_encryption = str(data.get("TicketEncryptionType", ""))
        if ticket_encryption == "0x17":
            service = data.get("ServiceName", "unknown")
            client = data.get("TargetUserName", "unknown")
            findings.append({
                "type": "kerberoasting_detected",
                "severity": "high",
                "event_id": 4769,
                "service": service,
                "client": client,
                "encryption": "RC4 (0x17)",
                "timestamp": evt.get("TimeCreated", evt.get("timestamp", "")),
                "detail": f"RC4 TGS request for {service} by {client}",
            })
    return findings


def detect_golden_ticket(events: list[dict]) -> list[dict]:
    """Detect Golden Ticket indicators via Event ID 4768 anomalies."""
    findings = []
    for evt in events:
        eid = evt.get("EventID") or evt.get("event_id")
        if eid != 4768:
            continue
        data = evt.get("EventData", evt.get("event_data", {}))
        client = data.get("TargetUserName", "")
        ip_addr = data.get("IpAddress", "")
        if ip_addr and not ip_addr.startswith("::") and ip_addr != "127.0.0.1":
            findings.append({
                "type": "golden_ticket_indicator",
                "severity": "critical",
                "event_id": 4768,
                "client": client,
                "source_ip": ip_addr,
                "timestamp": evt.get("TimeCreated", evt.get("timestamp", "")),
                "detail": f"TGT request for {client} from {ip_addr}",
            })
    return findings


def detect_lateral_movement(events: list[dict]) -> list[dict]:
    """Detect lateral movement via Type 3 logons and explicit credential use."""
    findings = []
    lateral_events = defaultdict(list)
    for evt in events:
        eid = evt.get("EventID") or evt.get("event_id")
        data = evt.get("EventData", evt.get("event_data", {}))
        if eid == 4624:
            logon_type = str(data.get("LogonType", ""))
            if logon_type == "3":
                src_ip = data.get("IpAddress", "")
                user = data.get("TargetUserName", "")
                lateral_events[(user, src_ip)].append(
                    evt.get("TimeCreated", evt.get("timestamp", "")))
        elif eid == 4648:
            user = data.get("SubjectUserName", "")
            target = data.get("TargetServerName", "")
            findings.append({
                "type": "explicit_credential_use",
                "severity": "medium",
                "event_id": 4648,
                "user": user,
                "target_server": target,
                "timestamp": evt.get("TimeCreated", evt.get("timestamp", "")),
                "detail": f"Explicit credential logon by {user} to {target}",
            })

    for (user, src_ip), timestamps in lateral_events.items():
        if len(timestamps) > 5:
            findings.append({
                "type": "lateral_movement_pattern",
                "severity": "high",
                "user": user,
                "source_ip": src_ip,
                "logon_count": len(timestamps),
                "detail": f"{len(timestamps)} Type 3 logons by {user} from {src_ip}",
            })
    return findings


def detect_persistence(events: list[dict]) -> list[dict]:
    """Detect persistence mechanisms via account creation and group changes."""
    findings = []
    for evt in events:
        eid = evt.get("EventID") or evt.get("event_id")
        data = evt.get("EventData", evt.get("event_data", {}))
        if eid == 4720:
            creator = data.get("SubjectUserName", "unknown")
            new_account = data.get("TargetUserName", "unknown")
            findings.append({
                "type": "account_created",
                "severity": "medium",
                "event_id": 4720,
                "creator": creator,
                "new_account": new_account,
                "timestamp": evt.get("TimeCreated", evt.get("timestamp", "")),
                "detail": f"Account {new_account} created by {creator}",
            })
        elif eid in (4728, 4732):
            subject = data.get("SubjectUserName", "unknown")
            member = data.get("MemberName", "unknown")
            group = data.get("TargetUserName", "unknown")
            findings.append({
                "type": "group_membership_change",
                "severity": "high",
                "event_id": eid,
                "subject": subject,
                "member": member,
                "group": group,
                "timestamp": evt.get("TimeCreated", evt.get("timestamp", "")),
                "detail": f"{member} added to {group} by {subject}",
            })
    return findings


def generate_report(log_path: str) -> dict:
    """Run all detection checks and produce consolidated report."""
    events = parse_evtx_json(log_path)
    findings = []
    findings.extend(detect_dcsync(events))
    findings.extend(detect_kerberoasting(events))
    findings.extend(detect_golden_ticket(events))
    findings.extend(detect_lateral_movement(events))
    findings.extend(detect_persistence(events))

    severity_counts = Counter(f["severity"] for f in findings)
    return {
        "report": "ad_compromise_investigation",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "log_file": log_path,
        "total_events_analyzed": len(events),
        "total_findings": len(findings),
        "severity_summary": dict(severity_counts),
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="AD Compromise Investigation Agent")
    parser.add_argument("--log", required=True, help="Path to JSON-exported Windows Security event log")
    parser.add_argument("--output", help="Output JSON file path")
    args = parser.parse_args()

    report = generate_report(args.log)
    output = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
