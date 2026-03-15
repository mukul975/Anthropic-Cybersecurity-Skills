#!/usr/bin/env python3
"""Pass-the-Ticket attack detection agent using Windows event log analysis."""

import json
import sys
import argparse
from datetime import datetime


def detect_ptt_events(log_file):
    """Analyze Windows Security logs for Pass-the-Ticket indicators."""
    detections = []
    try:
        with open(log_file, "r") as f:
            events = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        return [{"error": str(e)}]

    for event in events:
        eid = str(event.get("EventID", ""))
        if eid == "4768":
            if event.get("TicketEncryptionType") == "0x17":
                detections.append({
                    "event_id": eid,
                    "type": "TGT_request_rc4",
                    "account": event.get("TargetUserName", ""),
                    "source_ip": event.get("IpAddress", ""),
                    "severity": "HIGH",
                    "note": "RC4 TGT request may indicate golden ticket",
                })
        elif eid == "4769":
            if event.get("TicketEncryptionType") == "0x17":
                detections.append({
                    "event_id": eid,
                    "type": "service_ticket_rc4",
                    "account": event.get("TargetUserName", ""),
                    "service": event.get("ServiceName", ""),
                    "severity": "MEDIUM",
                    "note": "RC4 service ticket — potential Kerberoasting or PTT",
                })
        elif eid == "4624":
            if event.get("LogonType") == "3" and event.get("AuthenticationPackageName") == "Kerberos":
                source = event.get("IpAddress", "")
                detections.append({
                    "event_id": eid,
                    "type": "network_logon_kerberos",
                    "account": event.get("TargetUserName", ""),
                    "source_ip": source,
                    "severity": "INFO",
                    "note": "Kerberos network logon — correlate with TGT anomalies",
                })
    return detections


def generate_sigma_rules():
    """Generate Sigma detection rules for Pass-the-Ticket."""
    rules = [
        {
            "title": "Pass-the-Ticket via RC4 Encryption Downgrade",
            "logsource": {"product": "windows", "service": "security"},
            "detection": {
                "selection": {"EventID": [4768, 4769], "TicketEncryptionType": "0x17"},
                "condition": "selection",
            },
            "level": "high",
            "tags": ["attack.lateral_movement", "attack.t1550.003"],
        },
        {
            "title": "Anomalous Kerberos TGT Request from Non-Domain Controller",
            "logsource": {"product": "windows", "service": "security"},
            "detection": {
                "selection": {"EventID": 4768},
                "filter": {"IpAddress|startswith": ["::1", "127."]},
                "condition": "selection and not filter",
            },
            "level": "medium",
            "tags": ["attack.credential_access", "attack.t1558"],
        },
    ]
    return rules


def generate_hunt_queries():
    """Generate threat hunting queries for PTT detection."""
    return {
        "splunk": [
            'index=wineventlog EventCode=4768 TicketEncryptionType=0x17 | stats count by Account_Name, src_ip',
            'index=wineventlog EventCode=4769 ServiceName!="krbtgt" TicketEncryptionType=0x17 | table _time Account_Name ServiceName',
        ],
        "kql": [
            'SecurityEvent | where EventID == 4768 | where TicketEncryptionType == "0x17" | summarize count() by TargetAccount, IpAddress',
            'SecurityEvent | where EventID == 4769 | where TicketEncryptionType == "0x17" | project TimeGenerated, TargetAccount, ServiceName',
        ],
    }


def run_detection(log_file=None):
    """Execute Pass-the-Ticket detection analysis."""
    print(f"\n{'='*60}")
    print(f"  PASS-THE-TICKET DETECTION ANALYSIS")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    if log_file:
        events = detect_ptt_events(log_file)
        print(f"--- EVENT ANALYSIS ({len(events)} detections) ---")
        for e in events[:15]:
            if "error" not in e:
                print(f"  [{e['severity']}] {e['type']}: {e.get('account', 'N/A')} from {e.get('source_ip', 'N/A')}")

    rules = generate_sigma_rules()
    print(f"\n--- SIGMA RULES ({len(rules)}) ---")
    for r in rules:
        print(f"  [{r['level'].upper()}] {r['title']}")

    queries = generate_hunt_queries()
    print(f"\n--- HUNT QUERIES ---")
    for platform, qlist in queries.items():
        print(f"  {platform.upper()}:")
        for q in qlist:
            print(f"    {q[:80]}...")

    return {"detections": events if log_file else [], "sigma_rules": rules, "hunt_queries": queries}


def main():
    parser = argparse.ArgumentParser(description="Pass-the-Ticket Detection Agent")
    parser.add_argument("--log-file", help="Windows event log JSON export")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_detection(args.log_file)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
