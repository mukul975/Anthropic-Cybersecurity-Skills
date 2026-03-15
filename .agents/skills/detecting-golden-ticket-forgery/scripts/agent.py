#!/usr/bin/env python3
"""Detect Kerberos Golden Ticket forgery via Windows Security event log analysis."""

import json
import argparse
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime


def parse_security_events(xml_path):
    """Parse exported Windows Security event log XML for Kerberos events 4768/4769."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    events = []
    for event_el in root.findall(".//e:Event", ns):
        sys_el = event_el.find("e:System", ns)
        event_id = int(sys_el.find("e:EventID", ns).text)
        if event_id not in (4768, 4769):
            continue
        time_created = sys_el.find("e:TimeCreated", ns).attrib.get("SystemTime", "")
        data_el = event_el.find("e:EventData", ns)
        fields = {}
        for d in data_el.findall("e:Data", ns):
            fields[d.attrib.get("Name", "")] = d.text or ""
        events.append({"event_id": event_id, "timestamp": time_created, **fields})
    return events


def detect_rc4_in_aes_environment(events):
    """Detect RC4 encryption (0x17) in TGS requests where AES should be enforced."""
    alerts = []
    for ev in events:
        if ev["event_id"] != 4769:
            continue
        enc_type = ev.get("TicketEncryptionType", "")
        if enc_type in ("0x17", "23"):
            alerts.append({
                "detection": "RC4 Encryption in TGS Request",
                "mitre_technique": "T1558.001",
                "timestamp": ev["timestamp"],
                "user": ev.get("TargetUserName", ""),
                "domain": ev.get("TargetDomainName", ""),
                "service": ev.get("ServiceName", ""),
                "ip_address": ev.get("IpAddress", ""),
                "encryption_type": enc_type,
                "severity": "critical",
                "description": "RC4 (0x17) encryption detected in TGS request; Golden Ticket indicator in AES-enforced environments",
            })
    return alerts


def detect_orphaned_tgs(events):
    """Detect TGS requests (4769) without preceding TGT request (4768) from same user."""
    tgt_users = set()
    for ev in events:
        if ev["event_id"] == 4768:
            tgt_users.add(f"{ev.get('TargetUserName', '')}@{ev.get('TargetDomainName', '')}")
    alerts = []
    tgs_without_tgt = defaultdict(list)
    for ev in events:
        if ev["event_id"] != 4769:
            continue
        user_key = f"{ev.get('TargetUserName', '')}@{ev.get('TargetDomainName', '')}"
        if user_key not in tgt_users and ev.get("TargetUserName", ""):
            tgs_without_tgt[user_key].append(ev)
    for user, tgs_events in tgs_without_tgt.items():
        alerts.append({
            "detection": "Orphaned TGS Request (No Preceding TGT)",
            "mitre_technique": "T1558.001",
            "user": user,
            "tgs_count": len(tgs_events),
            "services": list({e.get("ServiceName", "") for e in tgs_events}),
            "source_ips": list({e.get("IpAddress", "") for e in tgs_events}),
            "first_seen": tgs_events[0]["timestamp"],
            "severity": "critical",
            "description": "TGS requests without corresponding TGT; forged ticket likely",
        })
    return alerts


def detect_abnormal_ticket_lifetime(events, max_lifetime_hours=10):
    """Detect tickets with lifetime exceeding domain policy (default MaxTicketAge=10h)."""
    user_tgt_times = defaultdict(list)
    for ev in events:
        if ev["event_id"] == 4768 and ev.get("TargetUserName"):
            try:
                ts = datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00"))
                user_tgt_times[ev["TargetUserName"]].append(ts)
            except (ValueError, AttributeError):
                continue
    alerts = []
    for user, times in user_tgt_times.items():
        if len(times) < 2:
            continue
        times.sort()
        for i in range(1, len(times)):
            gap_hours = (times[i] - times[i - 1]).total_seconds() / 3600
            if gap_hours > max_lifetime_hours * 2:
                alerts.append({
                    "detection": "Abnormal TGT Renewal Gap",
                    "mitre_technique": "T1558.001",
                    "user": user,
                    "gap_hours": round(gap_hours, 2),
                    "max_expected_hours": max_lifetime_hours,
                    "severity": "high",
                    "description": f"TGT renewal gap of {gap_hours:.1f}h exceeds 2x MaxTicketAge ({max_lifetime_hours}h)",
                })
    return alerts


def detect_krbtgt_service_anomaly(events):
    """Detect TGS requests targeting the krbtgt service (unusual and suspicious)."""
    alerts = []
    for ev in events:
        if ev["event_id"] == 4769 and ev.get("ServiceName", "").lower().startswith("krbtgt"):
            alerts.append({
                "detection": "TGS Request Targeting krbtgt Service",
                "mitre_technique": "T1558.001",
                "timestamp": ev["timestamp"],
                "user": ev.get("TargetUserName", ""),
                "service": ev.get("ServiceName", ""),
                "ip_address": ev.get("IpAddress", ""),
                "severity": "critical",
                "description": "Direct TGS request for krbtgt service is highly anomalous",
            })
    return alerts


def generate_splunk_queries():
    """Return Splunk SPL queries for Golden Ticket detection."""
    return {
        "rc4_downgrade": (
            'index=wineventlog sourcetype="WinEventLog:Security" EventCode=4769 '
            'TicketEncryptionType=0x17 ServiceName!="krbtgt" '
            '| stats count by TargetUserName, IpAddress, ServiceName'
        ),
        "orphaned_tgs": (
            'index=wineventlog EventCode=4769 '
            '| join type=left TargetUserName [search index=wineventlog EventCode=4768 '
            '| rename TargetUserName as tgt_user | dedup tgt_user | fields tgt_user] '
            '| where isnull(tgt_user) | stats count by TargetUserName, IpAddress'
        ),
        "krbtgt_tgs": (
            'index=wineventlog EventCode=4769 ServiceName="krbtgt*" '
            '| table _time, TargetUserName, IpAddress, ServiceName, TicketEncryptionType'
        ),
    }


def main():
    parser = argparse.ArgumentParser(description="Golden Ticket Forgery Detector")
    parser.add_argument("--evtx-xml", help="Path to exported Security event log XML")
    parser.add_argument("--max-ticket-hours", type=int, default=10, help="MaxTicketAge in hours (default: 10)")
    parser.add_argument("--output", default="golden_ticket_report.json", help="Output report path")
    parser.add_argument("--show-splunk", action="store_true", help="Print Splunk SPL queries")
    args = parser.parse_args()

    if args.show_splunk:
        for name, spl in generate_splunk_queries().items():
            print(f"\n--- {name} ---\n{spl}")
        return

    if not args.evtx_xml:
        print("[!] Provide --evtx-xml path or use --show-splunk for detection queries")
        return

    events = parse_security_events(args.evtx_xml)
    print(f"[+] Parsed {len(events)} Kerberos events (4768/4769)")

    rc4_alerts = detect_rc4_in_aes_environment(events)
    orphan_alerts = detect_orphaned_tgs(events)
    lifetime_alerts = detect_abnormal_ticket_lifetime(events, args.max_ticket_hours)
    krbtgt_alerts = detect_krbtgt_service_anomaly(events)

    report = {
        "analysis_time": datetime.utcnow().isoformat() + "Z",
        "total_events": len(events),
        "detections": {
            "rc4_encryption_downgrade": rc4_alerts,
            "orphaned_tgs_requests": orphan_alerts,
            "abnormal_ticket_lifetime": lifetime_alerts,
            "krbtgt_service_anomaly": krbtgt_alerts,
        },
        "total_alerts": len(rc4_alerts) + len(orphan_alerts) + len(lifetime_alerts) + len(krbtgt_alerts),
        "mitre_techniques": ["T1558.001"],
        "splunk_queries": generate_splunk_queries(),
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] RC4 downgrades: {len(rc4_alerts)}")
    print(f"[+] Orphaned TGS: {len(orphan_alerts)}")
    print(f"[+] Lifetime anomalies: {len(lifetime_alerts)}")
    print(f"[+] krbtgt anomalies: {len(krbtgt_alerts)}")
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
