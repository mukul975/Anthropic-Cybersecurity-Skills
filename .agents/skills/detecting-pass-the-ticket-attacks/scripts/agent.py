#!/usr/bin/env python3
"""Detect Kerberos Pass-the-Ticket attacks via Windows Event ID 4768/4769/4771 analysis."""

import json
import argparse
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime


def parse_evtx_xml(xml_path):
    """Parse exported Windows Security event log XML for Kerberos events."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    events = []
    for event_el in root.findall(".//e:Event", ns):
        sys_el = event_el.find("e:System", ns)
        event_id = int(sys_el.find("e:EventID", ns).text)
        if event_id not in (4768, 4769, 4771):
            continue
        time_created = sys_el.find("e:TimeCreated", ns).attrib.get("SystemTime", "")
        data_el = event_el.find("e:EventData", ns)
        fields = {}
        for d in data_el.findall("e:Data", ns):
            fields[d.attrib.get("Name", "")] = d.text or ""
        events.append({
            "event_id": event_id,
            "timestamp": time_created,
            "target_user": fields.get("TargetUserName", ""),
            "target_domain": fields.get("TargetDomainName", ""),
            "ip_address": fields.get("IpAddress", ""),
            "service_name": fields.get("ServiceName", ""),
            "ticket_encryption_type": fields.get("TicketEncryptionType", ""),
            "status": fields.get("Status", ""),
            "pre_auth_type": fields.get("PreAuthType", ""),
        })
    return events


def detect_rc4_downgrade(events):
    """Detect RC4 encryption downgrade (TicketEncryptionType 0x17) in TGS requests."""
    alerts = []
    for ev in events:
        enc_type = ev["ticket_encryption_type"]
        if enc_type in ("0x17", "23"):
            alerts.append({
                "detection": "RC4 Encryption Downgrade",
                "mitre_technique": "T1550.003",
                "event_id": ev["event_id"],
                "timestamp": ev["timestamp"],
                "user": ev["target_user"],
                "domain": ev["target_domain"],
                "service": ev["service_name"],
                "ip_address": ev["ip_address"],
                "encryption_type": enc_type,
                "severity": "high",
                "description": "RC4 (0x17) ticket encryption detected; may indicate Pass-the-Ticket or Kerberoasting",
            })
    return alerts


def detect_cross_host_ticket_reuse(events):
    """Detect same user TGS requests from multiple source IPs within short window."""
    user_ips = defaultdict(set)
    user_events = defaultdict(list)
    for ev in events:
        if ev["event_id"] == 4769 and ev["target_user"] and ev["ip_address"]:
            key = f"{ev['target_user']}@{ev['target_domain']}"
            user_ips[key].add(ev["ip_address"])
            user_events[key].append(ev)
    alerts = []
    for user, ips in user_ips.items():
        if len(ips) >= 2:
            sample = user_events[user][:5]
            alerts.append({
                "detection": "Cross-Host Ticket Reuse",
                "mitre_technique": "T1550.003",
                "user": user,
                "source_ips": list(ips),
                "ip_count": len(ips),
                "request_count": len(user_events[user]),
                "severity": "critical",
                "sample_timestamps": [e["timestamp"] for e in sample],
                "description": "Same user ticket used from multiple IPs, indicating stolen ticket replay",
            })
    return alerts


def detect_anomalous_tgs_volume(events, threshold=50):
    """Detect users requesting abnormally high number of TGS tickets."""
    user_tgs = defaultdict(int)
    for ev in events:
        if ev["event_id"] == 4769 and ev["target_user"]:
            user_tgs[f"{ev['target_user']}@{ev['target_domain']}"] += 1
    alerts = []
    for user, count in user_tgs.items():
        if count >= threshold:
            alerts.append({
                "detection": "Anomalous TGS Volume",
                "mitre_technique": "T1550.003",
                "user": user,
                "tgs_request_count": count,
                "threshold": threshold,
                "severity": "high",
                "description": f"User requested {count} service tickets (threshold: {threshold})",
            })
    return alerts


def detect_preauth_failures(events, threshold=10):
    """Detect excessive Kerberos pre-authentication failures (Event ID 4771)."""
    user_failures = defaultdict(int)
    for ev in events:
        if ev["event_id"] == 4771:
            user_failures[f"{ev['target_user']}@{ev['target_domain']}"] += 1
    alerts = []
    for user, count in user_failures.items():
        if count >= threshold:
            alerts.append({
                "detection": "Excessive Pre-Auth Failures",
                "mitre_technique": "T1110.003",
                "user": user,
                "failure_count": count,
                "severity": "medium",
                "description": f"{count} Kerberos pre-authentication failures detected",
            })
    return alerts


def generate_splunk_queries():
    """Return SPL queries for Splunk-based PtT detection."""
    return {
        "rc4_downgrade": (
            'index=wineventlog sourcetype="WinEventLog:Security" EventCode=4769 '
            'TicketEncryptionType=0x17 | stats count by TargetUserName, IpAddress, ServiceName'
        ),
        "cross_host_reuse": (
            'index=wineventlog EventCode=4769 | stats dc(IpAddress) as ip_count, '
            'values(IpAddress) as source_ips by TargetUserName | where ip_count > 1'
        ),
        "tgs_volume_anomaly": (
            'index=wineventlog EventCode=4769 | stats count by TargetUserName '
            '| where count > 50 | sort -count'
        ),
        "preauth_failures": (
            'index=wineventlog EventCode=4771 | stats count by TargetUserName, IpAddress '
            '| where count > 10'
        ),
    }


def main():
    parser = argparse.ArgumentParser(description="Pass-the-Ticket Attack Detector")
    parser.add_argument("--evtx-xml", help="Path to exported Security event log XML")
    parser.add_argument("--tgs-threshold", type=int, default=50, help="TGS volume alert threshold")
    parser.add_argument("--preauth-threshold", type=int, default=10, help="Pre-auth failure threshold")
    parser.add_argument("--output", default="ptt_detection_report.json", help="Output report path")
    parser.add_argument("--show-splunk", action="store_true", help="Print Splunk SPL queries")
    args = parser.parse_args()

    if args.show_splunk:
        queries = generate_splunk_queries()
        for name, spl in queries.items():
            print(f"\n--- {name} ---\n{spl}")
        return

    if not args.evtx_xml:
        print("[!] Provide --evtx-xml path to exported Windows Security event log XML")
        print("[*] Or use --show-splunk to get Splunk detection queries")
        return

    events = parse_evtx_xml(args.evtx_xml)
    print(f"[+] Parsed {len(events)} Kerberos events (4768/4769/4771)")

    rc4_alerts = detect_rc4_downgrade(events)
    reuse_alerts = detect_cross_host_ticket_reuse(events)
    volume_alerts = detect_anomalous_tgs_volume(events, args.tgs_threshold)
    preauth_alerts = detect_preauth_failures(events, args.preauth_threshold)

    report = {
        "analysis_time": datetime.utcnow().isoformat() + "Z",
        "total_kerberos_events": len(events),
        "detections": {
            "rc4_downgrade": rc4_alerts,
            "cross_host_ticket_reuse": reuse_alerts,
            "anomalous_tgs_volume": volume_alerts,
            "preauth_failures": preauth_alerts,
        },
        "total_alerts": len(rc4_alerts) + len(reuse_alerts) + len(volume_alerts) + len(preauth_alerts),
        "mitre_techniques": ["T1550.003", "T1558.003", "T1110.003"],
        "splunk_queries": generate_splunk_queries(),
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Alerts: RC4={len(rc4_alerts)}, Reuse={len(reuse_alerts)}, "
          f"Volume={len(volume_alerts)}, PreAuth={len(preauth_alerts)}")
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
