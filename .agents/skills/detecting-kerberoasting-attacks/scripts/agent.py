#!/usr/bin/env python3
"""Kerberoasting Detection Agent - Detects Kerberoasting via Event 4769 TGS-REQ analysis."""

import json
import logging
import argparse
from collections import defaultdict
from datetime import datetime

from Evtx.Evtx import FileHeader
from lxml import etree

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}

WEAK_ENCRYPTION_TYPES = {"0x17": "RC4-HMAC", "0x18": "RC4-HMAC-EXP"}
STRONG_ENCRYPTION_TYPES = {"0x11": "AES128", "0x12": "AES256"}


def parse_tgs_events(evtx_path):
    """Parse Event ID 4769 (Kerberos TGS requests) from Security EVTX."""
    tgs_events = []
    with open(evtx_path, "rb") as f:
        fh = FileHeader(f)
        for record in fh.records():
            try:
                xml = record.xml()
                root = etree.fromstring(xml.encode("utf-8"))
                event_id_elem = root.find(".//evt:System/evt:EventID", NS)
                if event_id_elem is None or event_id_elem.text != "4769":
                    continue
                data = {}
                for elem in root.findall(".//evt:EventData/evt:Data", NS):
                    data[elem.get("Name", "")] = elem.text or ""
                time_elem = root.find(".//evt:System/evt:TimeCreated", NS)
                timestamp = time_elem.get("SystemTime", "") if time_elem is not None else ""
                tgs_events.append({
                    "timestamp": timestamp,
                    "target_name": data.get("TargetUserName", ""),
                    "service_name": data.get("ServiceName", ""),
                    "client_address": data.get("IpAddress", ""),
                    "ticket_encryption": data.get("TicketEncryptionType", ""),
                    "ticket_options": data.get("TicketOptions", ""),
                    "status": data.get("Status", ""),
                    "logon_guid": data.get("LogonGuid", ""),
                })
            except Exception:
                continue
    logger.info("Parsed %d TGS-REQ events from %s", len(tgs_events), evtx_path)
    return tgs_events


def detect_rc4_tgs_requests(tgs_events):
    """Detect TGS requests using weak RC4-HMAC encryption (Kerberoasting indicator)."""
    rc4_requests = []
    for event in tgs_events:
        enc_type = event["ticket_encryption"]
        if enc_type in WEAK_ENCRYPTION_TYPES:
            service = event["service_name"]
            if service and not service.endswith("$") and "krbtgt" not in service.lower():
                event["encryption_name"] = WEAK_ENCRYPTION_TYPES[enc_type]
                event["indicator"] = "RC4 TGS for service account (non-machine)"
                rc4_requests.append(event)
    logger.info("Found %d RC4 TGS requests for service accounts", len(rc4_requests))
    return rc4_requests


def detect_high_volume_tgs(tgs_events, threshold=10, window_minutes=5):
    """Detect high-volume TGS requests from a single source (spray pattern)."""
    source_buckets = defaultdict(list)
    for event in tgs_events:
        source_buckets[event["client_address"]].append(event)
    alerts = []
    for source, events in source_buckets.items():
        events.sort(key=lambda e: e["timestamp"])
        unique_services = set()
        for event in events:
            unique_services.add(event["service_name"])
        if len(unique_services) >= threshold:
            alerts.append({
                "source_ip": source,
                "unique_services_requested": len(unique_services),
                "total_requests": len(events),
                "services": list(unique_services)[:20],
                "first_seen": events[0]["timestamp"],
                "last_seen": events[-1]["timestamp"],
                "indicator": "High-volume TGS spray (Kerberoasting)",
            })
    logger.info("Found %d high-volume TGS sources", len(alerts))
    return alerts


def detect_anomalous_spn_requests(tgs_events, known_spns=None):
    """Detect TGS requests for unusual or sensitive SPNs."""
    sensitive_spns = {"MSSQLSvc", "HTTP", "MSSQL", "exchangeAB", "CIFS", "HOST"}
    anomalous = []
    for event in tgs_events:
        service = event["service_name"]
        service_class = service.split("/")[0] if "/" in service else service
        if service_class in sensitive_spns:
            enc = event["ticket_encryption"]
            if enc in WEAK_ENCRYPTION_TYPES:
                event["spn_class"] = service_class
                event["risk"] = "Sensitive SPN with RC4 encryption"
                anomalous.append(event)
    logger.info("Found %d anomalous SPN requests", len(anomalous))
    return anomalous


def correlate_with_logon_events(evtx_path, suspicious_sources):
    """Correlate suspicious TGS sources with logon events (4624) for attribution."""
    source_ips = {s["source_ip"] for s in suspicious_sources}
    logon_map = {}
    with open(evtx_path, "rb") as f:
        fh = FileHeader(f)
        for record in fh.records():
            try:
                xml = record.xml()
                root = etree.fromstring(xml.encode("utf-8"))
                event_id_elem = root.find(".//evt:System/evt:EventID", NS)
                if event_id_elem is None or event_id_elem.text != "4624":
                    continue
                data = {}
                for elem in root.findall(".//evt:EventData/evt:Data", NS):
                    data[elem.get("Name", "")] = elem.text or ""
                source_ip = data.get("IpAddress", "")
                if source_ip in source_ips:
                    logon_map[source_ip] = {
                        "account": data.get("TargetUserName", ""),
                        "domain": data.get("TargetDomainName", ""),
                        "logon_type": data.get("LogonType", ""),
                        "workstation": data.get("WorkstationName", ""),
                    }
            except Exception:
                continue
    return logon_map


def generate_report(tgs_events, rc4_findings, spray_findings, spn_findings, logon_correlation):
    """Generate Kerberoasting detection report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_tgs_events": len(tgs_events),
        "rc4_service_requests": len(rc4_findings),
        "tgs_spray_sources": len(spray_findings),
        "anomalous_spn_requests": len(spn_findings),
        "rc4_details": rc4_findings[:20],
        "spray_details": spray_findings,
        "spn_details": spn_findings[:20],
        "attacker_attribution": logon_correlation,
    }
    total_findings = len(rc4_findings) + len(spray_findings) + len(spn_findings)
    print(f"KERBEROASTING DETECTION: {total_findings} indicators found")
    return report


def main():
    parser = argparse.ArgumentParser(description="Kerberoasting Detection Agent")
    parser.add_argument("--evtx-file", required=True, help="Path to Security EVTX file")
    parser.add_argument("--spray-threshold", type=int, default=10)
    parser.add_argument("--output", default="kerberoast_report.json")
    args = parser.parse_args()

    tgs_events = parse_tgs_events(args.evtx_file)
    rc4_findings = detect_rc4_tgs_requests(tgs_events)
    spray_findings = detect_high_volume_tgs(tgs_events, args.spray_threshold)
    spn_findings = detect_anomalous_spn_requests(tgs_events)
    logon_map = correlate_with_logon_events(args.evtx_file, spray_findings)

    report = generate_report(tgs_events, rc4_findings, spray_findings, spn_findings, logon_map)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
