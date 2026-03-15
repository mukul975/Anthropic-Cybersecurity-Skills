#!/usr/bin/env python3
"""Threat Intelligence Platform Agent - Manages MISP events, IOC ingestion, and enrichment via PyMISP."""

import json
import logging
import argparse
from datetime import datetime

import requests
from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPTag

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def connect_misp(url, key, ssl=True):
    """Connect to MISP instance via PyMISP."""
    misp = PyMISP(url, key, ssl=ssl)
    logger.info("Connected to MISP at %s", url)
    return misp


def create_threat_event(misp, info, threat_level=2, distribution=1, analysis=0, tags=None):
    """Create a new MISP event for a threat campaign."""
    event = MISPEvent()
    event.info = info
    event.threat_level_id = threat_level
    event.distribution = distribution
    event.analysis = analysis
    if tags:
        for tag_name in tags:
            tag = MISPTag()
            tag.name = tag_name
            event.add_tag(tag)
    result = misp.add_event(event, pythonify=True)
    logger.info("Created MISP event: %s (ID: %s)", info, result.id)
    return result


def add_iocs_to_event(misp, event_id, iocs):
    """Add IOC attributes to an existing MISP event."""
    type_map = {
        "ipv4": "ip-dst",
        "domain": "domain",
        "url": "url",
        "sha256": "sha256",
        "md5": "md5",
        "email": "email-src",
    }
    added = 0
    for ioc in iocs:
        ioc_type = type_map.get(ioc["type"], ioc["type"])
        attr = MISPAttribute()
        attr.type = ioc_type
        attr.value = ioc["value"]
        attr.to_ids = ioc.get("to_ids", True)
        attr.comment = ioc.get("comment", "")
        attr.category = ioc.get("category", "Network activity")
        misp.add_attribute(event_id, attr, pythonify=True)
        added += 1
    logger.info("Added %d IOCs to event %s", added, event_id)
    return added


def ingest_urlhaus_feed(misp, event_id):
    """Ingest recent malicious URLs from URLhaus into a MISP event."""
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/50/"
    resp = requests.post(url, timeout=30)
    data = resp.json()
    iocs = []
    for entry in data.get("urls", []):
        iocs.append({
            "type": "url",
            "value": entry["url"],
            "comment": f"URLhaus: {entry.get('threat', 'unknown')}",
            "to_ids": True,
            "category": "Network activity",
        })
    if iocs:
        add_iocs_to_event(misp, event_id, iocs)
    logger.info("Ingested %d URLs from URLhaus", len(iocs))
    return len(iocs)


def ingest_feodotracker_feed(misp, event_id):
    """Ingest C2 IPs from Feodo Tracker into a MISP event."""
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
    resp = requests.get(url, timeout=30)
    iocs = []
    for entry in resp.json():
        iocs.append({
            "type": "ipv4",
            "value": entry["ip_address"],
            "comment": f"Feodo: {entry.get('malware', 'unknown')} port {entry.get('port', '')}",
            "to_ids": True,
            "category": "Network activity",
        })
    if iocs:
        add_iocs_to_event(misp, event_id, iocs)
    logger.info("Ingested %d C2 IPs from Feodo Tracker", len(iocs))
    return len(iocs)


def enrich_ip_virustotal(ip_address, api_key):
    """Enrich an IP address via VirusTotal API v3."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    resp = requests.get(url, headers={"x-apikey": api_key}, timeout=30)
    if resp.status_code == 200:
        attrs = resp.json()["data"]["attributes"]
        return {
            "ip": ip_address,
            "malicious": attrs.get("last_analysis_stats", {}).get("malicious", 0),
            "as_owner": attrs.get("as_owner", ""),
            "country": attrs.get("country", ""),
        }
    return {"ip": ip_address, "error": resp.status_code}


def enrich_event_iocs(misp, event_id, vt_api_key):
    """Enrich all IP attributes in a MISP event via VirusTotal."""
    event = misp.get_event(event_id, pythonify=True)
    enriched = 0
    for attr in event.attributes:
        if attr.type == "ip-dst" and vt_api_key:
            vt_data = enrich_ip_virustotal(attr.value, vt_api_key)
            if vt_data.get("malicious", 0) > 0:
                attr.comment = f"{attr.comment} | VT: {vt_data['malicious']} malicious"
                misp.update_attribute(attr, pythonify=True)
                enriched += 1
    logger.info("Enriched %d attributes via VirusTotal", enriched)
    return enriched


def tag_with_mitre(misp, event_id, techniques):
    """Tag a MISP event with MITRE ATT&CK technique identifiers."""
    event = misp.get_event(event_id, pythonify=True)
    for technique in techniques:
        tag = MISPTag()
        tag.name = f"misp-galaxy:mitre-attack-pattern=\"{technique}\""
        event.add_tag(tag)
    misp.update_event(event, pythonify=True)
    logger.info("Tagged event %s with %d MITRE techniques", event_id, len(techniques))


def search_correlated_events(misp, attribute_value):
    """Search MISP for events containing a specific attribute value."""
    results = misp.search(value=attribute_value, pythonify=True)
    events = []
    for event in results:
        events.append({
            "event_id": event.id,
            "info": event.info,
            "date": str(event.date),
            "threat_level": event.threat_level_id,
        })
    logger.info("Found %d correlated events for %s", len(events), attribute_value)
    return events


def export_stix_bundle(misp, event_id, output_path):
    """Export a MISP event as a STIX 2.1 bundle."""
    stix_data = misp.get_stix_event(event_id)
    with open(output_path, "w") as f:
        json.dump(stix_data, f, indent=2)
    logger.info("Exported STIX bundle for event %s to %s", event_id, output_path)


def generate_report(event_id, feed_counts, enriched, correlations):
    """Generate TI platform operation report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_id": event_id,
        "feed_ingestion": feed_counts,
        "enriched_attributes": enriched,
        "correlations_found": len(correlations),
    }
    total_iocs = sum(feed_counts.values())
    print(f"TI PLATFORM REPORT: Event {event_id}, {total_iocs} IOCs ingested, {enriched} enriched")
    return report


def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Platform Agent")
    parser.add_argument("--misp-url", required=True, help="MISP instance URL")
    parser.add_argument("--misp-key", required=True, help="MISP API key")
    parser.add_argument("--event-info", default="Automated TI Feed Ingestion")
    parser.add_argument("--ingest-feeds", action="store_true")
    parser.add_argument("--vt-key", help="VirusTotal API key for enrichment")
    parser.add_argument("--no-ssl", action="store_true")
    parser.add_argument("--output", default="misp_report.json")
    args = parser.parse_args()

    misp = connect_misp(args.misp_url, args.misp_key, ssl=not args.no_ssl)
    event = create_threat_event(misp, args.event_info, tags=["tlp:green", "type:osint"])
    event_id = event.id

    feed_counts = {}
    if args.ingest_feeds:
        feed_counts["urlhaus"] = ingest_urlhaus_feed(misp, event_id)
        feed_counts["feodotracker"] = ingest_feodotracker_feed(misp, event_id)

    enriched = 0
    if args.vt_key:
        enriched = enrich_event_iocs(misp, event_id, args.vt_key)

    report = generate_report(event_id, feed_counts, enriched, [])
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
