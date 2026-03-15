#!/usr/bin/env python3
"""Threat Intelligence Feed Integration Agent - Ingests STIX/TAXII and open-source TI feeds."""

import json
import logging
import argparse
import hashlib
from datetime import datetime, timedelta

import requests
from taxii2client.v21 import Server, Collection
from stix2 import Indicator, Bundle, parse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def ingest_taxii_feed(taxii_url, collection_url, username, password, hours_back=24):
    """Ingest indicators from a TAXII 2.1 server collection."""
    added_after = (datetime.utcnow() - timedelta(hours=hours_back)).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z"
    )
    collection = Collection(collection_url, user=username, password=password)
    response = collection.get_objects(added_after=added_after, type=["indicator"])
    indicators = []
    for obj in response.get("objects", []):
        indicator = parse(obj)
        indicators.append({
            "id": str(indicator.id),
            "pattern": indicator.pattern,
            "valid_from": str(indicator.valid_from),
            "source": "taxii",
        })
    logger.info("Ingested %d indicators from TAXII feed", len(indicators))
    return indicators


def ingest_urlhaus_feed():
    """Ingest recent malicious URLs from Abuse.ch URLhaus."""
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/"
    resp = requests.post(url, timeout=30)
    data = resp.json()
    indicators = []
    for entry in data.get("urls", []):
        indicators.append({
            "type": "url",
            "value": entry["url"],
            "threat": entry.get("threat", "unknown"),
            "status": entry.get("url_status", "unknown"),
            "tags": entry.get("tags", []),
            "source": "urlhaus",
        })
    logger.info("Ingested %d URLs from URLhaus", len(indicators))
    return indicators


def ingest_feodotracker():
    """Ingest C2 IP blocklist from Abuse.ch Feodo Tracker."""
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
    resp = requests.get(url, timeout=30)
    indicators = []
    for entry in resp.json():
        indicators.append({
            "type": "ipv4",
            "value": entry["ip_address"],
            "port": entry.get("port"),
            "malware": entry.get("malware", "unknown"),
            "first_seen": entry.get("first_seen"),
            "source": "feodotracker",
        })
    logger.info("Ingested %d C2 IPs from Feodo Tracker", len(indicators))
    return indicators


def normalize_to_stix(indicators):
    """Convert raw indicators to STIX 2.1 Indicator objects."""
    pattern_map = {
        "ipv4": lambda v: f"[ipv4-addr:value = '{v}']",
        "domain": lambda v: f"[domain-name:value = '{v}']",
        "url": lambda v: f"[url:value = '{v}']",
        "sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
    }
    stix_objects = []
    for ioc in indicators:
        ioc_type = ioc.get("type", "url")
        pattern_fn = pattern_map.get(ioc_type, pattern_map["url"])
        stix_ind = Indicator(
            name=f"{ioc_type}: {ioc['value']}",
            pattern=pattern_fn(ioc["value"]),
            pattern_type="stix",
            valid_from=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            labels=[ioc.get("source", "unknown")],
        )
        stix_objects.append(stix_ind)
    logger.info("Normalized %d indicators to STIX 2.1", len(stix_objects))
    return stix_objects


def deduplicate(indicators):
    """Deduplicate indicators across feeds by type:value hash."""
    seen = set()
    unique = []
    for ioc in indicators:
        key = hashlib.sha256(f"{ioc.get('type', '')}:{ioc['value']}".encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            unique.append(ioc)
    logger.info("Deduplicated: %d -> %d unique indicators", len(indicators), len(unique))
    return unique


def export_stix_bundle(stix_objects, output_path):
    """Export STIX 2.1 bundle to JSON file."""
    bundle = Bundle(objects=stix_objects)
    with open(output_path, "w") as f:
        f.write(bundle.serialize(pretty=True))
    logger.info("STIX bundle exported to %s (%d indicators)", output_path, len(stix_objects))


def push_to_splunk_ti(splunk_url, session_key, indicators):
    """Push indicators to Splunk ES threat intelligence framework."""
    headers = {"Authorization": f"Splunk {session_key}"}
    pushed = 0
    for ioc in indicators:
        data = {"ip": ioc["value"], "description": f"{ioc.get('source')}: {ioc['value']}"}
        resp = requests.post(
            f"{splunk_url}/services/data/threat_intel/item/ip_intel",
            headers=headers, data=data, verify=False,
        )
        if resp.status_code == 201:
            pushed += 1
    logger.info("Pushed %d indicators to Splunk TI", pushed)


def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Feed Integration Agent")
    parser.add_argument("--taxii-url", help="TAXII 2.1 server URL")
    parser.add_argument("--taxii-collection", help="TAXII collection URL")
    parser.add_argument("--taxii-user", help="TAXII username")
    parser.add_argument("--taxii-pass", help="TAXII password")
    parser.add_argument("--urlhaus", action="store_true", help="Ingest URLhaus feed")
    parser.add_argument("--feodo", action="store_true", help="Ingest Feodo Tracker feed")
    parser.add_argument("--output", default="ti_bundle.json", help="STIX bundle output")
    args = parser.parse_args()

    all_indicators = []

    if args.taxii_url and args.taxii_collection:
        taxii_iocs = ingest_taxii_feed(
            args.taxii_url, args.taxii_collection, args.taxii_user, args.taxii_pass
        )
        all_indicators.extend(taxii_iocs)

    if args.urlhaus:
        all_indicators.extend(ingest_urlhaus_feed())

    if args.feodo:
        all_indicators.extend(ingest_feodotracker())

    unique = deduplicate(all_indicators)
    stix_objects = normalize_to_stix(unique)
    export_stix_bundle(stix_objects, args.output)
    logger.info("Feed integration complete: %d total indicators", len(unique))


if __name__ == "__main__":
    main()
