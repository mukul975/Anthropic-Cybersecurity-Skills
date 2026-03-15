#!/usr/bin/env python3
"""Threat intelligence enrichment pipeline for Splunk.

Manages threat intel lookups, KV store collections, and modular inputs
for enriching Splunk events with IOC context from MISP, OTX, and CSV feeds.
"""

import sys
import json
import csv
import os
import datetime
import io

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


SPLUNK_TI_COLLECTIONS = {
    "ip_intel": {
        "fields": ["ip", "threat_key", "description", "source", "weight", "time"],
        "lookup_name": "ip_intel_lookup",
    },
    "domain_intel": {
        "fields": ["domain", "threat_key", "description", "source", "weight", "time"],
        "lookup_name": "domain_intel_lookup",
    },
    "file_intel": {
        "fields": ["file_hash", "file_name", "threat_key", "description", "source", "weight", "time"],
        "lookup_name": "file_intel_lookup",
    },
    "email_intel": {
        "fields": ["src_user", "threat_key", "description", "source", "weight", "time"],
        "lookup_name": "email_intel_lookup",
    },
}


def fetch_otx_pulse_iocs(pulse_id):
    """Fetch IOCs from AlienVault OTX pulse."""
    if not HAS_REQUESTS:
        return {"error": "requests not installed"}
    url = "https://otx.alienvault.com/api/v1/pulses/{}/indicators".format(pulse_id)
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            iocs = []
            for ind in data.get("results", []):
                iocs.append({
                    "type": ind.get("type", ""),
                    "indicator": ind.get("indicator", ""),
                    "title": ind.get("title", ""),
                    "created": ind.get("created", ""),
                })
            return {"pulse_id": pulse_id, "count": len(iocs), "indicators": iocs}
        return {"error": "HTTP {}".format(resp.status_code)}
    except Exception as e:
        return {"error": str(e)}


def convert_iocs_to_splunk_lookup(iocs, collection_type="ip_intel"):
    """Convert IOC list to Splunk KV store format."""
    collection = SPLUNK_TI_COLLECTIONS.get(collection_type, SPLUNK_TI_COLLECTIONS["ip_intel"])
    rows = []
    now = datetime.datetime.utcnow().isoformat() + "Z"
    for ioc in iocs:
        if collection_type == "ip_intel" and ioc.get("type") in ("IPv4", "IPv6"):
            rows.append({
                "ip": ioc["indicator"],
                "threat_key": ioc.get("title", "malicious_ip"),
                "description": "OTX: " + ioc.get("title", ""),
                "source": "otx",
                "weight": "3",
                "time": now,
            })
        elif collection_type == "domain_intel" and ioc.get("type") in ("domain", "hostname"):
            rows.append({
                "domain": ioc["indicator"],
                "threat_key": ioc.get("title", "malicious_domain"),
                "description": "OTX: " + ioc.get("title", ""),
                "source": "otx",
                "weight": "3",
                "time": now,
            })
        elif collection_type == "file_intel" and ioc.get("type") in ("FileHash-SHA256", "FileHash-MD5"):
            rows.append({
                "file_hash": ioc["indicator"],
                "file_name": "",
                "threat_key": ioc.get("title", "malicious_file"),
                "description": "OTX: " + ioc.get("title", ""),
                "source": "otx",
                "weight": "3",
                "time": now,
            })
    return {"collection": collection_type, "lookup_name": collection["lookup_name"], "row_count": len(rows), "rows": rows}


def generate_splunk_lookup_csv(rows, output_path=None):
    """Generate CSV file for Splunk lookup table."""
    if not rows:
        return ""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    csv_content = output.getvalue()
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(csv_content)
    return csv_content


def build_spl_correlation_search(collection_type="ip_intel"):
    """Build SPL query for threat intelligence correlation."""
    queries = {
        "ip_intel": (
            '| tstats summariesonly=t count from datamodel=Network_Traffic '
            'by All_Traffic.dest_ip '
            '| rename All_Traffic.dest_ip as ip '
            '| lookup ip_intel_lookup ip OUTPUT threat_key description source '
            '| where isnotnull(threat_key) '
            '| table ip threat_key description source count'
        ),
        "domain_intel": (
            '| tstats summariesonly=t count from datamodel=Network_Resolution '
            'by DNS.query '
            '| rename DNS.query as domain '
            '| lookup domain_intel_lookup domain OUTPUT threat_key description source '
            '| where isnotnull(threat_key) '
            '| table domain threat_key description source count'
        ),
        "file_intel": (
            'index=endpoint sourcetype=sysmon EventCode=1 '
            '| lookup file_intel_lookup file_hash as Hashes OUTPUT threat_key description '
            '| where isnotnull(threat_key) '
            '| table _time Computer Image Hashes threat_key description'
        ),
    }
    return queries.get(collection_type, "| makeresults | eval error=\"Unknown collection\"")


if __name__ == "__main__":
    print("=" * 60)
    print("Threat Intelligence Enrichment in Splunk")
    print("KV store collections, lookup tables, SPL correlation")
    print("=" * 60)
    print("  requests available: {}".format(HAS_REQUESTS))

    print("\n--- Splunk TI Collections ---")
    for name, info in SPLUNK_TI_COLLECTIONS.items():
        print("  {}: lookup={}, fields={}".format(name, info["lookup_name"], len(info["fields"])))

    print("\n--- SPL Correlation Queries ---")
    for ctype in ["ip_intel", "domain_intel", "file_intel"]:
        spl = build_spl_correlation_search(ctype)
        print("  [{}] {}...".format(ctype, spl[:80]))

    demo_iocs = [
        {"type": "IPv4", "indicator": "198.51.100.42", "title": "C2 Server"},
        {"type": "domain", "indicator": "evil.example.com", "title": "Phishing Domain"},
        {"type": "FileHash-SHA256", "indicator": "a" * 64, "title": "Malware Sample"},
    ]
    for ctype in ["ip_intel", "domain_intel", "file_intel"]:
        result = convert_iocs_to_splunk_lookup(demo_iocs, ctype)
        if result["row_count"] > 0:
            print("\n  Converted {} IOCs to {} format".format(result["row_count"], ctype))

    print("\n" + json.dumps({"collections_configured": len(SPLUNK_TI_COLLECTIONS)}, indent=2))
