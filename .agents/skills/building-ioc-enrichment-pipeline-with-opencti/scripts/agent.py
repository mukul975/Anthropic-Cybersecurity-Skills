#!/usr/bin/env python3
"""IOC enrichment pipeline using OpenCTI and the pycti Python client.

Queries OpenCTI's GraphQL API to enrich indicators of compromise with
threat context, relationships, and scoring from connected intelligence sources.
"""

import os
import sys
import json
import datetime
import hashlib
import re

try:
    from pycti import OpenCTIApiClient
    HAS_PYCTI = True
except ImportError:
    HAS_PYCTI = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def init_client(url=None, token=None):
    """Initialize OpenCTI API client."""
    url = url or os.environ.get("OPENCTI_URL", "http://localhost:8080")
    token = token or os.environ.get("OPENCTI_TOKEN", "")
    if not HAS_PYCTI:
        return None
    return OpenCTIApiClient(url, token)


def enrich_indicator(client, indicator_value):
    """Enrich a single indicator via OpenCTI GraphQL API."""
    if not client:
        return {"error": "pycti not available"}
    filters = {
        "mode": "and",
        "filters": [{"key": "value", "values": [indicator_value]}],
        "filterGroups": [],
    }
    results = client.indicator.list(filters=filters)
    enriched = []
    for ind in results:
        entry = {
            "id": ind.get("id"),
            "pattern": ind.get("pattern"),
            "name": ind.get("name"),
            "valid_from": ind.get("valid_from"),
            "valid_until": ind.get("valid_until"),
            "score": ind.get("x_opencti_score"),
            "created_by": ind.get("createdBy", {}).get("name", "Unknown") if ind.get("createdBy") else "Unknown",
            "labels": [l.get("value") for l in ind.get("objectLabel", [])],
            "kill_chain_phases": [
                f"{k.get("kill_chain_name")}:{k.get("phase_name")}"
                for k in ind.get("killChainPhases", [])
            ],
        }
        enriched.append(entry)
    return enriched


def enrich_observable(client, observable_value):
    """Enrich a STIX Cyber Observable via OpenCTI."""
    if not client:
        return {"error": "pycti not available"}
    filters = {
        "mode": "and",
        "filters": [{"key": "value", "values": [observable_value]}],
        "filterGroups": [],
    }
    results = client.stix_cyber_observable.list(filters=filters)
    enriched = []
    for obs in results:
        entry = {
            "id": obs.get("id"),
            "entity_type": obs.get("entity_type"),
            "value": obs.get("observable_value"),
            "score": obs.get("x_opencti_score"),
            "labels": [l.get("value") for l in obs.get("objectLabel", [])],
            "created_by": obs.get("createdBy", {}).get("name", "Unknown") if obs.get("createdBy") else "Unknown",
        }
        enriched.append(entry)
    return enriched


def get_relationships(client, entity_id, relationship_type=None):
    """Get STIX relationships for an entity."""
    if not client:
        return []
    filters = {
        "mode": "and",
        "filters": [{"key": "fromId", "values": [entity_id]}],
        "filterGroups": [],
    }
    if relationship_type:
        filters["filters"].append({"key": "relationship_type", "values": [relationship_type]})
    rels = client.stix_core_relationship.list(filters=filters)
    return [
        {
            "type": r.get("relationship_type"),
            "target": r.get("to", {}).get("name", r.get("to", {}).get("observable_value", "?")),
            "confidence": r.get("confidence"),
            "start_time": r.get("start_time"),
        }
        for r in rels
    ]


def classify_ioc(value):
    """Classify IOC type from value string."""
    if re.match(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}$", value):
        return "IPv4-Addr"
    if re.match(r"^[a-fA-F0-9]{32}$", value):
        return "MD5"
    if re.match(r"^[a-fA-F0-9]{40}$", value):
        return "SHA-1"
    if re.match(r"^[a-fA-F0-9]{64}$", value):
        return "SHA-256"
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
        return "Domain-Name"
    if value.startswith("http://") or value.startswith("https://"):
        return "Url"
    return "Unknown"


def build_enrichment_report(client, iocs):
    """Build enrichment report for a list of IOCs."""
    report = {"timestamp": datetime.datetime.utcnow().isoformat() + "Z", "iocs": []}
    for ioc in iocs:
        ioc_type = classify_ioc(ioc)
        entry = {"value": ioc, "type": ioc_type, "indicators": [], "observables": [], "relationships": []}
        if client:
            entry["indicators"] = enrich_indicator(client, ioc)
            entry["observables"] = enrich_observable(client, ioc)
            for ind in entry["indicators"]:
                if ind.get("id"):
                    entry["relationships"].extend(get_relationships(client, ind["id"]))
        report["iocs"].append(entry)
    return report


if __name__ == "__main__":
    print("=" * 60)
    print("IOC Enrichment Pipeline with OpenCTI")
    print("pycti GraphQL client for indicator and observable enrichment")
    print("=" * 60)
    print(f"  pycti available: {HAS_PYCTI}")

    demo_iocs = ["198.51.100.42", "evil-domain.example.com", "d41d8cd98f00b204e9800998ecf8427e"]
    if len(sys.argv) > 1:
        demo_iocs = sys.argv[1:]

    client = init_client() if HAS_PYCTI else None
    if not client:
        print("
[DEMO] No OpenCTI connection. Showing classification only.")

    report = build_enrichment_report(client, demo_iocs)
    for ioc in report["iocs"]:
        print(f"
  IOC: {ioc["value"]}  Type: {ioc["type"]}")
        print(f"    Indicators found: {len(ioc["indicators"])}")
        print(f"    Observables found: {len(ioc["observables"])}")
        print(f"    Relationships: {len(ioc["relationships"])}")

    print(f"
{json.dumps({"total_iocs": len(report["iocs"])}, indent=2)}")
