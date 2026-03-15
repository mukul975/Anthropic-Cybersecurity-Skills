#!/usr/bin/env python3
"""Adversary Infrastructure Tracking Agent - Tracks threat actor infrastructure using passive DNS and certificate transparency."""

import json
import logging
import argparse
from datetime import datetime
from collections import defaultdict

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def query_crtsh(domain):
    """Query crt.sh certificate transparency for domain certificates."""
    resp = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=30)
    resp.raise_for_status()
    certs = resp.json()
    logger.info("crt.sh: %d certificates for %s", len(certs), domain)
    return certs


def query_urlhaus(ioc, ioc_type="host"):
    """Query URLhaus for malicious URL hosting information."""
    resp = requests.post("https://urlhaus-api.abuse.ch/v1/host/", data={ioc_type: ioc}, timeout=15)
    resp.raise_for_status()
    return resp.json()


def query_threatfox(ioc):
    """Query ThreatFox for IOC intelligence."""
    resp = requests.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_ioc", "search_term": ioc}, timeout=15)
    resp.raise_for_status()
    return resp.json()


def pivot_on_certificate(cert_data):
    """Pivot on certificate data to find related infrastructure."""
    related_domains = set()
    issuers = defaultdict(list)
    for cert in cert_data:
        name_value = cert.get("name_value", "")
        for domain in name_value.split("\n"):
            domain = domain.strip().lstrip("*.")
            if domain:
                related_domains.add(domain)
        issuer = cert.get("issuer_name", "")
        issuers[issuer].append(cert.get("serial_number", ""))
    return {"related_domains": sorted(related_domains), "issuers": {k: len(v) for k, v in issuers.items()}}


def build_infrastructure_map(seed_iocs, ioc_types):
    """Build infrastructure map from seed IOCs."""
    infra_map = {"nodes": [], "edges": [], "iocs": {}}
    for ioc, itype in zip(seed_iocs, ioc_types):
        node = {"ioc": ioc, "type": itype, "sources": []}
        if itype == "domain":
            try:
                certs = query_crtsh(ioc)
                pivot = pivot_on_certificate(certs)
                node["ct_domains"] = pivot["related_domains"][:20]
                node["sources"].append("crt.sh")
                for related in pivot["related_domains"][:5]:
                    infra_map["edges"].append({"from": ioc, "to": related, "relation": "shared_certificate"})
            except requests.RequestException as e:
                node["ct_error"] = str(e)
        try:
            urlhaus = query_urlhaus(ioc, "host" if itype == "domain" else "host")
            if urlhaus.get("query_status") == "ok" and urlhaus.get("urls"):
                node["urlhaus_urls"] = len(urlhaus.get("urls", []))
                node["sources"].append("urlhaus")
        except requests.RequestException:
            pass
        try:
            tf = query_threatfox(ioc)
            if tf.get("query_status") == "ok" and tf.get("data"):
                node["threatfox_hits"] = len(tf["data"])
                node["sources"].append("threatfox")
        except requests.RequestException:
            pass
        infra_map["nodes"].append(node)
        infra_map["iocs"][ioc] = node
    return infra_map


def generate_report(infra_map, seed_iocs):
    """Generate infrastructure tracking report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "seed_iocs": seed_iocs,
        "nodes_discovered": len(infra_map["nodes"]),
        "edges_discovered": len(infra_map["edges"]),
        "infrastructure_map": infra_map,
    }
    print(f"INFRA REPORT: {len(infra_map['nodes'])} nodes, {len(infra_map['edges'])} edges")
    return report


def main():
    parser = argparse.ArgumentParser(description="Adversary Infrastructure Tracking Agent")
    parser.add_argument("--iocs", nargs="+", required=True, help="Seed IOCs (domains/IPs)")
    parser.add_argument("--types", nargs="+", required=True, help="IOC types (domain/ip)")
    parser.add_argument("--output", default="infra_tracking_report.json")
    args = parser.parse_args()

    infra_map = build_infrastructure_map(args.iocs, args.types)
    report = generate_report(infra_map, args.iocs)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
