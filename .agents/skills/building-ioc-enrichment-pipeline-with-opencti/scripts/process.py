#!/usr/bin/env python3
"""
OpenCTI IOC Enrichment Pipeline Script

Automates IOC enrichment using OpenCTI's pycti library and external APIs:
- Queries VirusTotal, Shodan, AbuseIPDB, GreyNoise for IOC context
- Creates STIX 2.1 bundles with enrichment results
- Updates OpenCTI observables with enrichment data
- Generates enrichment reports with confidence scoring

Requirements:
    pip install pycti stix2 requests

Usage:
    python process.py --url http://localhost:8080 --token YOUR_TOKEN --enrich-ip 1.2.3.4
    python process.py --url http://localhost:8080 --token YOUR_TOKEN --enrich-domain evil.com
    python process.py --url http://localhost:8080 --token YOUR_TOKEN --bulk-enrich --days 1
"""

import argparse
import json
import sys
import os
from datetime import datetime, timedelta
from typing import Optional

try:
    from pycti import OpenCTIApiClient
except ImportError:
    print("ERROR: pycti not installed. Run: pip install pycti")
    sys.exit(1)

import requests


class OpenCTIEnrichmentPipeline:
    """Automated IOC enrichment pipeline for OpenCTI."""

    def __init__(self, url: str, token: str):
        self.client = OpenCTIApiClient(url, token)
        self.vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.shodan_key = os.environ.get("SHODAN_API_KEY", "")
        self.abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY", "")
        self.greynoise_key = os.environ.get("GREYNOISE_API_KEY", "")
        self.stats = {
            "enriched": 0,
            "failed": 0,
            "skipped": 0,
            "vt_queries": 0,
            "shodan_queries": 0,
            "abuseipdb_queries": 0,
            "greynoise_queries": 0,
        }

    def enrich_ip(self, ip_address: str) -> dict:
        """Enrich an IP address with multiple external sources."""
        results = {"ip": ip_address, "sources": {}, "confidence_score": 0}

        # VirusTotal enrichment
        if self.vt_key:
            vt_data = self._query_virustotal_ip(ip_address)
            if vt_data:
                results["sources"]["virustotal"] = vt_data
                malicious = vt_data.get("malicious_count", 0)
                total = vt_data.get("total_engines", 0)
                if total > 0:
                    results["confidence_score"] += int((malicious / total) * 30)

        # Shodan enrichment
        if self.shodan_key:
            shodan_data = self._query_shodan(ip_address)
            if shodan_data:
                results["sources"]["shodan"] = shodan_data
                vulns = len(shodan_data.get("vulns", []))
                results["confidence_score"] += min(vulns * 5, 20)

        # AbuseIPDB enrichment
        if self.abuseipdb_key:
            abuse_data = self._query_abuseipdb(ip_address)
            if abuse_data:
                results["sources"]["abuseipdb"] = abuse_data
                abuse_score = abuse_data.get("abuse_confidence_score", 0)
                results["confidence_score"] += int(abuse_score * 0.3)

        # GreyNoise enrichment
        if self.greynoise_key:
            gn_data = self._query_greynoise(ip_address)
            if gn_data:
                results["sources"]["greynoise"] = gn_data
                classification = gn_data.get("classification", "unknown")
                if classification == "malicious":
                    results["confidence_score"] += 20
                elif classification == "benign":
                    results["confidence_score"] = max(0, results["confidence_score"] - 20)

        results["confidence_score"] = min(100, results["confidence_score"])
        self.stats["enriched"] += 1
        return results

    def enrich_domain(self, domain: str) -> dict:
        """Enrich a domain with VirusTotal context."""
        results = {"domain": domain, "sources": {}, "confidence_score": 0}

        if self.vt_key:
            vt_data = self._query_virustotal_domain(domain)
            if vt_data:
                results["sources"]["virustotal"] = vt_data
                malicious = vt_data.get("malicious_count", 0)
                total = vt_data.get("total_engines", 0)
                if total > 0:
                    results["confidence_score"] += int((malicious / total) * 50)

        results["confidence_score"] = min(100, results["confidence_score"])
        self.stats["enriched"] += 1
        return results

    def enrich_hash(self, file_hash: str) -> dict:
        """Enrich a file hash with VirusTotal context."""
        results = {"hash": file_hash, "sources": {}, "confidence_score": 0}

        if self.vt_key:
            vt_data = self._query_virustotal_hash(file_hash)
            if vt_data:
                results["sources"]["virustotal"] = vt_data
                malicious = vt_data.get("malicious_count", 0)
                total = vt_data.get("total_engines", 0)
                if total > 0:
                    results["confidence_score"] += int((malicious / total) * 80)

        results["confidence_score"] = min(100, results["confidence_score"])
        self.stats["enriched"] += 1
        return results

    def _query_virustotal_ip(self, ip: str) -> Optional[dict]:
        """Query VirusTotal for IP address information."""
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.vt_key},
                timeout=30,
            )
            self.stats["vt_queries"] += 1
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious_count": stats.get("malicious", 0),
                    "suspicious_count": stats.get("suspicious", 0),
                    "harmless_count": stats.get("harmless", 0),
                    "total_engines": sum(stats.values()) if stats else 0,
                    "as_owner": data.get("as_owner", ""),
                    "country": data.get("country", ""),
                    "reputation": data.get("reputation", 0),
                }
        except Exception as e:
            print(f"[-] VirusTotal query failed for {ip}: {e}")
        return None

    def _query_virustotal_domain(self, domain: str) -> Optional[dict]:
        """Query VirusTotal for domain information."""
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": self.vt_key},
                timeout=30,
            )
            self.stats["vt_queries"] += 1
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious_count": stats.get("malicious", 0),
                    "suspicious_count": stats.get("suspicious", 0),
                    "total_engines": sum(stats.values()) if stats else 0,
                    "registrar": data.get("registrar", ""),
                    "creation_date": data.get("creation_date", ""),
                    "reputation": data.get("reputation", 0),
                    "categories": data.get("categories", {}),
                }
        except Exception as e:
            print(f"[-] VirusTotal query failed for {domain}: {e}")
        return None

    def _query_virustotal_hash(self, file_hash: str) -> Optional[dict]:
        """Query VirusTotal for file hash information."""
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": self.vt_key},
                timeout=30,
            )
            self.stats["vt_queries"] += 1
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious_count": stats.get("malicious", 0),
                    "suspicious_count": stats.get("suspicious", 0),
                    "total_engines": sum(stats.values()) if stats else 0,
                    "type_description": data.get("type_description", ""),
                    "size": data.get("size", 0),
                    "names": data.get("names", [])[:5],
                    "tags": data.get("tags", [])[:10],
                }
        except Exception as e:
            print(f"[-] VirusTotal query failed for {file_hash}: {e}")
        return None

    def _query_shodan(self, ip: str) -> Optional[dict]:
        """Query Shodan for IP host information."""
        try:
            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}",
                timeout=30,
            )
            self.stats["shodan_queries"] += 1
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", []),
                    "os": data.get("os"),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "country": data.get("country_name", ""),
                    "city": data.get("city", ""),
                    "hostnames": data.get("hostnames", []),
                    "tags": data.get("tags", []),
                }
        except Exception as e:
            print(f"[-] Shodan query failed for {ip}: {e}")
        return None

    def _query_abuseipdb(self, ip: str) -> Optional[dict]:
        """Query AbuseIPDB for IP reputation."""
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": self.abuseipdb_key,
                    "Accept": "application/json",
                },
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                timeout=30,
            )
            self.stats["abuseipdb_queries"] += 1
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "distinct_users": data.get("numDistinctUsers", 0),
                    "country": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "usage_type": data.get("usageType", ""),
                    "is_tor": data.get("isTor", False),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "last_reported": data.get("lastReportedAt", ""),
                }
        except Exception as e:
            print(f"[-] AbuseIPDB query failed for {ip}: {e}")
        return None

    def _query_greynoise(self, ip: str) -> Optional[dict]:
        """Query GreyNoise for IP classification."""
        try:
            resp = requests.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers={"key": self.greynoise_key},
                timeout=30,
            )
            self.stats["greynoise_queries"] += 1
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "classification": data.get("classification", "unknown"),
                    "noise": data.get("noise", False),
                    "riot": data.get("riot", False),
                    "name": data.get("name", ""),
                    "last_seen": data.get("last_seen", ""),
                    "message": data.get("message", ""),
                }
        except Exception as e:
            print(f"[-] GreyNoise query failed for {ip}: {e}")
        return None

    def update_opencti_observable(self, observable_value: str,
                                  enrichment: dict) -> bool:
        """Update OpenCTI observable with enrichment results."""
        try:
            # Search for existing observable
            observables = self.client.stix_cyber_observable.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": "value", "values": [observable_value]}],
                    "filterGroups": [],
                }
            )

            if not observables:
                print(f"[-] Observable {observable_value} not found in OpenCTI")
                return False

            obs_id = observables[0]["id"]
            score = enrichment.get("confidence_score", 0)

            # Update confidence score
            self.client.stix_cyber_observable.update_field(
                id=obs_id,
                input={"key": "x_opencti_score", "value": str(score)},
            )

            # Add enrichment note
            note_content = json.dumps(enrichment["sources"], indent=2)
            self.client.note.create(
                content=f"## Automated Enrichment Results\n```json\n{note_content}\n```",
                abstract=f"Enrichment Score: {score}/100",
                objects=[obs_id],
            )

            # Add labels based on score
            if score >= 80:
                self.client.stix_cyber_observable.add_label(
                    id=obs_id, label_name="enrichment:critical"
                )
            elif score >= 50:
                self.client.stix_cyber_observable.add_label(
                    id=obs_id, label_name="enrichment:high"
                )

            print(f"[+] Updated {observable_value} in OpenCTI (score: {score})")
            return True

        except Exception as e:
            print(f"[-] Failed to update OpenCTI: {e}")
            self.stats["failed"] += 1
            return False

    def bulk_enrich_recent(self, days: int = 1, max_items: int = 100):
        """Bulk enrich recently created observables."""
        date_from = (datetime.now() - timedelta(days=days)).strftime(
            "%Y-%m-%dT00:00:00.000Z"
        )

        observables = self.client.stix_cyber_observable.list(
            first=max_items,
            filters={
                "mode": "and",
                "filters": [
                    {"key": "created_at", "values": [date_from], "operator": "gt"}
                ],
                "filterGroups": [],
            },
        )

        print(f"[+] Found {len(observables)} observables to enrich")

        for obs in observables:
            entity_type = obs.get("entity_type", "")
            value = obs.get("observable_value", "")

            if not value:
                continue

            if entity_type == "IPv4-Addr":
                enrichment = self.enrich_ip(value)
            elif entity_type == "Domain-Name":
                enrichment = self.enrich_domain(value)
            elif entity_type in ("StixFile", "Artifact"):
                hashes = obs.get("hashes", {})
                sha256 = hashes.get("SHA-256", "")
                if sha256:
                    enrichment = self.enrich_hash(sha256)
                else:
                    continue
            else:
                self.stats["skipped"] += 1
                continue

            self.update_opencti_observable(value, enrichment)

    def print_stats(self):
        """Print enrichment statistics."""
        print("\n=== Enrichment Pipeline Statistics ===")
        for key, value in self.stats.items():
            print(f"  {key.replace('_', ' ').title()}: {value}")
        print("=====================================\n")


def main():
    parser = argparse.ArgumentParser(
        description="OpenCTI IOC Enrichment Pipeline"
    )
    parser.add_argument("--url", required=True, help="OpenCTI instance URL")
    parser.add_argument("--token", required=True, help="OpenCTI API token")
    parser.add_argument("--enrich-ip", help="Enrich a single IP address")
    parser.add_argument("--enrich-domain", help="Enrich a single domain")
    parser.add_argument("--enrich-hash", help="Enrich a single file hash")
    parser.add_argument(
        "--bulk-enrich", action="store_true", help="Bulk enrich recent observables"
    )
    parser.add_argument("--days", type=int, default=1, help="Lookback days for bulk")
    parser.add_argument("--max-items", type=int, default=100, help="Max items for bulk")
    parser.add_argument(
        "--update-opencti", action="store_true",
        help="Update results back to OpenCTI",
    )
    parser.add_argument("--output", help="Output file for enrichment results")

    args = parser.parse_args()
    pipeline = OpenCTIEnrichmentPipeline(args.url, args.token)

    results = None

    if args.enrich_ip:
        results = pipeline.enrich_ip(args.enrich_ip)
        if args.update_opencti:
            pipeline.update_opencti_observable(args.enrich_ip, results)

    elif args.enrich_domain:
        results = pipeline.enrich_domain(args.enrich_domain)
        if args.update_opencti:
            pipeline.update_opencti_observable(args.enrich_domain, results)

    elif args.enrich_hash:
        results = pipeline.enrich_hash(args.enrich_hash)
        if args.update_opencti:
            pipeline.update_opencti_observable(args.enrich_hash, results)

    elif args.bulk_enrich:
        pipeline.bulk_enrich_recent(days=args.days, max_items=args.max_items)

    if results:
        print(json.dumps(results, indent=2, default=str))
        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2, default=str)
            print(f"[+] Results saved to {args.output}")

    pipeline.print_stats()


if __name__ == "__main__":
    main()
