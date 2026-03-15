#!/usr/bin/env python3
"""
Splunk Threat Intelligence Enrichment Pipeline

Manages threat intelligence feed ingestion, normalization,
and enrichment workflows for Splunk Enterprise Security.
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import Optional


class ThreatIndicator:
    """Represents a single threat intelligence indicator."""

    def __init__(self, value: str, indicator_type: str, source: str,
                 threat_type: str, confidence: int, description: str = "",
                 severity: str = "medium", first_seen: Optional[str] = None,
                 last_seen: Optional[str] = None, tags: Optional[list] = None):
        self.value = value
        self.indicator_type = indicator_type
        self.source = source
        self.threat_type = threat_type
        self.confidence = min(100, max(0, confidence))
        self.description = description
        self.severity = severity
        self.first_seen = first_seen or datetime.utcnow().isoformat()
        self.last_seen = last_seen or datetime.utcnow().isoformat()
        self.tags = tags or []
        self.indicator_id = self._generate_id()

    def _generate_id(self) -> str:
        hash_input = f"{self.indicator_type}:{self.value}:{self.source}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]

    def is_expired(self, max_age_days: int = 90) -> bool:
        last = datetime.fromisoformat(self.last_seen.replace("Z", "+00:00").replace("+00:00", ""))
        return (datetime.utcnow() - last).days > max_age_days

    def to_kv_store_record(self) -> dict:
        type_field_map = {
            "ip": "ip",
            "domain": "domain",
            "file_hash": "file_hash",
            "url": "url",
            "email": "email",
        }
        key_field = type_field_map.get(self.indicator_type, "value")
        return {
            "_key": self.indicator_id,
            key_field: self.value,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "source": self.source,
            "description": self.description,
            "severity": self.severity,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "tags": ",".join(self.tags),
        }


class ThreatFeed:
    """Represents a threat intelligence feed source."""

    def __init__(self, name: str, feed_type: str, url: str,
                 polling_interval: int = 3600, api_key: str = ""):
        self.name = name
        self.feed_type = feed_type
        self.url = url
        self.polling_interval = polling_interval
        self.api_key = api_key
        self.indicators = []
        self.last_poll = None
        self.stats = {"total_ingested": 0, "duplicates_skipped": 0, "expired_removed": 0}

    def add_indicator(self, indicator: ThreatIndicator):
        self.indicators.append(indicator)
        self.stats["total_ingested"] += 1

    def get_active_indicators(self, max_age_days: int = 90) -> list:
        active = [i for i in self.indicators if not i.is_expired(max_age_days)]
        self.stats["expired_removed"] = len(self.indicators) - len(active)
        return active

    def generate_splunk_input_conf(self) -> str:
        return f"""[threatlist://{self.name}]
description = {self.name} threat feed
type = {self.feed_type}
url = {self.url}
polling_interval = {self.polling_interval}
disabled = false
"""


class EnrichmentPipeline:
    """Manages the complete TI enrichment pipeline for Splunk."""

    def __init__(self):
        self.feeds = []
        self.kv_store = {"ip_intel": [], "domain_intel": [], "file_intel": [], "url_intel": []}
        self.correlation_hits = []

    def add_feed(self, feed: ThreatFeed):
        self.feeds.append(feed)

    def ingest_all_feeds(self):
        for feed in self.feeds:
            active = feed.get_active_indicators()
            for indicator in active:
                collection = self._get_collection(indicator.indicator_type)
                if collection is not None:
                    self.kv_store[collection].append(indicator.to_kv_store_record())

    def _get_collection(self, indicator_type: str) -> Optional[str]:
        mapping = {
            "ip": "ip_intel",
            "domain": "domain_intel",
            "file_hash": "file_intel",
            "url": "url_intel",
        }
        return mapping.get(indicator_type)

    def simulate_correlation(self, events: list) -> list:
        """Simulate correlating events against TI indicators."""
        hits = []
        ip_iocs = {r["ip"]: r for r in self.kv_store.get("ip_intel", []) if "ip" in r}
        domain_iocs = {r["domain"]: r for r in self.kv_store.get("domain_intel", []) if "domain" in r}

        for event in events:
            dest_ip = event.get("dest_ip", "")
            domain = event.get("domain", "")

            if dest_ip in ip_iocs:
                ioc = ip_iocs[dest_ip]
                hits.append({
                    "event": event,
                    "match_type": "ip",
                    "matched_value": dest_ip,
                    "threat_type": ioc["threat_type"],
                    "confidence": ioc["confidence"],
                    "source": ioc["source"],
                    "severity": ioc["severity"],
                })

            if domain in domain_iocs:
                ioc = domain_iocs[domain]
                hits.append({
                    "event": event,
                    "match_type": "domain",
                    "matched_value": domain,
                    "threat_type": ioc["threat_type"],
                    "confidence": ioc["confidence"],
                    "source": ioc["source"],
                    "severity": ioc["severity"],
                })

        self.correlation_hits = hits
        return hits

    def get_pipeline_stats(self) -> dict:
        return {
            "total_feeds": len(self.feeds),
            "kv_store_sizes": {k: len(v) for k, v in self.kv_store.items()},
            "total_indicators": sum(len(v) for v in self.kv_store.values()),
            "correlation_hits": len(self.correlation_hits),
            "feed_stats": [
                {"name": f.name, "indicators": len(f.indicators), "stats": f.stats}
                for f in self.feeds
            ],
        }

    def generate_spl_correlation(self, indicator_type: str) -> str:
        templates = {
            "ip": (
                '| tstats summariesonly=true count from datamodel=Network_Traffic '
                'where All_Traffic.action=allowed by All_Traffic.dest_ip, All_Traffic.src_ip, _time span=5m\n'
                '| rename "All_Traffic.*" as *\n'
                '| lookup ip_threat_intel_lookup ip as dest_ip '
                'OUTPUT threat_type, confidence, source as ti_source, severity as ti_severity\n'
                '| where isnotnull(threat_type) AND confidence > 70\n'
                '| eval description="TI Hit: ".dest_ip." (".threat_type.") from ".ti_source'
            ),
            "domain": (
                'index=dns sourcetype=stream:dns\n'
                '| lookup domain_threat_intel_lookup domain as query '
                'OUTPUT threat_type, confidence, source as ti_source\n'
                '| where isnotnull(threat_type) AND confidence > 70\n'
                '| stats count dc(src_ip) as unique_sources by query, threat_type, ti_source\n'
                '| eval description="DNS to malicious domain ".query." from ".unique_sources." sources"'
            ),
            "file_hash": (
                'index=endpoint sourcetype=sysmon EventCode=1\n'
                '| lookup file_hash_intel_lookup file_hash as Hashes '
                'OUTPUT malware_family, confidence, source as ti_source\n'
                '| where isnotnull(malware_family)\n'
                '| eval description="Known malware ".malware_family." on ".Computer'
            ),
        }
        return templates.get(indicator_type, "# No template for this indicator type")


if __name__ == "__main__":
    pipeline = EnrichmentPipeline()

    # Create sample feeds
    otx_feed = ThreatFeed("AlienVault_OTX", "api", "https://otx.alienvault.com/api/v1/pulses/subscribed")
    otx_feed.add_indicator(ThreatIndicator("203.0.113.50", "ip", "OTX", "C2", 85, "Known C2 server", "high"))
    otx_feed.add_indicator(ThreatIndicator("198.51.100.25", "ip", "OTX", "Scanner", 60, "Port scanner", "medium"))
    otx_feed.add_indicator(ThreatIndicator("evil-domain.com", "domain", "OTX", "Phishing", 92, "Phishing domain", "critical"))

    abuse_feed = ThreatFeed("AbuseIPDB", "csv", "https://api.abuseipdb.com/api/v2/blacklist")
    abuse_feed.add_indicator(ThreatIndicator("203.0.113.50", "ip", "AbuseIPDB", "C2", 90, "Reported C2", "high"))
    abuse_feed.add_indicator(ThreatIndicator("192.0.2.100", "ip", "AbuseIPDB", "Brute Force", 75, "SSH brute forcer", "medium"))

    pipeline.add_feed(otx_feed)
    pipeline.add_feed(abuse_feed)
    pipeline.ingest_all_feeds()

    # Simulate events
    events = [
        {"src_ip": "10.0.0.50", "dest_ip": "203.0.113.50", "dest_port": 443, "domain": ""},
        {"src_ip": "10.0.1.100", "dest_ip": "8.8.8.8", "dest_port": 53, "domain": "google.com"},
        {"src_ip": "10.0.2.75", "dest_ip": "93.184.216.34", "dest_port": 80, "domain": "evil-domain.com"},
        {"src_ip": "10.0.0.10", "dest_ip": "192.0.2.100", "dest_port": 22, "domain": ""},
    ]

    hits = pipeline.simulate_correlation(events)

    print("=" * 70)
    print("THREAT INTELLIGENCE ENRICHMENT PIPELINE")
    print("=" * 70)

    stats = pipeline.get_pipeline_stats()
    print(f"\nFeeds: {stats['total_feeds']}")
    print(f"Total Indicators: {stats['total_indicators']}")
    print(f"KV Store: {stats['kv_store_sizes']}")

    print(f"\nCorrelation Hits: {len(hits)}")
    for hit in hits:
        print(f"  [{hit['severity'].upper()}] {hit['match_type']}: {hit['matched_value']} "
              f"({hit['threat_type']}) - Confidence: {hit['confidence']}% - Source: {hit['source']}")

    print(f"\n{'=' * 70}")
    print("GENERATED SPL CORRELATION SEARCHES")
    print("=" * 70)
    for ioc_type in ["ip", "domain", "file_hash"]:
        print(f"\n--- {ioc_type.upper()} Correlation ---")
        print(pipeline.generate_spl_correlation(ioc_type))
