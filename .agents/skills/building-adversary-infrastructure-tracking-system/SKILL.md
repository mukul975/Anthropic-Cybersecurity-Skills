---
name: building-adversary-infrastructure-tracking-system
description: Build an automated system to track adversary infrastructure using passive DNS, certificate transparency, WHOIS data, and IP enrichment to map and monitor threat actor command-and-control networks.
domain: cybersecurity
subdomain: threat-intelligence
tags: [infrastructure-tracking, passive-dns, c2, whois, threat-actor, pivoting, threat-intelligence, domain-analysis]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Building Adversary Infrastructure Tracking System

## Overview

Adversary infrastructure tracking uses passive DNS records, certificate transparency logs, WHOIS registration data, and IP enrichment to discover, map, and monitor threat actor command-and-control (C2) networks. Attackers frequently reuse hosting providers, registrars, SSL certificates, and naming patterns across campaigns, enabling analysts to pivot from known indicators to discover new infrastructure. This skill covers building an automated tracking system that identifies infrastructure relationships, detects newly registered domains matching adversary patterns, and maintains a continuously updated map of threat actor networks.

## Prerequisites

- Python 3.9+ with `requests`, `dnspython`, `python-whois`, `shodan`, `networkx` libraries
- API keys: SecurityTrails, PassiveTotal/RiskIQ, Shodan, VirusTotal
- Access to passive DNS data sources
- Understanding of DNS infrastructure, hosting, and domain registration
- Graph database (Neo4j) or NetworkX for relationship visualization

## Key Concepts

### Passive DNS

Passive DNS captures historical DNS resolution data, recording which domains resolved to which IPs and when. Unlike active DNS queries, passive DNS preserves historical relationships even after records change, enabling analysts to track infrastructure changes, identify shared hosting patterns, and discover related domains that resolved to the same IP addresses over time.

### Infrastructure Pivoting

Pivoting identifies related infrastructure by following connections: IP pivot (find all domains on an IP), domain pivot (find all IPs a domain resolved to), WHOIS pivot (find domains with same registrant), certificate pivot (find hosts sharing SSL certificates), and NS/MX pivot (find domains using same name servers or mail servers).

### Adversary Infrastructure Patterns

Threat actors exhibit patterns: preferred registrars (Namecheap, REG.RU, Tucows), preferred hosting (bulletproof hosting providers, cloud services), domain generation algorithms (DGA), consistent naming patterns, and certificate reuse across campaigns.

## Practical Steps

### Step 1: Passive DNS Infrastructure Discovery

```python
import requests
import json
from collections import defaultdict
from datetime import datetime

class InfrastructureTracker:
    def __init__(self, securitytrails_key=None, vt_key=None, shodan_key=None):
        self.st_key = securitytrails_key
        self.vt_key = vt_key
        self.shodan_key = shodan_key
        self.infrastructure_graph = defaultdict(lambda: {"nodes": set(), "edges": []})

    def passive_dns_lookup(self, domain):
        """Query passive DNS for domain resolution history."""
        headers = {"apikey": self.st_key}
        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            records = resp.json().get("records", [])
            history = []
            for record in records:
                for value in record.get("values", []):
                    history.append({
                        "domain": domain,
                        "ip": value.get("ip", ""),
                        "first_seen": record.get("first_seen", ""),
                        "last_seen": record.get("last_seen", ""),
                        "type": record.get("type", "a"),
                    })
            print(f"[+] Passive DNS for {domain}: {len(history)} records")
            return history
        return []

    def reverse_ip_lookup(self, ip_address):
        """Find all domains hosted on an IP address."""
        headers = {"apikey": self.st_key}
        url = f"https://api.securitytrails.com/v1/ips/nearby/{ip_address}"
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            blocks = resp.json().get("blocks", [])
            domains = []
            for block in blocks:
                for site in block.get("sites", []):
                    domains.append(site)
            print(f"[+] Reverse IP for {ip_address}: {len(domains)} domains")
            return domains
        return []

    def whois_lookup(self, domain):
        """Get WHOIS registration data for pivoting."""
        headers = {"apikey": self.st_key}
        url = f"https://api.securitytrails.com/v1/domain/{domain}/whois"
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            whois_data = {
                "domain": domain,
                "registrar": data.get("registrar", ""),
                "registrant_org": data.get("registrant_org", ""),
                "registrant_email": data.get("registrant_email", ""),
                "name_servers": data.get("nameServers", []),
                "created_date": data.get("createdDate", ""),
                "updated_date": data.get("updatedDate", ""),
                "expires_date": data.get("expiresDate", ""),
            }
            return whois_data
        return {}

    def pivot_from_seed(self, seed_indicator, indicator_type="domain", depth=2):
        """Recursively pivot from a seed indicator to discover infrastructure."""
        discovered = {"domains": set(), "ips": set(), "relationships": []}

        if indicator_type == "domain":
            discovered["domains"].add(seed_indicator)
            # Get IPs for domain
            pdns = self.passive_dns_lookup(seed_indicator)
            for record in pdns:
                ip = record["ip"]
                discovered["ips"].add(ip)
                discovered["relationships"].append({
                    "source": seed_indicator, "target": ip,
                    "type": "resolves_to",
                    "first_seen": record["first_seen"],
                    "last_seen": record["last_seen"],
                })

                if depth > 1:
                    # Reverse lookup on discovered IPs
                    reverse_domains = self.reverse_ip_lookup(ip)
                    for rd in reverse_domains[:20]:
                        discovered["domains"].add(rd)
                        discovered["relationships"].append({
                            "source": rd, "target": ip,
                            "type": "hosted_on",
                        })

        elif indicator_type == "ip":
            discovered["ips"].add(seed_indicator)
            domains = self.reverse_ip_lookup(seed_indicator)
            for domain in domains[:20]:
                discovered["domains"].add(domain)
                discovered["relationships"].append({
                    "source": domain, "target": seed_indicator,
                    "type": "hosted_on",
                })

        print(f"[+] Pivot from {seed_indicator}: "
              f"{len(discovered['domains'])} domains, "
              f"{len(discovered['ips'])} IPs, "
              f"{len(discovered['relationships'])} relationships")
        return discovered

tracker = InfrastructureTracker(
    securitytrails_key="YOUR_ST_KEY",
    vt_key="YOUR_VT_KEY",
)
```

### Step 2: Build Infrastructure Graph

```python
import networkx as nx

class InfrastructureGraph:
    def __init__(self):
        self.graph = nx.Graph()

    def add_discovery(self, discovery_data):
        """Add discovered infrastructure to graph."""
        for domain in discovery_data["domains"]:
            self.graph.add_node(domain, type="domain")
        for ip in discovery_data["ips"]:
            self.graph.add_node(ip, type="ip")
        for rel in discovery_data["relationships"]:
            self.graph.add_edge(
                rel["source"], rel["target"],
                relationship=rel["type"],
                first_seen=rel.get("first_seen", ""),
                last_seen=rel.get("last_seen", ""),
            )

    def find_clusters(self):
        """Identify infrastructure clusters."""
        components = list(nx.connected_components(self.graph))
        clusters = []
        for component in components:
            domains = [n for n in component if self.graph.nodes[n].get("type") == "domain"]
            ips = [n for n in component if self.graph.nodes[n].get("type") == "ip"]
            clusters.append({
                "size": len(component),
                "domains": sorted(domains),
                "ips": sorted(ips),
                "domain_count": len(domains),
                "ip_count": len(ips),
            })
        clusters.sort(key=lambda x: x["size"], reverse=True)
        print(f"[+] Infrastructure clusters: {len(clusters)}")
        return clusters

    def find_hub_nodes(self, top_n=10):
        """Find high-centrality nodes (shared infrastructure)."""
        centrality = nx.degree_centrality(self.graph)
        top_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:top_n]
        hubs = []
        for node, score in top_nodes:
            hubs.append({
                "node": node,
                "type": self.graph.nodes[node].get("type", "unknown"),
                "centrality": round(score, 4),
                "connections": self.graph.degree(node),
            })
        return hubs

    def export_graph(self, output_file="infrastructure_graph.json"):
        data = nx.node_link_data(self.graph)
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Graph exported: {self.graph.number_of_nodes()} nodes, "
              f"{self.graph.number_of_edges()} edges")

infra_graph = InfrastructureGraph()
discovery = tracker.pivot_from_seed("evil-domain.com", depth=2)
infra_graph.add_discovery(discovery)
clusters = infra_graph.find_clusters()
hubs = infra_graph.find_hub_nodes()
infra_graph.export_graph()
```

### Step 3: Monitor for New Infrastructure

```python
import time

class InfrastructureMonitor:
    def __init__(self, tracker, known_indicators):
        self.tracker = tracker
        self.known = set(known_indicators)
        self.alerts = []

    def check_new_registrations(self, patterns):
        """Check for newly registered domains matching adversary patterns."""
        import re
        new_domains = []
        for pattern in patterns:
            # Query SecurityTrails for new domains matching pattern
            headers = {"apikey": self.tracker.st_key}
            url = "https://api.securitytrails.com/v1/domains/list"
            params = {"include_ips": "true", "page": 1}
            body = {"filter": {"keyword": pattern}}
            resp = requests.post(url, headers=headers, json=body, timeout=30)
            if resp.status_code == 200:
                records = resp.json().get("records", [])
                for record in records:
                    domain = record.get("hostname", "")
                    if domain not in self.known:
                        new_domains.append({
                            "domain": domain,
                            "pattern_matched": pattern,
                            "first_seen": datetime.now().isoformat(),
                        })
                        self.known.add(domain)

        if new_domains:
            print(f"[ALERT] {len(new_domains)} new domains matching patterns")
            self.alerts.extend(new_domains)
        return new_domains

    def generate_infrastructure_report(self, clusters, hubs):
        report = f"""# Adversary Infrastructure Tracking Report
Generated: {datetime.now().isoformat()}

## Summary
- Infrastructure clusters identified: {len(clusters)}
- Total domains tracked: {sum(c['domain_count'] for c in clusters)}
- Total IPs tracked: {sum(c['ip_count'] for c in clusters)}
- New domains detected: {len(self.alerts)}

## Top Infrastructure Hubs
| Node | Type | Connections | Centrality |
|------|------|-------------|------------|
"""
        for hub in hubs[:10]:
            report += (f"| {hub['node']} | {hub['type']} "
                       f"| {hub['connections']} | {hub['centrality']} |\n")

        report += "\n## Infrastructure Clusters\n"
        for i, cluster in enumerate(clusters[:5], 1):
            report += f"\n### Cluster {i} ({cluster['size']} nodes)\n"
            report += f"- Domains: {', '.join(cluster['domains'][:5])}\n"
            report += f"- IPs: {', '.join(cluster['ips'][:5])}\n"

        with open("infrastructure_report.md", "w") as f:
            f.write(report)
        print("[+] Infrastructure report saved")

monitor = InfrastructureMonitor(tracker, known_indicators=set())
```

## Validation Criteria

- Passive DNS queries return historical resolution data
- Reverse IP lookups discover co-hosted domains
- Infrastructure pivoting expands from seed indicators
- Graph analysis identifies clusters and hub nodes
- New infrastructure detected through pattern monitoring
- Reports generated with actionable recommendations

## References

- [Juniper: Threat Hunting with Passive DNS](https://blogs.juniper.net/en-us/threat-research/threat-hunting-with-passive-dns-discovering-the-attacker-infrastructure)
- [Censys: Advanced Persistent Infrastructure Tracking](https://censys.com/blog/advanced-persistent-infrastructure-tracking)
- [Embee Research: Malware Infrastructure with DNS Pivoting](https://www.embeeresearch.io/infrastructure-analysis-with-dns-pivoting/)
- [Validin: Passive DNS Threat Hunting](https://www.validin.com/blog/announcing_validin_threat_hunting_platform/)
- [SecurityTrails API](https://securitytrails.com/corp/api)
- [Hunt.io: Uncovering Malicious Infrastructure](https://hunt.io/blog/practical-guide-unconvering-malicious-infrastructure)
