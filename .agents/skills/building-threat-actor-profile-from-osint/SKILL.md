---
name: building-threat-actor-profile-from-osint
description: Build comprehensive threat actor profiles using open-source intelligence (OSINT) techniques to document adversary motivations, capabilities, infrastructure, and TTPs for proactive defense.
domain: cybersecurity
subdomain: threat-intelligence
tags: [osint, threat-actor, profiling, maltego, spiderfoot, attribution, threat-intelligence, reconnaissance]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Building Threat Actor Profile from OSINT

## Overview

Threat actor profiling using OSINT systematically gathers and analyzes publicly available information to build comprehensive profiles of adversary groups. This skill covers collecting intelligence from public sources (security vendor reports, paste sites, dark web forums, social media, code repositories), correlating indicators across platforms, mapping adversary infrastructure using tools like Maltego and SpiderFoot, and producing structured threat actor dossiers that inform defensive strategies and attribution assessments.

## Prerequisites

- Python 3.9+ with `shodan`, `requests`, `beautifulsoup4`, `maltego-trx`, `stix2` libraries
- SpiderFoot (https://github.com/smicallef/spiderfoot) or SpiderFoot HX
- Maltego CE or Maltego XL for link analysis
- API keys: Shodan, VirusTotal, AlienVault OTX, PassiveTotal/RiskIQ
- MITRE ATT&CK knowledge for TTP mapping
- Understanding of STIX 2.1 Intrusion Set, Threat Actor, and Identity SDOs

## Key Concepts

### OSINT Sources for Threat Actor Profiling

Primary intelligence sources include vendor threat reports (Mandiant, CrowdStrike, Recorded Future, Talos), government advisories (CISA, NSA, FBI joint advisories), academic research papers, malware repositories (VirusTotal, MalwareBazaar, Malpedia), paste sites (Pastebin, GitHub Gists), code repositories, social media accounts, dark web forums, and certificate transparency logs.

### Structured Analytical Techniques

Profiling uses the Diamond Model (adversary, infrastructure, capability, victim), Analysis of Competing Hypotheses (ACH) for attribution confidence, and MITRE ATT&CK mapping for TTP documentation. Link analysis tools like Maltego visualize relationships between indicators, infrastructure, and actors.

### Profile Components

A complete threat actor profile includes: aliases and naming conventions across vendors, suspected origin and sponsorship, motivation (espionage, financial, hacktivism, disruption), targeted sectors and geographies, known campaigns and operations, TTPs mapped to ATT&CK, toolset and malware families, infrastructure patterns, and historical timeline.

## Practical Steps

### Step 1: Collect Intelligence from Multiple Sources

```python
import requests
import json
from datetime import datetime

class OSINTCollector:
    def __init__(self, vt_key=None, otx_key=None, shodan_key=None):
        self.vt_key = vt_key
        self.otx_key = otx_key
        self.shodan_key = shodan_key
        self.collected_data = {"sources": [], "indicators": [], "reports": []}

    def search_alienvault_otx(self, actor_name):
        """Search AlienVault OTX for threat actor pulses."""
        headers = {"X-OTX-API-KEY": self.otx_key}
        url = f"https://otx.alienvault.com/api/v1/search/pulses?q={actor_name}&limit=20"
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            pulses = data.get("results", [])
            for pulse in pulses:
                self.collected_data["reports"].append({
                    "source": "AlienVault OTX",
                    "title": pulse.get("name", ""),
                    "created": pulse.get("created", ""),
                    "description": pulse.get("description", "")[:500],
                    "tags": pulse.get("tags", []),
                    "indicators_count": len(pulse.get("indicators", [])),
                    "pulse_id": pulse.get("id", ""),
                })
                for ioc in pulse.get("indicators", []):
                    self.collected_data["indicators"].append({
                        "type": ioc.get("type", ""),
                        "value": ioc.get("indicator", ""),
                        "source": "OTX",
                        "pulse": pulse.get("name", ""),
                    })
            print(f"[+] OTX: Found {len(pulses)} pulses for '{actor_name}'")
        return self.collected_data

    def search_virustotal_collections(self, actor_name):
        """Search VirusTotal for threat actor collections."""
        headers = {"x-apikey": self.vt_key}
        url = "https://www.virustotal.com/api/v3/intelligence/search"
        params = {"query": f"tag:{actor_name.lower().replace(' ', '-')}"}
        resp = requests.get(url, headers=headers, params=params)
        if resp.status_code == 200:
            results = resp.json().get("data", [])
            print(f"[+] VT: Found {len(results)} samples tagged '{actor_name}'")
            return results
        return []

    def query_shodan_infrastructure(self, indicators):
        """Query Shodan for infrastructure details on IPs."""
        results = []
        for ip in indicators:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}"
            resp = requests.get(url)
            if resp.status_code == 200:
                data = resp.json()
                results.append({
                    "ip": ip,
                    "org": data.get("org", ""),
                    "asn": data.get("asn", ""),
                    "country": data.get("country_code", ""),
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "os": data.get("os", ""),
                    "last_update": data.get("last_update", ""),
                })
        print(f"[+] Shodan: Enriched {len(results)} IPs")
        return results

collector = OSINTCollector(
    vt_key="YOUR_VT_KEY",
    otx_key="YOUR_OTX_KEY",
    shodan_key="YOUR_SHODAN_KEY",
)
data = collector.search_alienvault_otx("APT29")
```

### Step 2: Build Structured Threat Actor Profile

```python
from stix2 import ThreatActor, IntrusionSet, Identity, Relationship, Bundle
from datetime import datetime

# Create STIX 2.1 Threat Actor profile
identity = Identity(
    name="Cybersecurity Analyst",
    identity_class="individual",
)

threat_actor = ThreatActor(
    name="APT29",
    description="APT29 (also known as Cozy Bear, Midnight Blizzard, NOBELIUM, The Dukes) "
                "is a Russian state-sponsored threat group attributed to Russia's Foreign "
                "Intelligence Service (SVR). Active since at least 2008, the group conducts "
                "cyber espionage targeting government, diplomatic, think tank, healthcare, "
                "and energy organizations primarily in NATO countries.",
    aliases=["Cozy Bear", "Midnight Blizzard", "NOBELIUM", "The Dukes",
             "Dark Halo", "UNC2452", "YTTRIUM", "Blue Kitsune", "Iron Ritual"],
    roles=["agent"],
    sophistication="strategic",
    resource_level="government",
    primary_motivation="organizational-gain",
    secondary_motivations=["ideology"],
    threat_actor_types=["nation-state"],
    goals=["Intelligence collection on foreign governments",
           "Long-term persistent access to high-value targets",
           "Supply chain compromise for broad access"],
    created_by_ref=identity.id,
)

intrusion_set = IntrusionSet(
    name="APT29",
    description="Intrusion set tracked as APT29, attributed to Russian SVR.",
    aliases=["Cozy Bear", "Midnight Blizzard"],
    first_seen="2008-01-01T00:00:00Z",
    goals=["espionage"],
    resource_level="government",
    primary_motivation="organizational-gain",
)

relationship = Relationship(
    relationship_type="attributed-to",
    source_ref=intrusion_set.id,
    target_ref=threat_actor.id,
)

bundle = Bundle(objects=[identity, threat_actor, intrusion_set, relationship])
with open("apt29_profile.json", "w") as f:
    f.write(bundle.serialize(pretty=True))
print("[+] STIX profile saved: apt29_profile.json")
```

### Step 3: Map TTPs to MITRE ATT&CK

```python
from attackcti import attack_client

lift = attack_client()
apt29_techs = lift.get_techniques_used_by_group("G0016")

profile_ttps = {
    "initial_access": [],
    "execution": [],
    "persistence": [],
    "defense_evasion": [],
    "credential_access": [],
    "lateral_movement": [],
    "collection": [],
    "c2": [],
    "exfiltration": [],
}

tactic_mapping = {
    "initial-access": "initial_access",
    "execution": "execution",
    "persistence": "persistence",
    "defense-evasion": "defense_evasion",
    "credential-access": "credential_access",
    "lateral-movement": "lateral_movement",
    "collection": "collection",
    "command-and-control": "c2",
    "exfiltration": "exfiltration",
}

for tech in apt29_techs:
    tech_id = ""
    for ref in tech.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            tech_id = ref.get("external_id", "")
            break
    for phase in tech.get("kill_chain_phases", []):
        tactic = phase.get("phase_name", "")
        key = tactic_mapping.get(tactic)
        if key:
            profile_ttps[key].append({
                "id": tech_id,
                "name": tech.get("name", ""),
                "description": tech.get("description", "")[:200],
            })

print("=== APT29 TTP Profile ===")
for tactic, techs in profile_ttps.items():
    if techs:
        print(f"\n{tactic.upper()} ({len(techs)} techniques):")
        for t in techs[:5]:
            print(f"  {t['id']}: {t['name']}")
```

### Step 4: Correlate Infrastructure with SpiderFoot

```python
import subprocess
import json

def run_spiderfoot_scan(target, scan_name="actor_recon"):
    """Run SpiderFoot scan against target domain or IP."""
    cmd = [
        "python3", "-m", "spiderfoot", "-s", target,
        "-m", "sfp_dns,sfp_whois,sfp_shodan,sfp_virustotal,sfp_certspotter",
        "-o", "json", "-q",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode == 0:
        findings = json.loads(result.stdout) if result.stdout else []
        print(f"[+] SpiderFoot: {len(findings)} findings for {target}")
        return findings
    return []

def correlate_infrastructure(indicators):
    """Find relationships between infrastructure indicators."""
    ip_to_domains = {}
    domain_to_ips = {}
    registrar_patterns = {}

    for indicator in indicators:
        ioc_type = indicator.get("type", "")
        value = indicator.get("value", "")

        if ioc_type == "IP_ADDRESS":
            if value not in ip_to_domains:
                ip_to_domains[value] = set()
        elif ioc_type == "INTERNET_NAME":
            if value not in domain_to_ips:
                domain_to_ips[value] = set()

    # Identify shared hosting, registration patterns
    shared_ips = {ip: domains for ip, domains in ip_to_domains.items() if len(domains) > 1}
    print(f"[+] Shared infrastructure IPs: {len(shared_ips)}")
    return {"shared_ips": shared_ips, "registrar_patterns": registrar_patterns}
```

### Step 5: Generate Threat Actor Dossier

```python
def generate_dossier(actor_name, profile_data, ttp_data, infrastructure_data):
    dossier = f"""# Threat Actor Dossier: {actor_name}
## Generated: {datetime.now().isoformat()}

## Executive Summary
{profile_data.get('description', '')}

## Attribution
- **Suspected Origin**: {profile_data.get('origin', 'Unknown')}
- **Sponsorship**: {profile_data.get('sponsorship', 'Unknown')}
- **Confidence Level**: {profile_data.get('confidence', 'Medium')}
- **First Observed**: {profile_data.get('first_seen', 'Unknown')}

## Aliases
{', '.join(profile_data.get('aliases', []))}

## Targeting
- **Sectors**: {', '.join(profile_data.get('sectors', []))}
- **Regions**: {', '.join(profile_data.get('regions', []))}
- **Motivation**: {profile_data.get('motivation', 'Unknown')}

## TTP Summary (MITRE ATT&CK)
"""
    for tactic, techs in ttp_data.items():
        if techs:
            dossier += f"\n### {tactic.replace('_', ' ').title()}\n"
            for t in techs:
                dossier += f"- **{t['id']}**: {t['name']}\n"

    dossier += f"""
## Infrastructure Patterns
- Known C2 servers: {len(infrastructure_data.get('c2_servers', []))}
- Domain patterns: {', '.join(infrastructure_data.get('domain_patterns', []))}
- Hosting preferences: {', '.join(infrastructure_data.get('hosting', []))}

## Recommendations
1. Monitor for known TTPs in EDR/SIEM
2. Block known infrastructure indicators
3. Hunt for behavioral patterns in network traffic
4. Implement detections for top technique gaps
"""
    with open(f"{actor_name.lower().replace(' ', '_')}_dossier.md", "w") as f:
        f.write(dossier)
    print(f"[+] Dossier saved for {actor_name}")

generate_dossier("APT29", {
    "description": "Russian state-sponsored espionage group attributed to SVR",
    "origin": "Russia", "sponsorship": "SVR (Foreign Intelligence Service)",
    "confidence": "High", "first_seen": "2008",
    "aliases": ["Cozy Bear", "Midnight Blizzard", "NOBELIUM", "The Dukes"],
    "sectors": ["Government", "Diplomatic", "Think Tank", "Healthcare", "Energy"],
    "regions": ["North America", "Europe", "NATO countries"],
    "motivation": "Espionage",
}, profile_ttps, {"c2_servers": [], "domain_patterns": [], "hosting": []})
```

## Validation Criteria

- Intelligence collected from at least 3 OSINT sources
- STIX 2.1 Threat Actor and Intrusion Set objects created correctly
- TTPs mapped to ATT&CK with technique IDs and procedure examples
- Infrastructure indicators correlated across sources
- Dossier includes attribution assessment with confidence levels
- Profile is actionable for detection engineering and threat hunting

## References

- [Huntress: Threat Actor Profiling](https://www.huntress.com/cybersecurity-101/topic/threat-actor-profiling)
- [CrowdStrike: OSINT in Cybersecurity](https://www.crowdstrike.com/en-us/cybersecurity-101/threat-intelligence/open-source-intelligence-osint/)
- [SpiderFoot OSINT Tool](https://github.com/smicallef/spiderfoot)
- [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
- [ShadowDragon: OSINT Techniques](https://shadowdragon.io/blog/osint-techniques/)
- [ISACA: Building a Threat-Led Cybersecurity Program](https://www.isaca.org/resources/white-papers/2025/building-a-threat-led-cybersecurity-program)
