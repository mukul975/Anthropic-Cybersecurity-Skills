---
name: performing-ics-asset-discovery-with-claroty
description: >
  Perform comprehensive ICS/OT asset discovery using Claroty xDome platform,
  leveraging passive monitoring, Claroty Edge active queries, and integration
  ecosystem to gain full visibility into industrial control system assets
  including PLCs, RTUs, HMIs, and network infrastructure across Purdue Model levels.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, asset-discovery, claroty, xdome, scada, network-visibility, iec62443]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing ICS Asset Discovery with Claroty

## When to Use

- When gaining initial visibility into an OT environment with unknown or poorly documented assets
- When preparing for an IEC 62443 risk assessment requiring a complete asset inventory
- When onboarding Claroty xDome into a brownfield industrial environment
- When validating existing asset inventory against actual network communications
- When identifying shadow OT devices or unauthorized connections in the control network

**Do not use** for IT-only asset discovery (use tools like Nessus or Qualys), for active scanning of sensitive PLC networks without vendor approval, or for environments where Claroty is not the deployed platform (see implementing-ot-network-traffic-analysis-with-nozomi).

## Prerequisites

- Claroty xDome SaaS subscription or on-premises deployment
- Network TAP or SPAN port configured at OT network boundaries (Levels 1-3 of Purdue Model)
- Claroty Edge collector deployed for safe active querying of hard-to-reach network segments
- Integration credentials for CMDB tools (ServiceNow, BMC) if used
- Network architecture diagram showing VLANs, switches, and firewall zones

## Workflow

### Step 1: Configure Passive Network Monitoring

Deploy Claroty sensors on SPAN ports to passively observe all OT network traffic without impacting operations.

```python
#!/usr/bin/env python3
"""Claroty xDome Asset Discovery Configuration and Reporting Tool.

Automates the configuration of passive monitoring sensors and generates
asset inventory reports from Claroty xDome API.
"""

import json
import sys
import csv
from datetime import datetime
from typing import Optional

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)


class ClarotyAssetDiscovery:
    """Interface with Claroty xDome API for ICS asset discovery."""

    def __init__(self, base_url: str, api_token: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        self.session.verify = verify_ssl

    def get_sites(self):
        """Retrieve all monitored sites."""
        resp = self.session.get(f"{self.base_url}/api/v1/sites")
        resp.raise_for_status()
        return resp.json().get("sites", [])

    def get_assets(self, site_id: Optional[str] = None, asset_type: Optional[str] = None):
        """Retrieve discovered assets with optional filtering.

        asset_type: PLC, RTU, HMI, DCS, Engineering_Workstation,
                    Historian, Network_Device, IO_Module, Safety_Controller
        """
        params = {}
        if site_id:
            params["site_id"] = site_id
        if asset_type:
            params["type"] = asset_type

        resp = self.session.get(f"{self.base_url}/api/v1/assets", params=params)
        resp.raise_for_status()
        return resp.json().get("assets", [])

    def get_asset_detail(self, asset_id: str):
        """Retrieve detailed asset information including firmware, modules, and CVEs."""
        resp = self.session.get(f"{self.base_url}/api/v1/assets/{asset_id}")
        resp.raise_for_status()
        return resp.json()

    def get_communication_map(self, site_id: str):
        """Retrieve communication relationships between assets."""
        resp = self.session.get(
            f"{self.base_url}/api/v1/sites/{site_id}/communications"
        )
        resp.raise_for_status()
        return resp.json().get("communications", [])

    def get_vulnerabilities(self, site_id: Optional[str] = None, severity: str = "critical"):
        """Retrieve vulnerabilities for discovered assets."""
        params = {"min_severity": severity}
        if site_id:
            params["site_id"] = site_id

        resp = self.session.get(f"{self.base_url}/api/v1/vulnerabilities", params=params)
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])

    def export_asset_inventory(self, output_file: str, site_id: Optional[str] = None):
        """Export full asset inventory to CSV for compliance reporting."""
        assets = self.get_assets(site_id=site_id)
        if not assets:
            print("[!] No assets found")
            return

        fieldnames = [
            "asset_id", "name", "type", "vendor", "model", "firmware_version",
            "ip_address", "mac_address", "serial_number", "purdue_level",
            "zone", "protocol", "first_seen", "last_seen", "risk_score",
            "cve_count", "site_name",
        ]

        with open(output_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for asset in assets:
                writer.writerow({
                    "asset_id": asset.get("id", ""),
                    "name": asset.get("name", "Unknown"),
                    "type": asset.get("type", ""),
                    "vendor": asset.get("vendor", ""),
                    "model": asset.get("model", ""),
                    "firmware_version": asset.get("firmware_version", ""),
                    "ip_address": asset.get("ip_address", ""),
                    "mac_address": asset.get("mac_address", ""),
                    "serial_number": asset.get("serial_number", ""),
                    "purdue_level": asset.get("purdue_level", ""),
                    "zone": asset.get("zone", ""),
                    "protocol": ", ".join(asset.get("protocols", [])),
                    "first_seen": asset.get("first_seen", ""),
                    "last_seen": asset.get("last_seen", ""),
                    "risk_score": asset.get("risk_score", 0),
                    "cve_count": asset.get("cve_count", 0),
                    "site_name": asset.get("site_name", ""),
                })

        print(f"[+] Exported {len(assets)} assets to {output_file}")

    def generate_purdue_level_report(self, site_id: str):
        """Generate asset distribution report by Purdue Model level."""
        assets = self.get_assets(site_id=site_id)
        levels = {0: [], 1: [], 2: [], 3: [], 3.5: [], 4: [], 5: []}

        for asset in assets:
            level = asset.get("purdue_level", -1)
            if level in levels:
                levels[level].append(asset)

        print(f"\n{'='*65}")
        print("PURDUE MODEL ASSET DISTRIBUTION REPORT")
        print(f"{'='*65}")
        print(f"Site: {site_id}")
        print(f"Total Assets Discovered: {len(assets)}")
        print(f"Report Generated: {datetime.now().isoformat()}")
        print(f"{'-'*65}")

        level_names = {
            0: "Level 0 - Physical Process (Sensors/Actuators)",
            1: "Level 1 - Basic Control (PLCs/RTUs)",
            2: "Level 2 - Supervisory Control (HMI/SCADA)",
            3: "Level 3 - Site Operations (Historian/MES)",
            3.5: "Level 3.5 - IT/OT DMZ",
            4: "Level 4 - Enterprise IT",
            5: "Level 5 - Enterprise Network/Internet",
        }

        for level, name in level_names.items():
            device_list = levels.get(level, [])
            print(f"\n  {name}")
            print(f"    Count: {len(device_list)}")
            if device_list:
                vendors = set(a.get("vendor", "Unknown") for a in device_list)
                types = set(a.get("type", "Unknown") for a in device_list)
                print(f"    Vendors: {', '.join(vendors)}")
                print(f"    Types: {', '.join(types)}")
                high_risk = [a for a in device_list if a.get("risk_score", 0) >= 7]
                if high_risk:
                    print(f"    High-Risk Assets: {len(high_risk)}")
                    for a in high_risk[:5]:
                        print(f"      - {a['name']} (Risk: {a.get('risk_score')})")


if __name__ == "__main__":
    discovery = ClarotyAssetDiscovery(
        base_url="https://your-claroty-instance.claroty.cloud",
        api_token="your-api-token-here",
        verify_ssl=True,
    )

    print("[*] Fetching sites...")
    sites = discovery.get_sites()
    for site in sites:
        print(f"  Site: {site['name']} (ID: {site['id']})")

    if sites:
        site_id = sites[0]["id"]
        print(f"\n[*] Generating Purdue level report for {sites[0]['name']}...")
        discovery.generate_purdue_level_report(site_id)

        print(f"\n[*] Exporting asset inventory...")
        discovery.export_asset_inventory(
            f"asset_inventory_{datetime.now().strftime('%Y%m%d')}.csv",
            site_id=site_id,
        )

        print(f"\n[*] Checking critical vulnerabilities...")
        vulns = discovery.get_vulnerabilities(site_id=site_id, severity="critical")
        print(f"  Critical vulnerabilities: {len(vulns)}")
        for v in vulns[:10]:
            print(f"    - {v.get('cve_id')}: {v.get('description', '')[:80]}")
```

### Step 2: Configure Active Discovery with Claroty Edge

Claroty Edge performs safe, targeted queries of OT devices using native industrial protocols (not IT scanning) to extract detailed asset information from devices that passive monitoring alone cannot fully identify.

```yaml
# Claroty Edge Active Discovery Configuration
# Safe active queries using native industrial protocols

edge_configuration:
  deployment_mode: "on-premises"
  collection_schedule:
    frequency: "weekly"
    maintenance_window: "Sunday 02:00-06:00"
    max_concurrent_queries: 5

  protocol_queries:
    siemens_s7:
      enabled: true
      target_subnets: ["10.10.1.0/24", "10.10.2.0/24"]
      ports: [102]
      query_type: "SZL_read"
      information_collected:
        - "Module identification"
        - "Firmware version"
        - "Hardware configuration"
        - "Protection level"

    rockwell_cip:
      enabled: true
      target_subnets: ["10.10.3.0/24"]
      ports: [44818]
      query_type: "CIP_identity"
      information_collected:
        - "Product name and revision"
        - "Serial number"
        - "Device type"
        - "Vendor ID"

    modbus:
      enabled: true
      target_subnets: ["10.10.4.0/24"]
      ports: [502]
      query_type: "read_device_identification"
      function_code: 43
      information_collected:
        - "Vendor name"
        - "Product code"
        - "Firmware revision"

    bacnet:
      enabled: true
      target_subnets: ["10.10.5.0/24"]
      ports: [47808]
      query_type: "who_is"
      information_collected:
        - "Device name"
        - "Vendor identifier"
        - "Model name"
        - "Application software version"

  safety_controls:
    excluded_subnets: ["10.10.100.0/24"]  # SIS network - never active scan
    rate_limiting: true
    max_packets_per_second: 10
    timeout_seconds: 5
    retry_count: 1
    abort_on_device_error: true
```

### Step 3: Validate and Enrich Asset Data

Cross-reference discovered assets against known inventories and enrich with vulnerability data.

```python
#!/usr/bin/env python3
"""Asset Validation and Enrichment Tool.

Cross-references Claroty discovery results against existing CMDB
and enriches with NVD vulnerability data.
"""

import json
import csv
import sys
from datetime import datetime

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)


class AssetValidator:
    """Validates and enriches OT asset inventory."""

    def __init__(self, inventory_file: str):
        self.discovered_assets = []
        self.load_inventory(inventory_file)
        self.discrepancies = []

    def load_inventory(self, filepath: str):
        """Load Claroty-discovered asset inventory."""
        with open(filepath, "r") as f:
            reader = csv.DictReader(f)
            self.discovered_assets = list(reader)
        print(f"[*] Loaded {len(self.discovered_assets)} discovered assets")

    def compare_with_cmdb(self, cmdb_file: str):
        """Compare discovered assets against CMDB records."""
        with open(cmdb_file, "r") as f:
            cmdb_assets = {row["ip_address"]: row for row in csv.DictReader(f)}

        discovered_ips = {a["ip_address"] for a in self.discovered_assets if a["ip_address"]}
        cmdb_ips = set(cmdb_assets.keys())

        shadow_devices = discovered_ips - cmdb_ips
        missing_devices = cmdb_ips - discovered_ips

        print(f"\n{'='*60}")
        print("ASSET INVENTORY VALIDATION REPORT")
        print(f"{'='*60}")
        print(f"Discovered assets: {len(discovered_ips)}")
        print(f"CMDB records: {len(cmdb_ips)}")
        print(f"Shadow OT devices (not in CMDB): {len(shadow_devices)}")
        print(f"Missing devices (in CMDB, not seen): {len(missing_devices)}")

        if shadow_devices:
            print(f"\n  SHADOW DEVICES (Unauthorized/Undocumented):")
            for ip in sorted(shadow_devices):
                asset = next((a for a in self.discovered_assets if a["ip_address"] == ip), {})
                print(f"    - {ip} | {asset.get('vendor', 'Unknown')} {asset.get('model', '')} | Type: {asset.get('type', 'Unknown')}")
                self.discrepancies.append({
                    "type": "SHADOW_DEVICE",
                    "severity": "HIGH",
                    "ip": ip,
                    "detail": f"Undocumented {asset.get('type', 'device')} from {asset.get('vendor', 'unknown vendor')}",
                })

        if missing_devices:
            print(f"\n  MISSING DEVICES (Expected but not seen):")
            for ip in sorted(missing_devices):
                cmdb = cmdb_assets[ip]
                print(f"    - {ip} | {cmdb.get('name', 'Unknown')} | Last CMDB update: {cmdb.get('last_updated', 'N/A')}")
                self.discrepancies.append({
                    "type": "MISSING_DEVICE",
                    "severity": "MEDIUM",
                    "ip": ip,
                    "detail": f"CMDB asset {cmdb.get('name', ip)} not seen on network",
                })

    def check_firmware_vulnerabilities(self, asset):
        """Check NVD for known vulnerabilities matching asset firmware."""
        vendor = asset.get("vendor", "").lower()
        model = asset.get("model", "").lower()
        firmware = asset.get("firmware_version", "")

        if not vendor or not model:
            return []

        search_term = f"{vendor} {model}"
        try:
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": search_term, "resultsPerPage": 10},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("vulnerabilities", [])
        except requests.RequestException:
            pass
        return []

    def generate_risk_summary(self):
        """Generate risk-prioritized summary of findings."""
        print(f"\n{'='*60}")
        print("RISK SUMMARY")
        print(f"{'='*60}")

        high_risk = [a for a in self.discovered_assets if float(a.get("risk_score", 0)) >= 7]
        end_of_life = [a for a in self.discovered_assets if a.get("firmware_version", "").startswith("v1.")]
        no_encryption = [a for a in self.discovered_assets if "modbus" in a.get("protocol", "").lower()]

        print(f"  High-risk assets (score >= 7): {len(high_risk)}")
        print(f"  Potentially end-of-life firmware: {len(end_of_life)}")
        print(f"  Assets using unencrypted protocols: {len(no_encryption)}")
        print(f"  Inventory discrepancies: {len(self.discrepancies)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python validate_assets.py <claroty_export.csv> [cmdb_export.csv]")
        sys.exit(1)

    validator = AssetValidator(sys.argv[1])
    if len(sys.argv) >= 3:
        validator.compare_with_cmdb(sys.argv[2])
    validator.generate_risk_summary()
```

## Key Concepts

| Term | Definition |
|------|------------|
| Passive Monitoring | Observing mirrored network traffic via SPAN/TAP without injecting packets, safe for all OT devices |
| Active Querying | Sending native protocol requests to extract detailed device information; requires careful scheduling |
| Claroty Edge | Claroty's safe active discovery collector that uses native industrial protocols rather than IT scanning |
| Purdue Level | Hierarchical classification of industrial network assets from Level 0 (physical process) to Level 5 (enterprise) |
| Shadow OT Device | Asset connected to the OT network that is not documented in the asset management system |
| xDome | Claroty's SaaS-based cyber-physical systems protection platform providing visibility, risk management, and threat detection |

## Common Scenarios

### Scenario: Brownfield Factory Asset Discovery

**Context**: A manufacturing plant with 20 years of equipment additions needs a complete OT asset inventory for an IEC 62443 risk assessment. No accurate asset records exist.

**Approach**:
1. Deploy Claroty sensors on SPAN ports at each major network segment (control, supervisory, DMZ)
2. Allow passive monitoring for 2-4 weeks to capture all regular communication patterns
3. Schedule Claroty Edge active queries during a planned maintenance window
4. Export discovered inventory and categorize assets by Purdue level, vendor, and criticality
5. Cross-reference against any existing documentation (P&ID diagrams, network drawings)
6. Identify shadow devices and initiate a review process with plant operations
7. Feed validated inventory into IEC 62443 zone and conduit risk assessment

**Pitfalls**: Do not rush active discovery before passive monitoring has captured baseline traffic patterns. Never use IT vulnerability scanners (Nessus active scans) directly against PLCs or RTUs -- this can crash legacy controllers. Always exclude Safety Instrumented Systems (SIS) from active queries.

## Output Format

```
ICS ASSET DISCOVERY REPORT
============================
Date: YYYY-MM-DD
Platform: Claroty xDome
Site: [Site Name]

DISCOVERY SUMMARY:
  Total Assets Discovered: [count]
  New Assets (not in CMDB): [count]
  High-Risk Assets: [count]

PURDUE LEVEL DISTRIBUTION:
  Level 0 (Process): [count] assets
  Level 1 (Control): [count] assets
  Level 2 (Supervisory): [count] assets
  Level 3 (Operations): [count] assets
  Level 3.5 (DMZ): [count] assets
  Level 4-5 (Enterprise): [count] assets

TOP VENDORS:
  1. [Vendor] - [count] devices
  2. [Vendor] - [count] devices

CRITICAL FINDINGS:
  - [Shadow device description]
  - [End-of-life firmware finding]
  - [Unencrypted protocol concern]
```
