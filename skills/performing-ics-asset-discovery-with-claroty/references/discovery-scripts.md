# Claroty Asset Discovery Scripts

Full standalone scripts referenced from `SKILL.md`. Both require `requests`.

## Step 1: Claroty xDome Asset Discovery and Reporting Tool

Configures passive monitoring and generates asset inventory reports from the Claroty xDome API (sites, assets, communication maps, vulnerabilities, CSV export, Purdue-level report):

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

## Step 3: Asset Validation and Enrichment Tool

Cross-references Claroty discovery results against an existing CMDB and enriches with NVD vulnerability data (shadow-device detection, missing-device detection, firmware CVE lookup, risk summary):

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
