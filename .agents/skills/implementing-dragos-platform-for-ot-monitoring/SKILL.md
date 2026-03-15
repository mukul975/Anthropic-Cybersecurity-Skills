---
name: implementing-dragos-platform-for-ot-monitoring
description: >
  Deploy and configure the Dragos Platform for OT network monitoring, leveraging
  its 600+ industrial protocol parsers, intelligence-driven threat detection
  analytics, and asset visibility capabilities to protect ICS environments against
  threat groups like VOLTZITE, GRAPHITE, and BAUXITE.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, dragos, threat-detection, ot-monitoring, scada, threat-intelligence, ndr]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Dragos Platform for OT Monitoring

## When to Use

- When deploying an OT-specific network detection and response (NDR) solution for industrial environments
- When needing threat intelligence-driven detection against known ICS threat groups (VOLTZITE, CHERNOVITE, KAMACITE)
- When building an OT SOC capability with purpose-built industrial security tooling
- When requiring asset discovery and vulnerability management alongside threat detection in a single platform
- When integrating OT security monitoring with an enterprise SIEM (Splunk, Sentinel, QRadar)

**Do not use** for IT-only network monitoring without ICS components, for endpoint detection and response (EDR) on OT workstations, or for environments standardized on Claroty or Nozomi (see respective skills).

## Prerequisites

- Dragos Platform license and deployment package
- Network TAP or SPAN port at OT network boundaries (one sensor per monitored segment)
- Dragos sensor hardware (physical appliance) or virtual appliance meeting minimum specifications
- Firewall rules allowing sensor-to-Dragos-SiteStore communication (encrypted, outbound only from OT)
- Dragos Knowledge Pack subscription for threat intelligence updates

## Workflow

### Step 1: Deploy Dragos Sensors and Configure Monitoring

```python
#!/usr/bin/env python3
"""Dragos Platform Deployment Validator and Integration Tool.

Validates Dragos sensor deployment, checks connectivity, and
configures integration with enterprise SIEM for OT alert forwarding.
"""

import json
import sys
import csv
from datetime import datetime
from typing import Optional, List, Dict

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)


class DragosPlatformManager:
    """Interface with Dragos Platform API for OT monitoring management."""

    def __init__(self, base_url: str, api_key: str, api_secret: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "API-Key": api_key,
            "API-Secret": api_secret,
            "Content-Type": "application/json",
        })
        self.session.verify = verify_ssl

    def get_sensors(self) -> List[Dict]:
        """Retrieve all deployed Dragos sensors and their status."""
        resp = self.session.get(f"{self.base_url}/api/v1/sensors")
        resp.raise_for_status()
        return resp.json().get("sensors", [])

    def get_assets(self, asset_type: Optional[str] = None) -> List[Dict]:
        """Retrieve OT assets discovered by Dragos."""
        params = {}
        if asset_type:
            params["type"] = asset_type
        resp = self.session.get(f"{self.base_url}/api/v1/assets", params=params)
        resp.raise_for_status()
        return resp.json().get("assets", [])

    def get_notifications(self, severity: str = "high", limit: int = 50) -> List[Dict]:
        """Retrieve threat detection notifications."""
        params = {"min_severity": severity, "limit": limit}
        resp = self.session.get(f"{self.base_url}/api/v1/notifications", params=params)
        resp.raise_for_status()
        return resp.json().get("notifications", [])

    def get_vulnerabilities(self, severity: str = "critical") -> List[Dict]:
        """Retrieve OT vulnerabilities with Dragos-specific context."""
        params = {"min_severity": severity}
        resp = self.session.get(f"{self.base_url}/api/v1/vulnerabilities", params=params)
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])

    def get_threat_groups(self) -> List[Dict]:
        """Retrieve tracked ICS threat group activity relevant to the environment."""
        resp = self.session.get(f"{self.base_url}/api/v1/threat-groups")
        resp.raise_for_status()
        return resp.json().get("threat_groups", [])

    def validate_deployment(self):
        """Validate sensor deployment health and coverage."""
        sensors = self.get_sensors()
        assets = self.get_assets()

        print(f"\n{'='*65}")
        print("DRAGOS PLATFORM DEPLOYMENT VALIDATION")
        print(f"{'='*65}")
        print(f"Validation Time: {datetime.now().isoformat()}")

        print(f"\n--- SENSOR STATUS ---")
        healthy_sensors = 0
        for sensor in sensors:
            status = sensor.get("status", "unknown")
            icon = "[OK]" if status == "connected" else "[!!]"
            print(f"  {icon} {sensor.get('name', 'Unknown')} | Status: {status}")
            print(f"      IP: {sensor.get('ip_address')} | Segment: {sensor.get('monitored_segment')}")
            print(f"      Last Seen: {sensor.get('last_seen')} | Packets/sec: {sensor.get('pps', 0)}")
            print(f"      Knowledge Pack: {sensor.get('knowledge_pack_version', 'N/A')}")
            if status == "connected":
                healthy_sensors += 1

        print(f"\n  Sensor Health: {healthy_sensors}/{len(sensors)} operational")

        print(f"\n--- ASSET VISIBILITY ---")
        print(f"  Total Assets Discovered: {len(assets)}")
        asset_types = {}
        for asset in assets:
            atype = asset.get("type", "Unknown")
            asset_types[atype] = asset_types.get(atype, 0) + 1
        for atype, count in sorted(asset_types.items(), key=lambda x: -x[1]):
            print(f"    {atype}: {count}")

        protocols = set()
        for asset in assets:
            protocols.update(asset.get("protocols", []))
        print(f"  Protocols Observed: {', '.join(sorted(protocols))}")

        print(f"\n--- THREAT INTELLIGENCE ---")
        groups = self.get_threat_groups()
        print(f"  Relevant Threat Groups: {len(groups)}")
        for group in groups:
            print(f"    - {group.get('name')}: {group.get('description', '')[:80]}")
            print(f"      Targets: {', '.join(group.get('target_sectors', []))}")
            print(f"      Activity Level: {group.get('activity_level', 'Unknown')}")

    def generate_siem_integration_config(self, siem_type: str = "splunk"):
        """Generate SIEM integration configuration for Dragos alerts."""
        configs = {
            "splunk": {
                "syslog_format": "CEF",
                "syslog_port": 514,
                "severity_mapping": {
                    "critical": 10,
                    "high": 7,
                    "medium": 5,
                    "low": 3,
                    "info": 1,
                },
                "index": "ot_security",
                "sourcetype": "dragos:notification",
                "fields": [
                    "notification_id", "severity", "category", "source_ip",
                    "destination_ip", "asset_name", "protocol", "description",
                    "mitre_ics_technique", "threat_group",
                ],
            },
            "sentinel": {
                "connector_type": "Syslog-CEF",
                "workspace_id": "<workspace-id>",
                "log_analytics_table": "DragosOTAlerts_CL",
                "severity_mapping": {
                    "critical": "High",
                    "high": "High",
                    "medium": "Medium",
                    "low": "Low",
                    "info": "Informational",
                },
            },
        }

        config = configs.get(siem_type, configs["splunk"])
        print(f"\n--- {siem_type.upper()} INTEGRATION CONFIG ---")
        print(json.dumps(config, indent=2))
        return config


if __name__ == "__main__":
    manager = DragosPlatformManager(
        base_url="https://dragos-sitestore.plant.local",
        api_key="your-api-key",
        api_secret="your-api-secret",
        verify_ssl=True,
    )

    manager.validate_deployment()
    manager.generate_siem_integration_config("splunk")

    print(f"\n--- RECENT HIGH-SEVERITY NOTIFICATIONS ---")
    notifications = manager.get_notifications(severity="high", limit=10)
    for n in notifications:
        print(f"  [{n.get('severity', '').upper()}] {n.get('title', 'No title')}")
        print(f"    Category: {n.get('category')} | Time: {n.get('timestamp')}")
        print(f"    Assets: {', '.join(n.get('affected_assets', []))}")
        print(f"    MITRE ICS: {n.get('mitre_technique', 'N/A')}")
```

### Step 2: Configure Detection Analytics and Knowledge Packs

```yaml
# Dragos Platform Detection Configuration
# Tuned for manufacturing/energy environment

detection_configuration:
  knowledge_pack:
    auto_update: true
    update_schedule: "weekly"
    include_threat_groups:
      - "VOLTZITE"    # Targets energy sector, exfiltrates OT diagrams
      - "GRAPHITE"    # New 2025 threat group targeting ICS
      - "BAUXITE"     # New 2025 threat group targeting ICS
      - "CHERNOVITE"  # Developed PIPEDREAM/INCONTROLLER framework
      - "ELECTRUM"    # Linked to Industroyer/CrashOverride
      - "KAMACITE"    # Targets energy sector initial access

  detection_categories:
    network_baseline:
      enabled: true
      learning_period_days: 30
      alert_on:
        - "new_communication_pair"
        - "new_protocol_detected"
        - "new_device_on_network"
        - "protocol_anomaly"

    threat_detection:
      enabled: true
      alert_on:
        - "known_malware_ioc"
        - "threat_group_ttp"
        - "lateral_movement"
        - "command_and_control"
        - "data_exfiltration"

    vulnerability_correlation:
      enabled: true
      alert_on:
        - "active_exploitation_attempt"
        - "vulnerability_with_public_exploit"

  protocol_monitoring:
    modbus:
      monitor_writes: true
      baseline_function_codes: true
      baseline_register_ranges: true
    dnp3:
      monitor_control_commands: true
      detect_firmware_updates: true
    s7comm:
      detect_cpu_stop: true
      detect_program_download: true
    opc_ua:
      monitor_method_calls: true
      detect_browsing: true
    ethernet_ip:
      monitor_cip_services: true
      detect_firmware_flash: true

  alert_routing:
    critical:
      notify: ["ot_soc_team", "plant_manager"]
      siem_forward: true
      auto_ticket: true
    high:
      notify: ["ot_soc_team"]
      siem_forward: true
      auto_ticket: true
    medium:
      siem_forward: true
    low:
      siem_forward: true
```

## Key Concepts

| Term | Definition |
|------|------------|
| Dragos Platform | Purpose-built OT cybersecurity platform with asset visibility, threat detection, and vulnerability management for ICS environments |
| Knowledge Pack | Dragos threat intelligence update containing detection analytics for new threats, malware, and vulnerability exploits specific to ICS |
| SiteStore | Dragos central management server aggregating data from all deployed sensors across a site |
| VOLTZITE | Dragos-tracked threat group targeting energy sector OT environments, exfiltrating GIS data and ICS network diagrams |
| PIPEDREAM/INCONTROLLER | Modular ICS attack framework developed by CHERNOVITE, targeting Schneider/OMRON PLCs and OPC UA servers |
| Neighborhood Keeper | Dragos community defense program sharing anonymized threat data across participating OT environments |

## Common Scenarios

### Scenario: Detecting VOLTZITE Reconnaissance in Energy Utility

**Context**: A Dragos sensor deployed at an electric utility detects unusual OPC UA browsing activity and exfiltration of device configuration data from an engineering workstation.

**Approach**:
1. Review the Dragos notification for MITRE ATT&CK ICS technique mapping
2. Identify the source host performing OPC UA browsing (check if it is an authorized engineering workstation)
3. Check Dragos threat intelligence correlation for VOLTZITE TTPs
4. Examine the scope of data accessed (GIS data, network diagrams, ICS configuration files)
5. Isolate the compromised workstation from the OT network
6. Check for lateral movement indicators to other OT systems
7. Engage Dragos Professional Services if threat group attribution is confirmed
8. Report to CISA as a critical infrastructure cyber incident

**Pitfalls**: Do not ignore OPC UA browsing alerts as false positives -- VOLTZITE specifically uses this technique for pre-positioning. Ensure Dragos Knowledge Packs are current to detect the latest VOLTZITE indicators. Do not reimage the compromised workstation before collecting forensic evidence.

## Output Format

```
DRAGOS OT MONITORING DEPLOYMENT REPORT
==========================================
Site: [Site Name]
Date: YYYY-MM-DD

SENSOR DEPLOYMENT:
  Total Sensors: [count]
  Operational: [count]
  Coverage: [percentage of OT segments monitored]

ASSET VISIBILITY:
  Total OT Assets: [count]
  PLCs: [count] | HMIs: [count] | Network Devices: [count]
  Protocols: [list]

THREAT DETECTION:
  Active Threat Groups Relevant: [count]
  Detection Analytics Loaded: [count]
  Alerts (Last 30 Days): [count by severity]

SIEM INTEGRATION:
  Status: [Connected/Disconnected]
  Events Forwarded (Last 24h): [count]
```
