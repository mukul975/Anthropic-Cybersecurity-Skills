---
name: implementing-purdue-model-network-segmentation
description: >
  Implement network segmentation based on the Purdue Enterprise Reference
  Architecture (PERA) model to separate industrial control system networks into
  hierarchical security zones from Level 0 physical process through Level 5
  enterprise, enforcing strict traffic control between OT and IT domains.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, purdue-model, network-segmentation, iec62443, defense-in-depth, dmz, scada]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Purdue Model Network Segmentation

## When to Use

- When designing or retrofitting network architecture for an ICS/SCADA environment
- When implementing IEC 62443 zone and conduit requirements in a brownfield plant
- When creating the IT/OT DMZ (Level 3.5) to control data flow between enterprise and control networks
- When remediating audit findings about flat OT networks or direct IT-to-OT connectivity
- When segmenting a converged IT/OT network after an acquisition or merger

**Do not use** for micro-segmentation within a single Purdue level (see implementing-zone-conduit-model-for-ics), for cloud-native environments without traditional ICS networks, or for network segmentation in purely IT environments.

## Prerequisites

- Complete OT asset inventory with Purdue level classification for each device
- Network architecture diagram showing current topology, VLANs, and firewall placements
- Industrial firewalls capable of deep packet inspection for OT protocols (Palo Alto, Fortinet, Cisco)
- Understanding of required data flows between Purdue levels (historian replication, remote access, patch distribution)
- Change management approval from plant operations for network modifications

## Workflow

### Step 1: Map Current Architecture to Purdue Levels

Classify all network assets and data flows according to the Purdue Model hierarchy.

```python
#!/usr/bin/env python3
"""Purdue Model Network Segmentation Planner.

Maps existing OT/IT network assets to Purdue Model levels and generates
segmentation recommendations including firewall rules and VLAN assignments.
"""

import json
import csv
import sys
from collections import defaultdict
from datetime import datetime
from typing import Dict, List


PURDUE_LEVELS = {
    0: {
        "name": "Physical Process",
        "description": "Sensors, actuators, field instruments",
        "typical_devices": ["Sensors", "Actuators", "Drives", "Motor starters"],
        "vlan_range": "100-109",
        "allowed_protocols": ["HART", "Profibus", "Foundation Fieldbus", "IO-Link"],
    },
    1: {
        "name": "Basic Control",
        "description": "PLCs, RTUs, safety controllers",
        "typical_devices": ["PLC", "RTU", "Safety Controller", "DCS Controller"],
        "vlan_range": "110-119",
        "allowed_protocols": ["EtherNet/IP", "Profinet", "Modbus/TCP", "S7comm", "OPC UA"],
    },
    2: {
        "name": "Supervisory Control",
        "description": "HMI, SCADA servers, engineering workstations",
        "typical_devices": ["HMI", "SCADA Server", "Engineering Workstation", "Batch Server"],
        "vlan_range": "120-129",
        "allowed_protocols": ["OPC UA", "OPC DA", "Modbus/TCP", "DNP3", "HTTPS"],
    },
    3: {
        "name": "Site Operations",
        "description": "Historian, MES, asset management",
        "typical_devices": ["Historian", "MES Server", "Asset Management", "Alarm Server"],
        "vlan_range": "130-139",
        "allowed_protocols": ["OPC UA", "SQL", "HTTPS", "MQTT"],
    },
    3.5: {
        "name": "IT/OT DMZ",
        "description": "Demilitarized zone between IT and OT",
        "typical_devices": ["Jump Server", "Historian Mirror", "Patch Server", "AV Update Server", "Remote Access Gateway"],
        "vlan_range": "150-159",
        "allowed_protocols": ["HTTPS", "RDP (to jump server only)", "SSH", "SQL (read replica)"],
    },
    4: {
        "name": "Enterprise IT",
        "description": "Enterprise applications, email, ERP",
        "typical_devices": ["ERP Server", "Email Server", "Business Applications", "Active Directory"],
        "vlan_range": "200-249",
        "allowed_protocols": ["HTTPS", "LDAPS", "SMTP", "SQL"],
    },
    5: {
        "name": "Enterprise Network / Internet",
        "description": "External connections, cloud services, partner networks",
        "typical_devices": ["Internet Gateway", "VPN Concentrator", "Cloud Services"],
        "vlan_range": "250-254",
        "allowed_protocols": ["HTTPS", "IPsec VPN"],
    },
}


class PurdueSegmentationPlanner:
    """Plans Purdue Model network segmentation."""

    def __init__(self):
        self.assets = []
        self.data_flows = []
        self.firewall_rules = []

    def load_asset_inventory(self, filepath: str):
        """Load asset inventory from CSV."""
        with open(filepath, "r") as f:
            self.assets = list(csv.DictReader(f))
        print(f"[*] Loaded {len(self.assets)} assets")

    def classify_assets(self):
        """Classify assets into Purdue levels based on type and function."""
        classification = defaultdict(list)
        for asset in self.assets:
            level = asset.get("purdue_level", "")
            try:
                level = float(level)
            except (ValueError, TypeError):
                level = self._infer_purdue_level(asset)

            classification[level].append(asset)
            asset["assigned_level"] = level

        return classification

    def _infer_purdue_level(self, asset: dict) -> float:
        """Infer Purdue level from device type if not explicitly assigned."""
        device_type = asset.get("type", "").lower()
        mapping = {
            "sensor": 0, "actuator": 0, "drive": 0,
            "plc": 1, "rtu": 1, "safety": 1, "dcs": 1,
            "hmi": 2, "scada": 2, "engineering": 2,
            "historian": 3, "mes": 3, "alarm": 3,
            "jump": 3.5, "patch": 3.5, "remote_access": 3.5,
            "erp": 4, "email": 4, "directory": 4,
        }
        for keyword, level in mapping.items():
            if keyword in device_type:
                return level
        return -1

    def generate_vlan_plan(self, classification: dict) -> list:
        """Generate VLAN assignment plan based on Purdue levels."""
        vlan_plan = []
        for level, info in PURDUE_LEVELS.items():
            assets_at_level = classification.get(level, [])
            vlan_plan.append({
                "purdue_level": level,
                "level_name": info["name"],
                "vlan_range": info["vlan_range"],
                "asset_count": len(assets_at_level),
                "allowed_protocols": info["allowed_protocols"],
            })
        return vlan_plan

    def generate_firewall_rules(self) -> list:
        """Generate inter-level firewall rules enforcing Purdue Model boundaries."""
        rules = [
            {
                "rule_id": 1,
                "name": "Block direct IT-to-Level1",
                "action": "DENY",
                "source_zone": "Level_4_Enterprise",
                "dest_zone": "Level_1_Control",
                "service": "ANY",
                "log": True,
                "description": "No direct access from enterprise IT to basic control PLCs",
            },
            {
                "rule_id": 2,
                "name": "Block direct IT-to-Level2",
                "action": "DENY",
                "source_zone": "Level_4_Enterprise",
                "dest_zone": "Level_2_Supervisory",
                "service": "ANY",
                "log": True,
                "description": "No direct access from enterprise IT to HMI/SCADA",
            },
            {
                "rule_id": 3,
                "name": "Allow DMZ-to-Historian-Replica",
                "action": "ALLOW",
                "source_zone": "Level_3_Operations",
                "dest_zone": "Level_35_DMZ",
                "service": "SQL/1433 (read replica push)",
                "log": True,
                "description": "Historian pushes data to DMZ replica for IT consumption",
            },
            {
                "rule_id": 4,
                "name": "Allow IT-to-DMZ-JumpServer",
                "action": "ALLOW",
                "source_zone": "Level_4_Enterprise",
                "dest_zone": "Level_35_DMZ",
                "service": "RDP/3389, SSH/22",
                "log": True,
                "description": "IT users access OT via jump server in DMZ only",
            },
            {
                "rule_id": 5,
                "name": "Allow DMZ-JumpServer-to-Level2",
                "action": "ALLOW",
                "source_zone": "Level_35_DMZ",
                "dest_zone": "Level_2_Supervisory",
                "service": "RDP/3389 (from jump server IP only)",
                "log": True,
                "description": "Jump server provides controlled access to HMI/SCADA",
            },
            {
                "rule_id": 6,
                "name": "Allow Level2-to-Level1",
                "action": "ALLOW",
                "source_zone": "Level_2_Supervisory",
                "dest_zone": "Level_1_Control",
                "service": "Modbus/502, EtherNet-IP/44818, S7comm/102",
                "log": True,
                "description": "HMI/SCADA communicates with PLCs using industrial protocols",
            },
            {
                "rule_id": 7,
                "name": "Block Level1-outbound-internet",
                "action": "DENY",
                "source_zone": "Level_1_Control",
                "dest_zone": "Level_5_Internet",
                "service": "ANY",
                "log": True,
                "description": "PLCs must never reach the internet directly",
            },
            {
                "rule_id": 8,
                "name": "Allow patch distribution DMZ-to-Level2",
                "action": "ALLOW",
                "source_zone": "Level_35_DMZ",
                "dest_zone": "Level_2_Supervisory",
                "service": "WSUS/8530",
                "log": True,
                "description": "Patch server in DMZ distributes updates to supervisory systems",
            },
            {
                "rule_id": 9,
                "name": "Default deny all inter-zone",
                "action": "DENY",
                "source_zone": "ANY",
                "dest_zone": "ANY",
                "service": "ANY",
                "log": True,
                "description": "Default deny all traffic not explicitly permitted",
            },
        ]
        self.firewall_rules = rules
        return rules

    def print_segmentation_plan(self, classification: dict):
        """Print the complete segmentation plan."""
        print(f"\n{'='*70}")
        print("PURDUE MODEL NETWORK SEGMENTATION PLAN")
        print(f"{'='*70}")
        print(f"Generated: {datetime.now().isoformat()}")

        vlan_plan = self.generate_vlan_plan(classification)
        print(f"\n--- VLAN ASSIGNMENT ---")
        for v in vlan_plan:
            print(f"\n  {v['level_name']} (Purdue {v['purdue_level']})")
            print(f"    VLAN Range: {v['vlan_range']}")
            print(f"    Assets: {v['asset_count']}")
            print(f"    Allowed Protocols: {', '.join(v['allowed_protocols'])}")

        print(f"\n--- INTER-ZONE FIREWALL RULES ---")
        rules = self.generate_firewall_rules()
        for rule in rules:
            action_symbol = "+" if rule["action"] == "ALLOW" else "X"
            print(f"\n  [{action_symbol}] Rule {rule['rule_id']}: {rule['name']}")
            print(f"      {rule['source_zone']} -> {rule['dest_zone']}")
            print(f"      Service: {rule['service']}")
            print(f"      Reason: {rule['description']}")


if __name__ == "__main__":
    planner = PurdueSegmentationPlanner()
    if len(sys.argv) >= 2:
        planner.load_asset_inventory(sys.argv[1])
    classification = planner.classify_assets()
    planner.print_segmentation_plan(classification)
```

### Step 2: Configure Industrial DMZ (Level 3.5)

The DMZ is the critical boundary between IT and OT. All data exchange must traverse it -- no direct connections are permitted.

```yaml
# Level 3.5 DMZ Architecture Configuration
# All IT-OT data exchange flows through the DMZ

dmz_architecture:
  zone_name: "IT_OT_DMZ"
  purdue_level: 3.5
  vlan: 150

  components:
    historian_replica:
      purpose: "Read-only copy of OT historian data for IT/business access"
      direction: "OT pushes data TO DMZ (unidirectional)"
      ip: "10.10.150.10"
      services:
        - port: 1433
          protocol: "SQL"
          direction: "inbound from Level 3 historian only"
        - port: 443
          protocol: "HTTPS"
          direction: "outbound to Level 4 for IT consumers"

    jump_server:
      purpose: "Controlled remote access point for OT maintenance"
      ip: "10.10.150.20"
      services:
        - port: 3389
          protocol: "RDP"
          direction: "inbound from Level 4 with MFA"
        - port: 3389
          protocol: "RDP"
          direction: "outbound to Level 2 HMIs only"
      security_controls:
        - "Multi-factor authentication required"
        - "Session recording enabled"
        - "Maximum session duration: 4 hours"
        - "Approval-based access workflow"

    patch_server:
      purpose: "Staging area for tested patches before OT deployment"
      ip: "10.10.150.30"
      services:
        - port: 8530
          protocol: "WSUS"
          direction: "pulls from Level 4 WSUS, pushes to Level 2-3"

    antivirus_relay:
      purpose: "AV signature distribution to OT endpoints"
      ip: "10.10.150.40"
      services:
        - port: 443
          protocol: "HTTPS"
          direction: "pulls definitions from Level 4, distributes to Level 2-3"

  firewall_rules:
    north_firewall:  # Between DMZ and Level 4 Enterprise
      - allow: "Level 4 -> DMZ jump server:3389 (with MFA)"
      - allow: "Level 4 -> DMZ historian replica:443 (read-only)"
      - allow: "DMZ patch server -> Level 4 WSUS:8530 (pull only)"
      - deny: "ALL other traffic"

    south_firewall:  # Between DMZ and Level 3 Operations
      - allow: "Level 3 historian -> DMZ replica:1433 (push direction)"
      - allow: "DMZ jump server -> Level 2 HMI:3389 (session-limited)"
      - allow: "DMZ patch server -> Level 2/3:8530 (scheduled)"
      - deny: "ALL other traffic"

    critical_rule: "NO traffic passes through DMZ end-to-end. DMZ breaks all connections."
```

## Key Concepts

| Term | Definition |
|------|------------|
| Purdue Model (PERA) | Hierarchical reference architecture organizing industrial networks into levels 0-5 based on function and trust |
| Level 3.5 DMZ | Demilitarized zone between IT (Level 4) and OT (Level 3), where all cross-boundary data exchange occurs |
| Defense in Depth | Layered security approach requiring attackers to breach multiple boundaries to reach critical control systems |
| Data Diode | Hardware-enforced unidirectional communication device ensuring data flows only from OT to IT, never reverse |
| Zone | Logical grouping of assets sharing common security requirements as defined by IEC 62443 |
| Conduit | Controlled communication path between zones with defined security policies |

## Common Scenarios

### Scenario: Flat OT Network Remediation

**Context**: An audit reveals that enterprise IT systems can directly communicate with PLCs on the control network. There is no DMZ and no firewall between IT and OT.

**Approach**:
1. Perform full traffic analysis to identify all legitimate data flows crossing IT/OT boundary
2. Design DMZ architecture with historian replica, jump server, and patch staging
3. Deploy industrial firewall between IT and DMZ (north firewall) and between DMZ and OT (south firewall)
4. Migrate data flows one at a time: start with historian replication through DMZ
5. Implement jump server for remote access, deprecating direct RDP to OT systems
6. Block direct IT-to-OT traffic on the north firewall after all flows migrate through DMZ
7. Validate with penetration test from IT network confirming no direct path to Level 1 controllers

**Pitfalls**: Do not cut over all traffic simultaneously -- migrate flow by flow with rollback plans. Legacy OT systems may use protocols that cannot traverse firewalls doing DPI; test thoroughly in a lab first. Never deploy the DMZ during active production without an agreed maintenance window.

## Output Format

```
PURDUE MODEL SEGMENTATION REPORT
====================================
Assessment Date: YYYY-MM-DD
Facility: [Plant Name]

CURRENT STATE:
  Network Type: [Flat/Partially segmented/Fully segmented]
  IT-OT Boundary: [None/Firewall/DMZ with dual firewall]
  Direct IT-to-PLC paths: [count]

RECOMMENDED ARCHITECTURE:
  Level 0-1: VLAN 110 (Control Network)
  Level 2:   VLAN 120 (Supervisory Network)
  Level 3:   VLAN 130 (Operations Network)
  Level 3.5: VLAN 150 (IT/OT DMZ)
  Level 4-5: VLAN 200+ (Enterprise)

DMZ COMPONENTS:
  - Historian Replica Server
  - Jump Server (MFA-enabled)
  - Patch Staging Server
  - AV Relay Server

FIREWALL RULES: [count] rules generated
MIGRATION STEPS: [count] phases planned
```
