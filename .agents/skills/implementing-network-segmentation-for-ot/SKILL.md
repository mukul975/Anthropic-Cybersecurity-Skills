---
name: implementing-network-segmentation-for-ot
description: >
  This skill covers implementing network segmentation in Operational Technology
  environments using VLANs, industrial firewalls, data diodes, and software-defined
  networking. It addresses the Purdue Model-based segmentation strategy, migration
  from flat networks to segmented architectures without disrupting operations,
  configuring OT-aware firewalls with industrial protocol deep packet inspection,
  and validating segmentation effectiveness through traffic analysis.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, scada, industrial-control, iec62443, network-segmentation, vlan]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Implementing Network Segmentation for OT

## When to Use

- When an OT security assessment reveals a flat network with no segmentation between Purdue levels
- When implementing IEC 62443 zone/conduit architecture after completing risk assessment (IEC 62443-3-2)
- When separating IT and OT networks as part of an IT/OT convergence security initiative
- When deploying a DMZ between corporate IT and OT to protect industrial systems from IT-originating threats
- When segmenting safety instrumented systems (SIS) from basic process control systems (BPCS)

**Do not use** for IT-only microsegmentation without OT components (see implementing-zero-trust-in-cloud), or for initial zone design without prior traffic analysis (see performing-ot-network-security-assessment first).

## Prerequisites

- Complete traffic baseline from passive monitoring (minimum 2-4 weeks of capture data)
- Asset inventory with Purdue level classifications for all OT devices
- Industrial-grade network switches with VLAN support and port security
- OT-aware firewalls (Cisco ISA-3000, Fortinet FortiGate Rugged, Palo Alto with OT Security)
- Maintenance window schedule for network changes
- Rollback plan approved by operations management

## Workflow

### Step 1: Design Segmentation Architecture Based on Traffic Baseline

Use the traffic baseline to design VLAN and firewall architecture that preserves all legitimate communication paths while isolating zones.

```python
#!/usr/bin/env python3
"""OT Network Segmentation Design Tool.

Analyzes traffic baseline data and generates a segmentation design
with VLAN assignments, firewall rules, and migration plan.
"""

import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from ipaddress import ip_address, ip_network


@dataclass
class VLANDesign:
    vlan_id: int
    name: str
    purdue_level: str
    subnet: str
    gateway: str
    description: str
    devices: list = field(default_factory=list)


@dataclass
class FirewallRule:
    rule_id: int
    source_zone: str
    source_ip: str
    dest_zone: str
    dest_ip: str
    protocol: str
    port: int
    action: str
    dpi_profile: str = ""
    comment: str = ""


class SegmentationDesigner:
    """Generates segmentation design from traffic baseline."""

    def __init__(self, baseline_file):
        with open(baseline_file) as f:
            self.baseline = json.load(f)
        self.vlans = []
        self.rules = []
        self.rule_counter = 1

    def design_vlans(self):
        """Create VLAN design based on Purdue levels."""
        self.vlans = [
            VLANDesign(10, "SIS-SAFETY", "Level 1 (Safety)",
                       "10.10.10.0/24", "10.10.10.1",
                       "Safety Instrumented Systems - air-gapped or hardware-isolated"),
            VLANDesign(20, "BPCS-FIELD", "Level 0-1 (Field/Control)",
                       "10.10.20.0/24", "10.10.20.1",
                       "PLCs, RTUs, I/O modules, field instruments"),
            VLANDesign(30, "BPCS-SUPERVISORY", "Level 2 (Supervisory)",
                       "10.10.30.0/24", "10.10.30.1",
                       "HMIs, engineering workstations, local historian"),
            VLANDesign(40, "SITE-OPS", "Level 3 (Operations)",
                       "10.10.40.0/24", "10.10.40.1",
                       "Site historian, OPC server, MES, alarm management"),
            VLANDesign(50, "OT-DMZ", "Level 3.5 (DMZ)",
                       "172.16.50.0/24", "172.16.50.1",
                       "Data diode, historian mirror, jump server, patch server"),
            VLANDesign(60, "ENTERPRISE", "Level 4 (Enterprise)",
                       "10.0.60.0/24", "10.0.60.1",
                       "Enterprise IT systems accessing OT data"),
            VLANDesign(999, "QUARANTINE", "Quarantine",
                       "10.10.99.0/24", "10.10.99.1",
                       "Quarantine VLAN for unauthorized or untrusted devices"),
        ]
        return self.vlans

    def generate_firewall_rules_from_baseline(self):
        """Generate firewall rules based on observed legitimate traffic."""
        self.rules = []

        # Default deny rules for each zone boundary
        zone_pairs = [
            ("Level 2", "Level 0-1"),
            ("Level 3", "Level 2"),
            ("Level 3.5", "Level 3"),
            ("Level 4", "Level 3.5"),
        ]

        # Generate allow rules from baseline observed traffic
        for flow in self.baseline.get("cross_zone_flows", []):
            self.rules.append(FirewallRule(
                rule_id=self.rule_counter,
                source_zone=flow["src_level"],
                source_ip=flow["src"],
                dest_zone=flow["dst_level"],
                dest_ip=flow["dst"],
                protocol=flow.get("protocol", "TCP"),
                port=flow.get("port", 0),
                action="ALLOW",
                dpi_profile=self._get_dpi_profile(flow.get("port", 0)),
                comment=f"Baseline observed: {flow['src']} -> {flow['dst']}",
            ))
            self.rule_counter += 1

        # Add default deny rules at the end of each zone ACL
        for src_zone, dst_zone in zone_pairs:
            self.rules.append(FirewallRule(
                rule_id=self.rule_counter,
                source_zone=src_zone,
                source_ip="any",
                dest_zone=dst_zone,
                dest_ip="any",
                protocol="any",
                port=0,
                action="DENY",
                comment=f"Default deny: {src_zone} -> {dst_zone}",
            ))
            self.rule_counter += 1

        return self.rules

    def _get_dpi_profile(self, port):
        """Return the appropriate DPI inspection profile for an OT protocol port."""
        dpi_profiles = {
            502: "modbus-inspect (allow read FC only from L3)",
            44818: "enip-inspect",
            4840: "opcua-inspect (require SignAndEncrypt)",
            102: "s7comm-inspect",
            20000: "dnp3-inspect",
        }
        return dpi_profiles.get(port, "none")

    def generate_migration_plan(self):
        """Generate phased migration plan for network segmentation."""
        plan = {
            "phase_1": {
                "name": "DMZ Implementation (Week 1-2)",
                "description": "Deploy DMZ between enterprise and OT networks",
                "steps": [
                    "Deploy DMZ firewall pair (inside and outside)",
                    "Migrate historian mirror to DMZ",
                    "Configure jump server in DMZ with MFA",
                    "Install data diode for unidirectional historian replication",
                    "Route enterprise-to-OT traffic through DMZ",
                    "Verify enterprise access to historian data via DMZ",
                ],
                "rollback": "Remove DMZ firewall rules, restore direct routing",
            },
            "phase_2": {
                "name": "L3/L2 Segmentation (Week 3-4)",
                "description": "Separate operations (L3) from control (L2) zones",
                "steps": [
                    "Create VLAN 30 and VLAN 40 on OT switches",
                    "Deploy industrial firewall between L2 and L3",
                    "Configure firewall in monitor mode (log only, no blocking)",
                    "Analyze logs for 1 week to validate rule completeness",
                    "Switch to enforcement mode during maintenance window",
                    "Validate all HMI-to-PLC and historian-to-PLC communications",
                ],
                "rollback": "Revert VLAN assignments, set firewall to permit-any",
            },
            "phase_3": {
                "name": "Field Device Isolation (Week 5-6)",
                "description": "Isolate Level 0-1 field devices from Level 2 supervisory",
                "steps": [
                    "Create VLAN 20 for PLCs and field instruments",
                    "Configure port security with MAC binding on PLC ports",
                    "Apply Modbus function code filtering (block writes from L3)",
                    "Test all control loops during maintenance window",
                    "Verify alarm propagation from field to HMI",
                ],
                "rollback": "Merge VLAN 20 back into VLAN 30",
            },
            "phase_4": {
                "name": "SIS Isolation (Week 7-8)",
                "description": "Fully isolate Safety Instrumented Systems",
                "steps": [
                    "Verify SIS is on dedicated VLAN 10 or air-gapped",
                    "Remove any network path between SIS and BPCS",
                    "Implement dedicated engineering workstation for SIS",
                    "Apply USB and removable media controls on SIS EWS",
                    "Test SIS functionality in isolation",
                ],
                "rollback": "N/A - SIS isolation should not be reversed",
            },
        }
        return plan

    def export_design(self, output_file):
        """Export complete segmentation design."""
        design = {
            "vlans": [asdict(v) for v in self.vlans],
            "firewall_rules": [asdict(r) for r in self.rules],
            "migration_plan": self.generate_migration_plan(),
        }

        with open(output_file, "w") as f:
            json.dump(design, f, indent=2)

        print(f"[*] Segmentation design exported to: {output_file}")
        print(f"    VLANs: {len(self.vlans)}")
        print(f"    Firewall Rules: {len(self.rules)}")

        return design


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python segmentation_designer.py <baseline.json> [output.json]")
        sys.exit(1)

    designer = SegmentationDesigner(sys.argv[1])
    designer.design_vlans()
    designer.generate_firewall_rules_from_baseline()

    output = sys.argv[2] if len(sys.argv) > 2 else "segmentation_design.json"
    designer.export_design(output)
```

### Step 2: Configure Industrial Switch VLANs

Apply VLAN configuration to industrial Ethernet switches with port security and unused port hardening.

```bash
# Cisco Industrial Ethernet 4000/5000 Series Configuration

# Create VLANs aligned with Purdue levels
vlan 10
  name SIS-SAFETY-L1
vlan 20
  name BPCS-FIELD-L01
vlan 30
  name BPCS-SUPERVISORY-L2
vlan 40
  name SITE-OPS-L3
vlan 50
  name OT-DMZ-L35
vlan 999
  name QUARANTINE

# PLC access ports with port security
interface range GigabitEthernet1/0/1-12
  description PLC Connections
  switchport mode access
  switchport access vlan 20
  switchport port-security
  switchport port-security maximum 1
  switchport port-security mac-address sticky
  switchport port-security violation shutdown
  storm-control broadcast level 10
  storm-control multicast level 10
  spanning-tree portfast
  spanning-tree bpduguard enable
  no cdp enable
  no lldp transmit
  no lldp receive

# HMI access ports
interface range GigabitEthernet1/0/13-18
  description HMI Stations
  switchport mode access
  switchport access vlan 30
  switchport port-security
  switchport port-security maximum 1
  switchport port-security mac-address sticky
  switchport port-security violation restrict
  spanning-tree portfast

# Trunk to zone firewall
interface TenGigabitEthernet1/0/1
  description Trunk to OT Zone Firewall
  switchport mode trunk
  switchport trunk allowed vlan 20,30,40,50
  switchport trunk native vlan 999
  switchport nonegotiate

# Disable and quarantine all unused ports
interface range GigabitEthernet1/0/19-48
  description UNUSED - Shutdown
  switchport mode access
  switchport access vlan 999
  shutdown
```

### Step 3: Validate Segmentation Effectiveness

After implementation, validate that segmentation correctly blocks unauthorized cross-zone traffic while permitting all legitimate operations.

```python
#!/usr/bin/env python3
"""OT Network Segmentation Validator.

Runs automated tests to verify zone isolation, firewall rules,
and protocol enforcement after segmentation deployment.
"""

import json
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, asdict


@dataclass
class ValidationTest:
    test_id: str
    description: str
    source_zone: str
    target_ip: str
    target_port: int
    expected_result: str  # "blocked" or "allowed"
    actual_result: str = ""
    status: str = ""  # PASS or FAIL


class SegmentationValidator:
    """Validates OT network segmentation implementation."""

    def __init__(self):
        self.tests = []
        self.results = []

    def add_test(self, test):
        self.tests.append(test)

    def run_connectivity_test(self, target_ip, target_port, timeout=3):
        """Test TCP connectivity to target."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, target_port))
            sock.close()
            return "reachable" if result == 0 else "blocked"
        except (socket.timeout, ConnectionRefusedError):
            return "blocked"
        except Exception:
            return "error"

    def run_all_tests(self):
        """Execute all segmentation validation tests."""
        print("=" * 60)
        print("OT SEGMENTATION VALIDATION")
        print("=" * 60)

        passed = 0
        failed = 0

        for test in self.tests:
            actual = self.run_connectivity_test(test.target_ip, test.target_port)
            test.actual_result = actual

            if actual == test.expected_result:
                test.status = "PASS"
                passed += 1
            else:
                test.status = "FAIL"
                failed += 1

            icon = "[+]" if test.status == "PASS" else "[-]"
            print(f"  {icon} {test.test_id}: {test.description}")
            print(f"      Target: {test.target_ip}:{test.target_port}")
            print(f"      Expected: {test.expected_result} | Actual: {actual} -> {test.status}")

        print(f"\n  Results: {passed} passed, {failed} failed out of {len(self.tests)} tests")
        return {"passed": passed, "failed": failed, "total": len(self.tests)}


if __name__ == "__main__":
    validator = SegmentationValidator()

    # Tests from Enterprise zone (Level 4) - should be blocked from OT
    validator.add_test(ValidationTest(
        "SEG-001", "Enterprise cannot reach PLCs via Modbus",
        "Level 4", "10.10.20.10", 502, "blocked"))
    validator.add_test(ValidationTest(
        "SEG-002", "Enterprise cannot reach PLCs via EtherNet/IP",
        "Level 4", "10.10.20.10", 44818, "blocked"))
    validator.add_test(ValidationTest(
        "SEG-003", "Enterprise can reach DMZ jump server",
        "Level 4", "172.16.50.10", 3389, "allowed"))
    validator.add_test(ValidationTest(
        "SEG-004", "Enterprise can reach DMZ historian mirror",
        "Level 4", "172.16.50.20", 443, "allowed"))

    # Tests from Operations zone (Level 3) - limited access to control
    validator.add_test(ValidationTest(
        "SEG-005", "Operations can read from PLCs via Modbus",
        "Level 3", "10.10.20.10", 502, "allowed"))
    validator.add_test(ValidationTest(
        "SEG-006", "Operations cannot reach SIS controllers",
        "Level 3", "10.10.10.10", 1502, "blocked"))

    validator.run_all_tests()
```

## Key Concepts

| Term | Definition |
|------|------------|
| VLAN | Virtual Local Area Network - Layer 2 broadcast domain isolation used to separate OT zones on shared switch infrastructure |
| Industrial Firewall | Firewall with deep packet inspection capabilities for industrial protocols (Modbus, DNP3, EtherNet/IP, OPC UA) |
| Data Diode | Hardware-enforced unidirectional gateway that physically prevents reverse data flow, used between OT operations and DMZ |
| Port Security | Switch feature that limits the number of MAC addresses on a port and locks assignments, preventing unauthorized device connections |
| Trunk Port | Switch port carrying multiple VLANs using 802.1Q tagging, used to connect switches and firewalls across zone boundaries |
| DMZ | Demilitarized Zone between enterprise IT and OT - a buffer zone where all cross-domain traffic terminates and is inspected |

## Tools & Systems

- **Cisco ISA-3000**: Industrial security appliance with Modbus, DNP3, and EtherNet/IP deep packet inspection for OT zone firewalls
- **Fortinet FortiGate Rugged Series**: Ruggedized NGFW with OT protocol support and industrial environment certifications
- **Waterfall Security Unidirectional Gateway**: Hardware data diode for enforcing one-way data flow from OT to IT
- **Cisco Industrial Ethernet Switches**: Managed switches with VLAN, port security, and industrial protocol support

## Output Format

```
OT Network Segmentation Report
================================
Implementation Date: YYYY-MM-DD

VLAN ARCHITECTURE:
  VLAN [ID] - [Name] ([Purdue Level])
    Subnet: [subnet/mask]
    Devices: [count]

FIREWALL RULES:
  [Zone A] -> [Zone B]: [allow/deny count]

VALIDATION RESULTS:
  Tests Passed: [N]/[Total]
  Critical Failures: [N]
```
