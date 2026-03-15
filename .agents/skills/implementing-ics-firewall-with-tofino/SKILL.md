---
name: implementing-ics-firewall-with-tofino
description: >
  Deploy and configure Tofino industrial firewalls from Belden/Hirschmann to
  protect SCADA systems and PLCs using deep packet inspection for OT protocols
  including Modbus, EtherNet/IP, OPC, and S7comm, enforcing granular access
  control between ICS security zones.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, firewall, tofino, belden, deep-packet-inspection, network-security, scada]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing ICS Firewall with Tofino

## When to Use

- When deploying zone-level firewall protection directly in front of critical PLCs or RTUs
- When requiring deep packet inspection of industrial protocols (Modbus, EtherNet/IP, OPC, S7comm)
- When implementing IEC 62443 zone and conduit boundaries with protocol-aware enforcement
- When protecting legacy PLCs that cannot be patched and need compensating controls
- When segmenting control network zones without disrupting existing industrial communications

**Do not use** for enterprise IT firewall deployment, for perimeter firewall between IT and OT (use Palo Alto/Fortinet at the DMZ), or for environments using only IP-based protocols without OT-specific DPI needs.

## Prerequisites

- Tofino Xenon appliance or Tofino virtual appliance with appropriate license
- Tofino Central Management Platform (CMP) for centralized policy management
- Network topology map showing PLC/RTU placement and communication requirements
- Baseline of OT protocol communications (Modbus function codes, EtherNet/IP CIP services)
- Change management approval for inline deployment between network zones

## Workflow

### Step 1: Design Tofino Deployment Architecture

```yaml
# Tofino ICS Firewall Deployment Architecture
# Zone-level protection using deep packet inspection

deployment_zones:
  zone_1_reactor_control:
    tofino_appliance: "TOFINO-XN-001"
    deployment_mode: "inline_bridge"
    protected_assets:
      - name: "PLC-REACTOR-01"
        ip: "10.10.1.10"
        vendor: "Siemens S7-1500"
        protocols: ["S7comm/102", "Profinet"]
      - name: "PLC-REACTOR-02"
        ip: "10.10.1.11"
        vendor: "Siemens S7-1500"
        protocols: ["S7comm/102", "Profinet"]
    authorized_communications:
      - source: "10.10.2.50"  # Engineering workstation
        dest: "10.10.1.0/24"
        protocols: ["S7comm"]
        access_type: "engineering"
      - source: "10.10.2.10"  # HMI server
        dest: "10.10.1.0/24"
        protocols: ["S7comm"]
        access_type: "operational"

  zone_2_packaging:
    tofino_appliance: "TOFINO-XN-002"
    deployment_mode: "inline_bridge"
    protected_assets:
      - name: "PLC-PACK-01"
        ip: "10.10.3.10"
        vendor: "Rockwell ControlLogix"
        protocols: ["EtherNet-IP/44818", "CIP"]
    authorized_communications:
      - source: "10.10.2.20"  # HMI
        dest: "10.10.3.0/24"
        protocols: ["EtherNet-IP"]
        access_type: "operational"

  zone_3_utilities:
    tofino_appliance: "TOFINO-XN-003"
    deployment_mode: "inline_bridge"
    protected_assets:
      - name: "RTU-BOILER-01"
        ip: "10.10.4.10"
        vendor: "Schneider M340"
        protocols: ["Modbus-TCP/502"]
    authorized_communications:
      - source: "10.10.2.30"  # SCADA server
        dest: "10.10.4.0/24"
        protocols: ["Modbus-TCP"]
        allowed_function_codes: [1, 2, 3, 4]  # Read only from SCADA
```

### Step 2: Configure Deep Packet Inspection Rules

```python
#!/usr/bin/env python3
"""Tofino ICS Firewall Rule Generator.

Generates Tofino firewall rules with deep packet inspection for
industrial protocols based on communication baseline analysis.
"""

import json
import sys
from datetime import datetime
from typing import Dict, List


class TofinoRuleGenerator:
    """Generates Tofino ICS firewall DPI rules."""

    def __init__(self):
        self.rules = []
        self.rule_id = 1000

    def add_modbus_rule(self, src: str, dst: str, allowed_funcs: List[int],
                        allowed_registers: List[dict] = None, description: str = ""):
        """Generate Modbus DPI rule."""
        func_names = {
            1: "read_coils", 2: "read_discrete_inputs",
            3: "read_holding_registers", 4: "read_input_registers",
            5: "write_single_coil", 6: "write_single_register",
            15: "write_multiple_coils", 16: "write_multiple_registers",
        }

        rule = {
            "rule_id": self.rule_id,
            "protocol": "Modbus-TCP",
            "action": "ALLOW",
            "source": src,
            "destination": dst,
            "port": 502,
            "dpi_policy": {
                "allowed_function_codes": [
                    {"code": fc, "name": func_names.get(fc, f"FC{fc}")}
                    for fc in allowed_funcs
                ],
                "blocked_function_codes": [
                    fc for fc in range(1, 128) if fc not in allowed_funcs
                ],
            },
            "description": description,
            "log": True,
        }

        if allowed_registers:
            rule["dpi_policy"]["allowed_register_ranges"] = allowed_registers

        self.rules.append(rule)
        self.rule_id += 1
        return rule

    def add_s7comm_rule(self, src: str, dst: str, allowed_operations: List[str],
                        description: str = ""):
        """Generate S7comm DPI rule."""
        operation_map = {
            "read": {"function": 0x04, "name": "Read Variable"},
            "write": {"function": 0x05, "name": "Write Variable"},
            "setup": {"function": 0xF0, "name": "Setup Communication"},
            "download": {"function": 0x1A, "name": "Request Download"},
            "upload": {"function": 0x1D, "name": "Start Upload"},
            "cpu_stop": {"function": 0x29, "name": "PLC Stop"},
            "cpu_start": {"function": 0x28, "name": "PI Service (Start)"},
        }

        rule = {
            "rule_id": self.rule_id,
            "protocol": "S7comm",
            "action": "ALLOW",
            "source": src,
            "destination": dst,
            "port": 102,
            "dpi_policy": {
                "allowed_operations": [
                    operation_map[op] for op in allowed_operations if op in operation_map
                ],
                "block_cpu_stop": "cpu_stop" not in allowed_operations,
                "block_program_download": "download" not in allowed_operations,
            },
            "description": description,
            "log": True,
        }

        self.rules.append(rule)
        self.rule_id += 1
        return rule

    def add_ethernet_ip_rule(self, src: str, dst: str, allowed_services: List[str],
                              description: str = ""):
        """Generate EtherNet/IP CIP DPI rule."""
        rule = {
            "rule_id": self.rule_id,
            "protocol": "EtherNet-IP",
            "action": "ALLOW",
            "source": src,
            "destination": dst,
            "port": 44818,
            "dpi_policy": {
                "allowed_cip_services": allowed_services,
                "block_firmware_flash": True,
                "block_program_download": "program_download" not in allowed_services,
            },
            "description": description,
            "log": True,
        }

        self.rules.append(rule)
        self.rule_id += 1
        return rule

    def add_default_deny(self):
        """Add default deny rule at the end."""
        self.rules.append({
            "rule_id": 9999,
            "protocol": "ANY",
            "action": "DENY",
            "source": "ANY",
            "destination": "ANY",
            "port": "ANY",
            "description": "Default deny - block all unmatched traffic",
            "log": True,
        })

    def generate_config(self) -> str:
        """Generate complete Tofino firewall configuration."""
        config = {
            "tofino_configuration": {
                "generated": datetime.now().isoformat(),
                "appliance_model": "Tofino Xenon",
                "firmware_version": "4.2",
                "mode": "inline_bridge",
                "failsafe": "fail_open",
                "rules": self.rules,
            }
        }
        return json.dumps(config, indent=2)

    def print_summary(self):
        """Print rule summary."""
        print(f"\n{'='*65}")
        print("TOFINO ICS FIREWALL RULE SUMMARY")
        print(f"{'='*65}")
        print(f"Generated: {datetime.now().isoformat()}")
        print(f"Total Rules: {len(self.rules)}")

        for rule in self.rules:
            action_icon = "+" if rule["action"] == "ALLOW" else "X"
            print(f"\n  [{action_icon}] Rule {rule['rule_id']}: {rule.get('description', '')}")
            print(f"      {rule['source']} -> {rule['destination']}:{rule['port']}")
            print(f"      Protocol: {rule['protocol']}")
            if "dpi_policy" in rule:
                dpi = rule["dpi_policy"]
                if "allowed_function_codes" in dpi:
                    funcs = [f["name"] for f in dpi["allowed_function_codes"]]
                    print(f"      DPI - Allowed Modbus FCs: {', '.join(funcs)}")
                if "allowed_operations" in dpi:
                    ops = [o["name"] for o in dpi["allowed_operations"]]
                    print(f"      DPI - Allowed S7 Ops: {', '.join(ops)}")


if __name__ == "__main__":
    gen = TofinoRuleGenerator()

    # SCADA server to Modbus RTUs: read-only
    gen.add_modbus_rule(
        src="10.10.2.30",
        dst="10.10.4.0/24",
        allowed_funcs=[1, 2, 3, 4],
        description="SCADA to utilities RTUs - read only",
    )

    # Engineering workstation to Siemens PLCs: full access
    gen.add_s7comm_rule(
        src="10.10.2.50",
        dst="10.10.1.0/24",
        allowed_operations=["read", "write", "setup", "download", "upload"],
        description="Engineering WS to reactor PLCs - full engineering access",
    )

    # HMI to Siemens PLCs: read + write only (no program download)
    gen.add_s7comm_rule(
        src="10.10.2.10",
        dst="10.10.1.0/24",
        allowed_operations=["read", "write", "setup"],
        description="HMI to reactor PLCs - operational access only",
    )

    # HMI to Rockwell PLCs: operational access
    gen.add_ethernet_ip_rule(
        src="10.10.2.20",
        dst="10.10.3.0/24",
        allowed_services=["read_tag", "write_tag", "get_attribute"],
        description="HMI to packaging PLCs - operational access",
    )

    gen.add_default_deny()
    gen.print_summary()
```

## Key Concepts

| Term | Definition |
|------|------------|
| Tofino Xenon | Belden/Hirschmann industrial firewall appliance with deep packet inspection for OT protocols |
| Deep Packet Inspection (DPI) | Examining message payload content beyond headers to enforce fine-grained rules on industrial protocol operations |
| Inline Bridge Mode | Transparent deployment mode where the firewall sits between network segments without requiring IP changes |
| Fail-Open | Safety mode where firewall passes all traffic if the appliance fails, maintaining process availability |
| Loadable Security Module (LSM) | Tofino plugin module providing protocol-specific DPI for Modbus, EtherNet/IP, OPC, or other protocols |
| Central Management Platform (CMP) | Tofino centralized management server for deploying and managing policies across multiple Tofino appliances |

## Output Format

```
TOFINO DEPLOYMENT REPORT
===========================
Date: YYYY-MM-DD
Appliances Deployed: [count]

PER-APPLIANCE SUMMARY:
  [Appliance ID]:
    Mode: Inline Bridge
    Failsafe: Fail-Open
    Protected Assets: [count]
    Rules: [count]
    DPI Protocols: [list]

RULE SUMMARY:
  Allow Rules: [count]
  Deny Rules: [count]
  DPI-Enforced Rules: [count]

MONITORING:
  Blocked Packets (24h): [count]
  DPI Violations (24h): [count]
```
