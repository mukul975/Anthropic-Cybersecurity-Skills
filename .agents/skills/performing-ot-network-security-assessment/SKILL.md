---
name: performing-ot-network-security-assessment
description: >
  This skill covers conducting comprehensive security assessments of Operational
  Technology (OT) networks including SCADA systems, DCS architectures, and industrial
  control system communication paths. It addresses the Purdue Reference Model layers,
  identifies IT/OT convergence risks, evaluates firewall rules between zones, and
  maps industrial protocol traffic (Modbus, DNP3, OPC UA, EtherNet/IP) to detect
  misconfigurations, unauthorized connections, and attack surfaces in critical infrastructure.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, scada, industrial-control, iec62443, network-assessment]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Performing OT Network Security Assessment

## When to Use

- When conducting an initial security baseline of an OT/ICS environment for a new client
- When evaluating the security posture of a facility after an IT/OT convergence initiative
- When preparing for IEC 62443 or NERC CIP compliance audits
- When assessing risk following a merger or acquisition involving industrial facilities
- When investigating whether an OT network has been compromised or has unmonitored pathways to corporate IT

**Do not use** for IT-only network assessments without OT components, for application-layer vulnerability scanning of IT web applications (see performing-web-app-penetration-test), or for active exploitation of live OT systems without explicit authorization and safety controls in place.

## Prerequisites

- Written authorization from the asset owner and operations management for all assessment activities
- Understanding of the Purdue Reference Model and IEC 62443 zone/conduit architecture
- Passive network monitoring tools (Nozomi Guardian, Dragos Platform, or Wireshark with industrial protocol dissectors)
- Access to network diagrams, firewall rule sets, and asset inventories (or the ability to perform passive discovery)
- Safety briefing on the physical processes controlled by the OT systems under assessment

## Workflow

### Step 1: Establish Assessment Scope and Safety Boundaries

Define the scope based on the Purdue Reference Model levels and identify safety-critical systems that must not be actively scanned. OT assessments differ fundamentally from IT assessments because active scanning can crash PLCs, disrupt safety instrumented systems (SIS), and cause physical harm.

```yaml
# OT Assessment Scope Definition
assessment:
  facility: "Chemical Processing Plant - Site Alpha"
  purdue_levels_in_scope:
    - level_0: "Physical process sensors and actuators (passive observation only)"
    - level_1: "PLCs, RTUs, safety controllers (passive only, no active scanning)"
    - level_2: "HMI stations, engineering workstations, historian (limited active with approval)"
    - level_3: "Site operations - OPC servers, application servers (active scanning permitted)"
    - level_3_5: "DMZ - data diodes, jump servers (active scanning permitted)"
    - level_4: "Enterprise IT connecting to OT (active scanning permitted)"

  safety_exclusions:
    - "Safety Instrumented Systems (SIS) - Triconex controllers"
    - "Emergency Shutdown (ESD) systems"
    - "Fire and Gas detection systems"
    - "Any Level 0/1 device during active production"

  authorized_activities:
    passive:
      - "Network traffic capture and analysis via SPAN ports"
      - "Industrial protocol deep packet inspection"
      - "Wireless spectrum analysis"
      - "Physical walkthrough and visual inspection"
    active_with_approval:
      - "Targeted Nmap scans of Level 2-4 systems during maintenance windows"
      - "Authentication testing on HMI and engineering workstations"
      - "Firewall rule verification between zones"
    prohibited:
      - "Active scanning of PLCs, RTUs, or SIS controllers"
      - "Fuzzing industrial protocols on live systems"
      - "Modifying PLC logic or firmware"
```

### Step 2: Perform Passive Network Discovery and Asset Inventory

Deploy passive monitoring to map all devices, communication flows, and protocols on the OT network without sending any traffic that could disrupt operations.

```python
#!/usr/bin/env python3
"""OT Network Passive Discovery and Asset Inventory Builder.

Uses pcap captures from SPAN ports to identify OT assets, protocols,
and communication patterns without active scanning.
"""

import json
import sys
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import rdpcap, IP, TCP, UDP
    from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse
except ImportError:
    print("Install scapy: pip install scapy")
    sys.exit(1)

# Industrial protocol port mappings
OT_PROTOCOL_PORTS = {
    502: "Modbus/TCP",
    102: "S7comm (Siemens)",
    44818: "EtherNet/IP (CIP)",
    2222: "EtherNet/IP (implicit)",
    4840: "OPC UA",
    20000: "DNP3",
    47808: "BACnet",
    1911: "Niagara Fox",
    789: "Crimson v3 (Red Lion)",
    2404: "IEC 60870-5-104",
    18245: "GE SRTP",
    5094: "HART-IP",
}

PURDUE_LEVEL_RANGES = {
    "Level 0-1 (Field Devices)": ["10.10.0.0/16", "192.168.10.0/24"],
    "Level 2 (Control Systems)": ["10.20.0.0/16", "192.168.20.0/24"],
    "Level 3 (Site Operations)": ["10.30.0.0/16", "192.168.30.0/24"],
    "Level 3.5 (DMZ)": ["172.16.0.0/16"],
    "Level 4 (Enterprise)": ["10.0.0.0/16"],
}


def classify_purdue_level(ip_addr):
    """Classify an IP address to its Purdue Reference Model level."""
    from ipaddress import ip_address, ip_network

    addr = ip_address(ip_addr)
    for level, subnets in PURDUE_LEVEL_RANGES.items():
        for subnet in subnets:
            if addr in ip_network(subnet):
                return level
    return "Unknown"


def analyze_ot_pcap(pcap_file):
    """Analyze pcap file to discover OT assets and communication patterns."""
    packets = rdpcap(pcap_file)

    assets = {}
    connections = defaultdict(lambda: {"count": 0, "protocols": set(), "ports": set()})
    protocol_stats = defaultdict(int)
    cross_zone_flows = []

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # Track assets
        for ip in (src_ip, dst_ip):
            if ip not in assets:
                assets[ip] = {
                    "ip": ip,
                    "purdue_level": classify_purdue_level(ip),
                    "protocols_observed": set(),
                    "roles": set(),
                    "first_seen": str(pkt.time),
                    "last_seen": str(pkt.time),
                    "mac": None,
                }
            assets[ip]["last_seen"] = str(pkt.time)

        # Identify OT protocols by port
        dst_port = None
        if pkt.haslayer(TCP):
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            dst_port = pkt[UDP].dport

        if dst_port and dst_port in OT_PROTOCOL_PORTS:
            protocol_name = OT_PROTOCOL_PORTS[dst_port]
            protocol_stats[protocol_name] += 1
            assets[src_ip]["protocols_observed"].add(protocol_name)
            assets[dst_ip]["protocols_observed"].add(protocol_name)

            # Determine roles
            assets[src_ip]["roles"].add("client/master")
            assets[dst_ip]["roles"].add("server/slave")

        # Track connections
        conn_key = (src_ip, dst_ip)
        connections[conn_key]["count"] += 1
        if dst_port:
            connections[conn_key]["ports"].add(dst_port)
            if dst_port in OT_PROTOCOL_PORTS:
                connections[conn_key]["protocols"].add(OT_PROTOCOL_PORTS[dst_port])

        # Detect cross-zone communication
        src_level = classify_purdue_level(src_ip)
        dst_level = classify_purdue_level(dst_ip)
        if src_level != dst_level and src_level != "Unknown" and dst_level != "Unknown":
            cross_zone_flows.append({
                "src": src_ip,
                "src_level": src_level,
                "dst": dst_ip,
                "dst_level": dst_level,
                "protocol": OT_PROTOCOL_PORTS.get(dst_port, f"port/{dst_port}"),
            })

    return {
        "asset_count": len(assets),
        "assets": {ip: {k: list(v) if isinstance(v, set) else v for k, v in info.items()} for ip, info in assets.items()},
        "protocol_distribution": dict(protocol_stats),
        "total_connections": len(connections),
        "cross_zone_flows": cross_zone_flows[:50],
    }


def generate_assessment_report(results):
    """Generate the OT network assessment findings report."""
    report = []
    report.append("=" * 70)
    report.append("OT NETWORK PASSIVE DISCOVERY REPORT")
    report.append(f"Generated: {datetime.now().isoformat()}")
    report.append("=" * 70)

    report.append(f"\nTotal Assets Discovered: {results['asset_count']}")
    report.append(f"Total Unique Connections: {results['total_connections']}")

    report.append("\n--- INDUSTRIAL PROTOCOL DISTRIBUTION ---")
    for proto, count in sorted(results["protocol_distribution"].items(), key=lambda x: -x[1]):
        report.append(f"  {proto}: {count} packets")

    report.append("\n--- CROSS-ZONE COMMUNICATION FLOWS ---")
    if results["cross_zone_flows"]:
        for flow in results["cross_zone_flows"][:20]:
            report.append(
                f"  {flow['src']} ({flow['src_level']}) -> "
                f"{flow['dst']} ({flow['dst_level']}) via {flow['protocol']}"
            )
    else:
        report.append("  No cross-zone flows detected (check subnet classifications)")

    report.append("\n--- FINDINGS ---")
    # Check for Level 4 to Level 0-1 direct connections (critical finding)
    for flow in results["cross_zone_flows"]:
        if "Level 4" in flow["src_level"] and "Level 0-1" in flow["dst_level"]:
            report.append(
                f"  [CRITICAL] Direct Enterprise-to-Field traffic: "
                f"{flow['src']} -> {flow['dst']} via {flow['protocol']}"
            )
        elif "Level 4" in flow["src_level"] and "Level 2" in flow["dst_level"]:
            report.append(
                f"  [HIGH] Enterprise-to-Control traffic bypassing DMZ: "
                f"{flow['src']} -> {flow['dst']} via {flow['protocol']}"
            )

    return "\n".join(report)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ot_network_discovery.py <pcap_file>")
        sys.exit(1)

    results = analyze_ot_pcap(sys.argv[1])
    print(generate_assessment_report(results))

    # Save detailed JSON
    output_file = sys.argv[1].replace(".pcap", "_inventory.json")
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nDetailed inventory saved to: {output_file}")
```

### Step 3: Evaluate Firewall Rules Between Purdue Zones

Analyze firewall configurations between OT zones to identify overly permissive rules, missing deny defaults, and unauthorized conduits that violate the IEC 62443 zone model.

```python
#!/usr/bin/env python3
"""OT Zone Firewall Rule Analyzer.

Parses firewall rule exports (CSV format) and evaluates them against
IEC 62443 zone/conduit model requirements.
"""

import csv
import json
import sys
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FirewallRule:
    rule_id: str
    source_zone: str
    source_ip: str
    dest_zone: str
    dest_ip: str
    service: str
    port: str
    action: str
    enabled: bool
    comment: str = ""


# IEC 62443 zone communication policy
# Defines which zone pairs are allowed to communicate and through what conduit
ALLOWED_CONDUITS = {
    ("Level 4", "Level 3.5"): {
        "allowed_ports": [443, 3389, 22],
        "description": "Enterprise to DMZ - web services, jump hosts",
        "requires_inspection": True,
    },
    ("Level 3.5", "Level 3"): {
        "allowed_ports": [443, 1433, 5432, 8080],
        "description": "DMZ to Site Ops - historian mirror, OPC relay",
        "requires_inspection": True,
    },
    ("Level 3", "Level 2"): {
        "allowed_ports": [502, 44818, 4840, 102],
        "description": "Site Ops to Control - OPC UA, Modbus, S7comm",
        "requires_inspection": True,
    },
    ("Level 2", "Level 1"): {
        "allowed_ports": [502, 44818, 102, 2222],
        "description": "Control to Field - direct industrial protocols",
        "requires_inspection": False,
    },
}

# Prohibited direct connections
PROHIBITED_CONDUITS = [
    ("Level 4", "Level 3"),
    ("Level 4", "Level 2"),
    ("Level 4", "Level 1"),
    ("Level 4", "Level 0"),
    ("Level 3", "Level 1"),
    ("Level 3", "Level 0"),
    ("Internet", "Level 3.5"),
    ("Internet", "Level 3"),
    ("Internet", "Level 2"),
    ("Internet", "Level 1"),
]


def parse_firewall_rules(csv_file):
    """Parse firewall rules from CSV export."""
    rules = []
    with open(csv_file, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rules.append(FirewallRule(
                rule_id=row.get("rule_id", ""),
                source_zone=row.get("source_zone", ""),
                source_ip=row.get("source_ip", ""),
                dest_zone=row.get("dest_zone", ""),
                dest_ip=row.get("dest_ip", ""),
                service=row.get("service", ""),
                port=row.get("port", ""),
                action=row.get("action", ""),
                enabled=row.get("enabled", "true").lower() == "true",
                comment=row.get("comment", ""),
            ))
    return rules


def analyze_rules(rules):
    """Analyze firewall rules against IEC 62443 zone model."""
    findings = {"critical": [], "high": [], "medium": [], "low": [], "info": []}

    for rule in rules:
        if not rule.enabled or rule.action.lower() != "allow":
            continue

        zone_pair = (rule.source_zone, rule.dest_zone)
        port = int(rule.port) if rule.port.isdigit() else 0

        # Check for prohibited conduits
        if zone_pair in PROHIBITED_CONDUITS:
            findings["critical"].append({
                "rule_id": rule.rule_id,
                "finding": f"Prohibited direct connection: {rule.source_zone} -> {rule.dest_zone}",
                "detail": f"Rule allows {rule.source_ip} to reach {rule.dest_ip}:{rule.port} ({rule.service})",
                "remediation": "Remove rule. Route traffic through DMZ (Level 3.5) with application-layer inspection.",
            })

        # Check for overly broad rules (any/any)
        elif rule.source_ip in ("any", "0.0.0.0/0") or rule.dest_ip in ("any", "0.0.0.0/0"):
            findings["high"].append({
                "rule_id": rule.rule_id,
                "finding": f"Overly permissive rule with 'any' address",
                "detail": f"{rule.source_ip} -> {rule.dest_ip}:{rule.port} in {zone_pair}",
                "remediation": "Restrict to specific host IPs per IEC 62443 least-privilege conduit policy.",
            })

        # Check allowed conduits for port violations
        elif zone_pair in ALLOWED_CONDUITS:
            conduit = ALLOWED_CONDUITS[zone_pair]
            if port and port not in conduit["allowed_ports"]:
                findings["medium"].append({
                    "rule_id": rule.rule_id,
                    "finding": f"Unauthorized port in conduit {zone_pair}",
                    "detail": f"Port {port} ({rule.service}) not in allowed list {conduit['allowed_ports']}",
                    "remediation": f"Remove port {port} from conduit or justify in risk assessment.",
                })

    return findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ot_firewall_analyzer.py <rules.csv>")
        sys.exit(1)

    rules = parse_firewall_rules(sys.argv[1])
    findings = analyze_rules(rules)

    print("=" * 70)
    print("OT ZONE FIREWALL RULE ANALYSIS")
    print("=" * 70)
    for severity in ["critical", "high", "medium", "low"]:
        if findings[severity]:
            print(f"\n--- {severity.upper()} FINDINGS ({len(findings[severity])}) ---")
            for f in findings[severity]:
                print(f"  [{f['rule_id']}] {f['finding']}")
                print(f"    Detail: {f['detail']}")
                print(f"    Fix: {f['remediation']}")
```

### Step 4: Assess Industrial Protocol Security

Evaluate the security configuration of industrial protocols in use, checking for authentication, encryption, and access controls.

```bash
# Capture Modbus/TCP traffic for analysis
tcpdump -i eth0 -w ot_capture.pcap 'port 502 or port 44818 or port 4840 or port 102 or port 20000' -c 100000

# Use Wireshark with OT protocol dissectors for deep inspection
tshark -r ot_capture.pcap -Y "modbus" -T fields \
  -e ip.src -e ip.dst -e modbus.func_code -e modbus.reference_num \
  -e modbus.word_cnt > modbus_analysis.csv

# Check for unauthenticated Modbus write operations (function codes 5,6,15,16)
tshark -r ot_capture.pcap -Y "modbus.func_code >= 5 && modbus.func_code <= 16" \
  -T fields -e ip.src -e ip.dst -e modbus.func_code -e frame.time

# Scan for OPC UA servers and check security policies
# Only run against Level 3+ systems with explicit authorization
python3 -c "
from opcua import Client
server_url = 'opc.tcp://10.30.1.50:4840'
client = Client(server_url)
endpoints = client.connect_and_get_server_endpoints()
for ep in endpoints:
    print(f'Endpoint: {ep.EndpointUrl}')
    print(f'  Security Mode: {ep.SecurityMode}')
    print(f'  Security Policy: {ep.SecurityPolicyUri}')
    print(f'  Auth Tokens: {[t.TokenType for t in ep.UserIdentityTokens]}')
"
```

### Step 5: Generate Assessment Report

Compile findings into a structured report aligned with IEC 62443 and NIST SP 800-82 Rev.3.

```
OT Network Security Assessment Report
=======================================
Facility: Chemical Processing Plant - Site Alpha
Assessment Date: 2026-02-23
Standard: IEC 62443-3-3 / NIST SP 800-82r3
Assessor: [Assessor Name]

EXECUTIVE SUMMARY:
  The OT network assessment identified 47 assets across Purdue levels 0-4.
  12 critical and 23 high-severity findings were identified, primarily
  related to insufficient network segmentation, unauthenticated industrial
  protocols, and unauthorized cross-zone communication paths.

ASSET INVENTORY SUMMARY:
  Level 0-1 (Field):    18 devices (PLCs, RTUs, I/O modules)
  Level 2 (Control):     9 devices (HMIs, engineering workstations)
  Level 3 (Operations): 12 devices (historians, OPC servers, app servers)
  Level 3.5 (DMZ):       3 devices (data diode, jump server, patch server)
  Level 4 (Enterprise):  5 devices (domain controllers, file servers)

CRITICAL FINDINGS:
  [OT-001] Direct Enterprise-to-PLC communication detected
    Source: 10.0.5.22 (Level 4 - IT workstation)
    Dest: 10.10.1.15 (Level 1 - Allen-Bradley PLC)
    Protocol: EtherNet/IP (port 44818)
    Impact: An attacker on the corporate network could directly modify PLC logic
    Remediation: Block direct L4-L1 traffic; route through DMZ proxy

  [OT-002] Modbus/TCP write commands without authentication
    Affected: 8 PLCs accepting unauthenticated FC6 (Write Single Register)
    Impact: Any device on the OT network can modify process setpoints
    Remediation: Deploy Modbus-aware firewall; restrict write-capable sources

  [OT-003] Flat network - no segmentation between Purdue levels
    Detail: All OT devices share VLAN 100 (10.10.0.0/16)
    Impact: Compromised HMI has direct access to all PLCs and SIS
    Remediation: Implement zone-based segmentation per IEC 62443-3-2

RISK MATRIX:
  Critical: 12 findings (immediate remediation required)
  High:     23 findings (remediate within 30 days)
  Medium:   15 findings (remediate within 90 days)
  Low:       8 findings (remediate in next maintenance cycle)
```

## Key Concepts

| Term | Definition |
|------|------------|
| Purdue Reference Model | Hierarchical architecture model (Levels 0-5) for organizing industrial control systems, defining security zones from physical process to enterprise IT |
| IEC 62443 | International standard series for industrial automation and control systems (IACS) security, defining security levels, zones, conduits, and security requirements |
| Zone | A grouping of logical or physical assets that share common security requirements, defined by IEC 62443-3-2 |
| Conduit | A logical grouping of communication channels connecting two or more zones, subject to common security policies |
| SCADA | Supervisory Control and Data Acquisition - system architecture for high-level process supervisory management of industrial processes |
| DCS | Distributed Control System - control system architecture where control elements are distributed throughout the system |
| Air Gap | Physical isolation of OT networks from IT/internet, increasingly replaced by managed conduits with firewalls and data diodes |
| Safety Instrumented System (SIS) | Independent system designed to bring a process to a safe state when a hazardous condition is detected |

## Tools & Systems

- **Nozomi Networks Guardian**: Passive OT network monitoring platform providing asset discovery, vulnerability assessment, and anomaly detection for industrial environments
- **Dragos Platform**: OT cybersecurity platform with asset visibility, threat detection, and vulnerability management designed for critical infrastructure
- **Claroty xDome**: Cyber-physical systems protection platform providing comprehensive asset inventory and risk scoring across OT, IoT, and IIoT
- **Wireshark/tshark**: Network protocol analyzer with industrial protocol dissectors for Modbus, DNP3, S7comm, EtherNet/IP, OPC UA, and BACnet
- **Nmap with OT scripts**: Network scanner with NSE scripts for OT protocol enumeration (use only on Level 2+ with authorization)
- **Grassmarlin**: NSA-developed passive OT network mapping tool for identifying SCADA/ICS network topology

## Common Scenarios

### Scenario: Flat OT Network with No Segmentation

**Context**: A water utility has all OT devices on a single VLAN. Passive network monitoring reveals HMIs, PLCs, historians, and a domain controller all sharing the same Layer 2 broadcast domain. There is no DMZ between the corporate network and the OT environment.

**Approach**:
1. Deploy passive monitoring on the SPAN port to capture a complete communication baseline over 2-4 weeks
2. Map all device-to-device communication flows with protocols and data volumes
3. Classify assets into Purdue levels based on their function and communication patterns
4. Design zone architecture with VLANs and inter-zone firewalls per IEC 62443-3-2
5. Prioritize DMZ creation between Level 3 and Level 4 as the highest-impact segmentation
6. Present segmentation plan with migration phases that avoid production disruption

**Pitfalls**: Active scanning PLCs during production can cause communication timeouts and process disruptions. Implementing segmentation without a complete traffic baseline will break legitimate control system communications. Relying solely on network-layer firewalls without industrial protocol inspection leaves Modbus/TCP and EtherNet/IP write commands unchecked.

## Output Format

```
OT Network Security Assessment Report
=======================================
Facility: [Facility Name]
Assessment Date: YYYY-MM-DD
Standard: IEC 62443-3-3 / NIST SP 800-82r3

EXECUTIVE SUMMARY:
  [2-3 sentence overview of findings and risk level]

ASSET INVENTORY:
  Level 0-1: [count] field devices
  Level 2:   [count] control systems
  Level 3:   [count] operations systems
  Level 3.5: [count] DMZ systems
  Level 4:   [count] enterprise systems

FINDINGS BY SEVERITY:
  Critical: [count] (immediate action required)
  High:     [count] (30-day remediation)
  Medium:   [count] (90-day remediation)
  Low:      [count] (next maintenance window)

DETAILED FINDINGS:
  [OT-NNN] Finding Title
    Severity: Critical|High|Medium|Low
    Affected Assets: [list]
    IEC 62443 Reference: [section]
    NIST 800-82r3 Reference: [section]
    Description: [technical detail]
    Impact: [operational and safety impact]
    Remediation: [specific technical remediation steps]
```
