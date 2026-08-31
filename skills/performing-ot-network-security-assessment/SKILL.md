---
name: performing-ot-network-security-assessment
description: Conducts comprehensive security assessments of Operational Technology (OT) networks including SCADA systems, DCS architectures, and industrial control system communication paths, addressing Purdue Reference Model layers, identifying IT/OT convergence risks, evaluating firewall rules between zones, and mapping industrial protocol traffic (Modbus, DNP3, OPC UA, EtherNet/IP) to detect misconfigurations, unauthorized connections, and attack surfaces in critical infrastructure. Use when conducting an OT/ICS security assessment, evaluating IT/OT convergence risks, or mapping industrial protocol attack surfaces across Purdue layers. Do not use for implementing Purdue-model network segmentation - use implementing-purdue-model-network-segmentation.
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot-security
- ics
- scada
- industrial-control
- iec62443
- network-assessment
version: 1.0.0
author: mahipal
license: Apache-2.0
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-05
- GV.OC-02
mitre_attack:
- T1078
- T1190
- T1059
- T0816
- T0836
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

See [references/analysis-scripts.md](references/analysis-scripts.md#step-2-ot-network-passive-discovery-and-asset-inventory-builder) for the full passive discovery and asset inventory script (Purdue classification, protocol mapping, cross-zone flow detection).


### Step 3: Evaluate Firewall Rules Between Purdue Zones

Analyze firewall configurations between OT zones to identify overly permissive rules, missing deny defaults, and unauthorized conduits that violate the IEC 62443 zone model.

See [references/analysis-scripts.md](references/analysis-scripts.md#step-3-ot-zone-firewall-rule-analyzer) for the full firewall rule analyzer script (IEC 62443 conduit policy checks).


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
