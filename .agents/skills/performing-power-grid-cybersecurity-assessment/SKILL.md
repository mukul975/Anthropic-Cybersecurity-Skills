---
name: performing-power-grid-cybersecurity-assessment
description: >
  This skill covers conducting cybersecurity assessments of electric power grid
  infrastructure including generation facilities, transmission substations, distribution
  systems, and energy management system (EMS) control centers. It addresses NERC CIP
  compliance verification, substation automation security, IEC 61850 protocol analysis,
  synchrophasor (PMU) network security, and the unique threat landscape targeting
  power grid operations as demonstrated by Industroyer/CrashOverride and related attacks.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, scada, industrial-control, iec62443, nerc-cip, power-grid, substation]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Performing Power Grid Cybersecurity Assessment

## When to Use

- When conducting periodic cybersecurity assessments of power grid facilities per NERC CIP requirements
- When assessing substation automation systems using IEC 61850 GOOSE and MMS protocols
- When evaluating the security of an Energy Management System (EMS) or SCADA control center
- When assessing synchrophasor (PMU) networks and wide-area monitoring systems
- When preparing for regional entity compliance audits or internal security reviews

**Do not use** for non-BES systems below NERC registration thresholds, for general OT assessment without power grid specifics (see performing-ot-network-security-assessment), or for physical security assessment of generation facilities without cyber scope.

## Prerequisites

- Understanding of electric power grid architecture (generation, transmission, distribution)
- Familiarity with NERC CIP standards and BES Cyber System categorization
- Knowledge of power grid protocols (IEC 61850, IEC 60870-5-104, DNP3, ICCP/TASE.2)
- Passive monitoring tools for substation network traffic analysis
- Access to EMS/SCADA architecture documentation and network diagrams

## Workflow

### Step 1: Map Power Grid Cyber Architecture

Identify and document all cyber systems supporting grid operations including EMS, SCADA, substation automation, and communication infrastructure.

```yaml
# Power Grid Cyber Architecture Assessment
facility_type: "Regional Transmission Organization Control Center"

ems_systems:
  primary_ems:
    vendor: "GE Grid Solutions"
    product: "EMS/SCADA (formerly XA/21)"
    functions:
      - "State estimation"
      - "Automatic generation control (AGC)"
      - "Security-constrained economic dispatch"
      - "Contingency analysis"
    protocols:
      - "ICCP/TASE.2 (inter-control center)"
      - "DNP3 (substation RTU polling)"
      - "IEC 60870-5-104 (substation polling)"

  backup_control_center:
    location: "Geographically diverse backup site"
    sync_method: "Real-time database mirroring"
    switchover_time: "< 5 minutes"

substation_automation:
  count: 145
  system_types:
    - vendor: "ABB"
      product: "RTU560"
      protocol: "DNP3 over TCP/IP"
      count: 85
    - vendor: "SEL"
      product: "SEL-3530 RTAC"
      protocol: "IEC 61850 MMS + GOOSE"
      count: 40
    - vendor: "Siemens"
      product: "SICAM A8000"
      protocol: "IEC 60870-5-104"
      count: 20

  communications:
    primary: "MPLS WAN (carrier-provided)"
    backup: "Licensed microwave radio"
    last_mile: "Fiber optic to substation"

synchrophasor_network:
  pmu_count: 75
  pdc: "GE PDC (Phasor Data Concentrator)"
  communication: "IEEE C37.118.2 over dedicated network"
  data_rate: "30-60 samples per second"
```

### Step 2: Assess Substation Automation Security

Evaluate IEC 61850-based substation automation for protocol security, access controls, and network segmentation.

```python
#!/usr/bin/env python3
"""Power Grid Substation Security Assessor.

Evaluates security of IEC 61850-based substation automation
systems including GOOSE messaging, MMS client/server, and
network architecture.
"""

import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime


@dataclass
class SubstationFinding:
    finding_id: str
    severity: str
    category: str
    title: str
    description: str
    affected_systems: list
    nerc_cip_ref: str
    iec_62351_ref: str
    remediation: str


class SubstationAssessment:
    """Assesses cybersecurity of substation automation systems."""

    def __init__(self, substation_name):
        self.name = substation_name
        self.findings = []
        self.counter = 1

    def assess_iec61850_security(self, config):
        """Assess IEC 61850 protocol security."""

        # GOOSE message authentication
        if not config.get("goose_authentication"):
            self.findings.append(SubstationFinding(
                finding_id=f"SUB-{self.counter:03d}",
                severity="critical",
                category="Protocol Security",
                title="IEC 61850 GOOSE Messages Lack Authentication",
                description=(
                    "GOOSE messages used for protection signaling between IEDs "
                    "are not authenticated. An attacker on the station bus could "
                    "inject false trip/close commands to circuit breakers."
                ),
                affected_systems=config.get("goose_publishers", []),
                nerc_cip_ref="CIP-005-7 R1.5 - ESP internal communications",
                iec_62351_ref="IEC 62351-6 - GOOSE/SV authentication",
                remediation=(
                    "Implement IEC 62351-6 GOOSE authentication using digital "
                    "signatures. Deploy VLAN isolation for GOOSE traffic as interim."
                ),
            ))
            self.counter += 1

        # MMS service access control
        if not config.get("mms_authentication"):
            self.findings.append(SubstationFinding(
                finding_id=f"SUB-{self.counter:03d}",
                severity="high",
                category="Protocol Security",
                title="MMS Client Connections Lack Authentication",
                description=(
                    "MMS (Manufacturing Message Specification) connections to IEDs "
                    "do not require client authentication. Any device on the station "
                    "bus can read/write IED configuration and operate breakers."
                ),
                affected_systems=config.get("mms_servers", []),
                nerc_cip_ref="CIP-007-6 R5 - System Access Controls",
                iec_62351_ref="IEC 62351-4 - MMS security profiles",
                remediation="Enable TLS for MMS connections per IEC 62351-4.",
            ))
            self.counter += 1

        # Station bus segmentation
        if not config.get("station_bus_segmented"):
            self.findings.append(SubstationFinding(
                finding_id=f"SUB-{self.counter:03d}",
                severity="high",
                category="Network Architecture",
                title="Flat Station Bus Network Without Segmentation",
                description=(
                    "Station bus connects all IEDs, HMI, engineering access, "
                    "and WAN gateway on a single VLAN without segmentation."
                ),
                affected_systems=["All station bus devices"],
                nerc_cip_ref="CIP-005-7 R1 - ESP boundary",
                iec_62351_ref="IEC 62351-10 - Security architecture",
                remediation=(
                    "Segment station bus into VLANs: protection IEDs, "
                    "measurement IEDs, station HMI, and WAN gateway."
                ),
            ))
            self.counter += 1

    def assess_remote_access(self, config):
        """Assess remote access security for substations."""
        if config.get("direct_vendor_access"):
            self.findings.append(SubstationFinding(
                finding_id=f"SUB-{self.counter:03d}",
                severity="critical",
                category="Remote Access",
                title="Direct Vendor Remote Access to Substation Without MFA",
                description=(
                    "Vendor support has direct VPN access to substation network "
                    "without traversing an intermediate system or requiring MFA."
                ),
                affected_systems=["Substation WAN gateway"],
                nerc_cip_ref="CIP-005-7 R2 - Remote Access Management",
                iec_62351_ref="IEC 62351-8 - Role-based access control",
                remediation=(
                    "Route vendor access through corporate jump server with MFA. "
                    "Implement session recording per CIP-005-7 R2.4."
                ),
            ))
            self.counter += 1

    def generate_report(self):
        """Generate substation assessment report."""
        report = []
        report.append("=" * 70)
        report.append(f"SUBSTATION CYBERSECURITY ASSESSMENT: {self.name}")
        report.append(f"Date: {datetime.now().isoformat()}")
        report.append("=" * 70)

        for sev in ["critical", "high", "medium", "low"]:
            findings = [f for f in self.findings if f.severity == sev]
            if findings:
                report.append(f"\n--- {sev.upper()} ({len(findings)}) ---")
                for f in findings:
                    report.append(f"  [{f.finding_id}] {f.title}")
                    report.append(f"    {f.description[:100]}...")
                    report.append(f"    NERC CIP: {f.nerc_cip_ref}")
                    report.append(f"    Remediation: {f.remediation[:80]}...")

        return "\n".join(report)


if __name__ == "__main__":
    assessment = SubstationAssessment("Substation Alpha - 345kV")

    assessment.assess_iec61850_security({
        "goose_authentication": False,
        "mms_authentication": False,
        "station_bus_segmented": False,
        "goose_publishers": ["SEL-411L-01", "SEL-411L-02", "SEL-487E-01"],
        "mms_servers": ["SEL-3530-RTAC", "ABB-REF615-01"],
    })

    assessment.assess_remote_access({
        "direct_vendor_access": True,
    })

    print(assessment.generate_report())
```

## Key Concepts

| Term | Definition |
|------|------------|
| IEC 61850 | International standard for communication networks and systems in substations, using GOOSE for protection signaling and MMS for SCADA data |
| GOOSE | Generic Object Oriented Substation Event - multicast protocol for fast peer-to-peer protection signaling between IEDs (< 4ms trip time) |
| MMS | Manufacturing Message Specification - client/server protocol for reading/writing IED data and operating circuit breakers |
| IEC 62351 | Security standard series for power system communication protocols providing authentication and encryption for IEC 61850, DNP3, and IEC 104 |
| ICCP/TASE.2 | Inter-Control Center Communications Protocol for data exchange between control centers of different utilities |
| Synchrophasor (PMU) | Phasor Measurement Unit providing time-synchronized voltage/current measurements at 30-60 samples/second for wide-area monitoring |

## Tools & Systems

- **Dragos Platform**: OT security platform with specific threat intelligence on power grid-targeting groups (ELECTRUM, KAMACITE)
- **SEL-3620 Ethernet Security Gateway**: Substation security device providing encryption, access control, and intrusion detection
- **GRIDsure**: Power grid cybersecurity assessment framework by Idaho National Laboratory
- **Wireshark with IEC 61850 Dissector**: Protocol analysis for GOOSE and MMS traffic in substations

## Output Format

```
Power Grid Cybersecurity Assessment Report
=============================================
Facility: [Name and Type]
NERC Registration: [Entity ID]
BES Impact Rating: [High/Medium/Low]

SUBSTATION FINDINGS: [N]
EMS/SCADA FINDINGS: [N]
COMMUNICATION FINDINGS: [N]

NERC CIP COMPLIANCE:
  CIP-002: [Status]
  CIP-005: [Status]
  CIP-007: [Status]
```
