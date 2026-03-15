---
name: performing-oil-gas-cybersecurity-assessment
description: >
  This skill covers conducting cybersecurity assessments specific to oil and gas
  facilities including upstream (exploration/production), midstream (pipeline/transport),
  and downstream (refining/distribution) operations. It addresses SCADA systems
  controlling pipeline operations, DCS for refinery process control, safety instrumented
  systems for hazardous processes, remote terminal units at unmanned wellhead sites,
  and compliance with API 1164, TSA Pipeline Security Directives, IEC 62443, and
  NIST Cybersecurity Framework for critical infrastructure.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, scada, industrial-control, iec62443, oil-gas, pipeline-security, api1164]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Performing Oil & Gas Cybersecurity Assessment

## When to Use

- When conducting a cybersecurity assessment of a refinery, pipeline, or production facility
- When preparing for TSA Pipeline Security Directive compliance (SD-01, SD-02)
- When assessing cybersecurity posture against API Standard 1164 (Pipeline SCADA Security)
- When evaluating the security of remote wellhead SCADA systems and satellite communications
- When a merger, acquisition, or regulatory audit requires a comprehensive OT security evaluation

**Do not use** for IT-only corporate network assessments of oil and gas companies, for physical security assessments without a cyber component, or for environmental compliance assessments.

## Prerequisites

- Written authorization from facility management and operations team
- Understanding of oil and gas operations (upstream, midstream, downstream processes)
- Familiarity with API 1164, TSA SD-01/SD-02, IEC 62443, and NIST CSF
- Passive monitoring tools for OT network traffic capture
- Access to network diagrams, SCADA architecture documentation, and safety studies (HAZOP)

## Workflow

### Step 1: Scope Assessment Based on Facility Type

Oil and gas facilities have unique characteristics based on their operational segment that affect the assessment approach.

```yaml
# Oil & Gas Cybersecurity Assessment Scope
facility:
  name: "Gulf Coast Refinery"
  segment: "Downstream"
  capacity: "250,000 barrels per day"
  regulatory: ["TSA SD-02", "API 1164", "IEC 62443", "NIST CSF"]

assessment_areas:
  process_control:
    description: "Refinery DCS and SCADA systems"
    systems:
      - "Honeywell Experion DCS - main process control"
      - "Yokogawa CENTUM VP - hydrocracker unit"
      - "Triconex SIS - emergency shutdown systems"
      - "Allen-Bradley PLCs - utilities and tank farm"
    protocols: ["Modbus/TCP", "OPC UA", "HART", "Foundation Fieldbus"]

  pipeline_scada:
    description: "Pipeline SCADA for crude receipt and product dispatch"
    systems:
      - "ABB RTU560 - pipeline RTUs at pump stations"
      - "GE iFIX SCADA - pipeline control center"
      - "Flow computers - custody transfer metering"
    protocols: ["DNP3", "Modbus RTU over serial", "IEC 60870-5-104"]
    communications: ["Licensed radio", "Leased line", "Satellite (VSAT)"]

  safety_systems:
    description: "Safety Instrumented Systems and fire/gas detection"
    systems:
      - "Schneider Triconex 3008 - process SIS"
      - "Honeywell FSC - fire and gas"
      - "Combustion turbine protection systems"
    criticality: "SIL 2/3 rated - highest priority"

  remote_access:
    description: "Vendor and operator remote access to OT"
    methods:
      - "Citrix-based remote access to SCADA terminals"
      - "VPN to vendor support for DCS maintenance"
      - "Satellite communication to remote pump stations"

  physical_security:
    description: "Physical security integration with cyber"
    systems:
      - "Access control systems (badge readers)"
      - "CCTV with IP network connectivity"
      - "Perimeter intrusion detection"

compliance_mapping:
  tsa_sd_02:
    - "Implement network segmentation between IT and OT"
    - "Develop and maintain a Cybersecurity Implementation Plan (CIP)"
    - "Establish a Cybersecurity Assessment Program"
    - "Report cybersecurity incidents to CISA within 24 hours"
    - "Implement access control measures for critical OT systems"
  api_1164:
    - "Risk-based cybersecurity program for pipeline SCADA"
    - "Asset identification and classification"
    - "Network security and access control"
    - "Personnel security and training"
    - "Incident response and recovery"
```

### Step 2: Assess Pipeline SCADA Security

Pipeline SCADA systems have unique challenges including long-distance communications over untrusted media, unmanned remote sites, and custody transfer integrity requirements.

```python
#!/usr/bin/env python3
"""Pipeline SCADA Security Assessment Tool.

Evaluates security of pipeline SCADA systems against
API 1164 and TSA Pipeline Security Directive requirements.
"""

import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime


@dataclass
class AssessmentFinding:
    finding_id: str
    category: str
    severity: str
    title: str
    description: str
    affected_systems: list
    regulatory_reference: str
    remediation: str
    timeline: str


@dataclass
class ComplianceCheck:
    requirement_id: str
    description: str
    standard: str
    status: str  # compliant, partial, non-compliant
    evidence: str
    gap: str = ""


class PipelineSCADAAssessment:
    """Pipeline SCADA security assessment per API 1164 / TSA SD-02."""

    def __init__(self, facility_name):
        self.facility = facility_name
        self.findings = []
        self.compliance_checks = []
        self.finding_counter = 1

    def assess_network_architecture(self, architecture_data):
        """Evaluate pipeline SCADA network architecture."""
        checks = []

        # TSA SD-02: Network segmentation between IT and OT
        if not architecture_data.get("it_ot_segmentation"):
            self.findings.append(AssessmentFinding(
                finding_id=f"OG-{self.finding_counter:03d}",
                category="Network Architecture",
                severity="critical",
                title="No IT/OT Network Segmentation",
                description=(
                    "Pipeline SCADA network is not segmented from corporate IT. "
                    "An attacker compromising the corporate network could pivot "
                    "directly to pipeline control systems."
                ),
                affected_systems=["Pipeline SCADA servers", "RTU communications"],
                regulatory_reference="TSA SD-02 Section 2.1; API 1164 Section 7",
                remediation="Deploy DMZ with industrial firewall between IT and pipeline SCADA",
                timeline="30 days",
            ))
            self.finding_counter += 1

        # Check for encrypted RTU communications
        if architecture_data.get("rtu_comm_encrypted") is False:
            self.findings.append(AssessmentFinding(
                finding_id=f"OG-{self.finding_counter:03d}",
                category="Communication Security",
                severity="high",
                title="Unencrypted Pipeline RTU Communications",
                description=(
                    "DNP3 communications between control center and remote RTUs "
                    "traverse radio/satellite links without encryption. An attacker "
                    "with radio access could intercept or inject SCADA commands."
                ),
                affected_systems=["Pipeline RTUs", "SCADA master station"],
                regulatory_reference="API 1164 Section 7.3; IEC 62351",
                remediation="Deploy DNP3 Secure Authentication or VPN tunnel for RTU links",
                timeline="90 days",
            ))
            self.finding_counter += 1

        # Check remote pump station physical security
        if not architecture_data.get("remote_site_intrusion_detection"):
            self.findings.append(AssessmentFinding(
                finding_id=f"OG-{self.finding_counter:03d}",
                category="Physical-Cyber Convergence",
                severity="high",
                title="Remote Pump Stations Lack Physical Intrusion Detection",
                description=(
                    "Unmanned pump stations along the pipeline corridor lack physical "
                    "intrusion detection systems. An attacker could gain physical access "
                    "to RTUs and SCADA communication equipment without detection."
                ),
                affected_systems=["Remote pump station RTUs and networking equipment"],
                regulatory_reference="TSA SD-02 Section 2.3; API 1164 Section 10",
                remediation="Install intrusion detection with cellular alerting at remote sites",
                timeline="60 days",
            ))
            self.finding_counter += 1

    def assess_custody_transfer(self, metering_data):
        """Assess security of custody transfer metering systems."""
        if not metering_data.get("flow_computer_auth"):
            self.findings.append(AssessmentFinding(
                finding_id=f"OG-{self.finding_counter:03d}",
                category="Custody Transfer Integrity",
                severity="critical",
                title="Flow Computer Lacks Authentication",
                description=(
                    "Custody transfer flow computers accept unauthenticated Modbus "
                    "commands allowing meter factor and flow calculation parameters "
                    "to be modified. This could enable financial fraud through "
                    "manipulation of custody transfer measurements."
                ),
                affected_systems=["Flow computers at custody transfer points"],
                regulatory_reference="API 1164 Section 8; API MPMS Chapter 21",
                remediation="Implement authenticated access to flow computers; deploy audit logging",
                timeline="45 days",
            ))
            self.finding_counter += 1

    def check_tsa_compliance(self):
        """Evaluate compliance with TSA Pipeline Security Directives."""
        tsa_requirements = [
            ComplianceCheck("TSA-01", "Cybersecurity Coordinator designated",
                           "TSA SD-01", "compliant", "CySec coordinator appointed"),
            ComplianceCheck("TSA-02", "Incident reporting to CISA within 24 hours",
                           "TSA SD-01", "partial", "Process exists but not tested",
                           gap="Need tabletop exercise to validate reporting timeline"),
            ComplianceCheck("TSA-03", "Cybersecurity Implementation Plan",
                           "TSA SD-02", "non-compliant", "No formal CIP exists",
                           gap="Develop and submit CIP to TSA within 90 days"),
            ComplianceCheck("TSA-04", "Network segmentation between IT and OT",
                           "TSA SD-02", "non-compliant", "Flat network observed",
                           gap="Implement DMZ and zone-based segmentation"),
            ComplianceCheck("TSA-05", "Access control for critical OT systems",
                           "TSA SD-02", "partial", "Shared accounts on SCADA",
                           gap="Implement individual accounts with role-based access"),
            ComplianceCheck("TSA-06", "Continuous monitoring and detection",
                           "TSA SD-02", "non-compliant", "No OT IDS deployed",
                           gap="Deploy OT intrusion detection (Dragos/Nozomi/Claroty)"),
            ComplianceCheck("TSA-07", "Patch management for critical systems",
                           "TSA SD-02", "partial", "Ad hoc patching only",
                           gap="Establish formal OT patch management program"),
        ]
        self.compliance_checks.extend(tsa_requirements)

    def generate_report(self):
        """Generate comprehensive assessment report."""
        report = []
        report.append("=" * 70)
        report.append(f"OIL & GAS CYBERSECURITY ASSESSMENT REPORT")
        report.append(f"Facility: {self.facility}")
        report.append(f"Date: {datetime.now().strftime('%Y-%m-%d')}")
        report.append("=" * 70)

        # Findings summary
        report.append(f"\nFINDINGS: {len(self.findings)}")
        for sev in ["critical", "high", "medium", "low"]:
            count = sum(1 for f in self.findings if f.severity == sev)
            if count:
                report.append(f"  {sev.upper()}: {count}")

        for f in self.findings:
            report.append(f"\n  [{f.finding_id}] [{f.severity.upper()}] {f.title}")
            report.append(f"    Category: {f.category}")
            report.append(f"    {f.description}")
            report.append(f"    Regulatory: {f.regulatory_reference}")
            report.append(f"    Remediation: {f.remediation} ({f.timeline})")

        # Compliance summary
        report.append(f"\n{'='*70}")
        report.append("TSA PIPELINE SECURITY DIRECTIVE COMPLIANCE")
        report.append("=" * 70)
        for c in self.compliance_checks:
            icon = "+" if c.status == "compliant" else "~" if c.status == "partial" else "-"
            report.append(f"  [{icon}] {c.requirement_id}: {c.description}")
            report.append(f"      Status: {c.status.upper()}")
            if c.gap:
                report.append(f"      Gap: {c.gap}")

        return "\n".join(report)


if __name__ == "__main__":
    assessment = PipelineSCADAAssessment("Gulf Coast Refinery")

    assessment.assess_network_architecture({
        "it_ot_segmentation": False,
        "rtu_comm_encrypted": False,
        "remote_site_intrusion_detection": False,
    })

    assessment.assess_custody_transfer({
        "flow_computer_auth": False,
    })

    assessment.check_tsa_compliance()
    print(assessment.generate_report())
```

## Key Concepts

| Term | Definition |
|------|------------|
| API 1164 | American Petroleum Institute standard for Pipeline SCADA Security providing a risk-based framework for cybersecurity of pipeline control systems |
| TSA Pipeline Security Directives | Mandatory cybersecurity requirements issued by TSA for pipeline operators including SD-01 (reporting) and SD-02 (implementation) |
| Custody Transfer | Transfer of ownership of petroleum products between parties, requiring metering system integrity to prevent financial fraud |
| DCS | Distributed Control System used in refineries for continuous process control with redundant controllers and operator stations |
| Remote Terminal Unit (RTU) | Field device at remote pipeline sites that collects sensor data and executes control commands, communicating via radio/satellite |
| Safety Integrity Level (SIL) | IEC 61511 rating for safety instrumented functions, with SIL 1-4 defining probability of failure on demand |
| HAZOP | Hazard and Operability Study identifying potential hazards in process design; cybersecurity should be integrated with HAZOP results |

## Tools & Systems

- **Dragos Platform**: OT cybersecurity platform with specific detection for oil and gas threat groups (XENOTIME, KAMACITE, ERYTHRITE)
- **Claroty xDome**: Comprehensive asset discovery and vulnerability management for oil and gas OT environments
- **Nozomi Guardian**: Network monitoring with support for pipeline protocols (DNP3, Modbus, IEC 60870-5-104)
- **Honeywell Forge Cybersecurity**: OT security platform designed for Honeywell DCS environments common in refineries

## Output Format

```
Oil & Gas Cybersecurity Assessment Report
==========================================
Facility: [Name]
Segment: Upstream / Midstream / Downstream
Date: YYYY-MM-DD
Standards: API 1164, TSA SD-02, IEC 62443

FINDINGS:
  Critical: [N]  High: [N]  Medium: [N]  Low: [N]

COMPLIANCE STATUS:
  TSA SD-02: [N]% compliant
  API 1164: [N]% compliant
  IEC 62443: [N]% compliant
```
