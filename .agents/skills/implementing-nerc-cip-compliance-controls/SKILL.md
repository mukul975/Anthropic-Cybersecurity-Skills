---
name: implementing-nerc-cip-compliance-controls
description: >
  This skill covers implementing North American Electric Reliability Corporation
  Critical Infrastructure Protection (NERC CIP) compliance controls for Bulk Electric
  System (BES) cyber systems. It addresses asset categorization (CIP-002), electronic
  security perimeters (CIP-005), system security management (CIP-007), configuration
  management (CIP-010), supply chain risk management (CIP-013), and the 2025 updates
  including mandatory MFA for remote access and expanded low-impact asset requirements.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, scada, industrial-control, iec62443, nerc-cip, power-grid, compliance]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Implementing NERC CIP Compliance Controls

## When to Use

- When a registered entity must achieve or maintain NERC CIP compliance for BES cyber systems
- When preparing for a NERC CIP compliance audit by the Regional Entity
- When implementing the 2025 CIP standard updates (CIP-003-9, CIP-005-7, CIP-010-4, CIP-013-2)
- When categorizing BES cyber systems after commissioning new generation, transmission, or control center assets
- When developing a compliance monitoring and evidence collection program

**Do not use** for non-BES industrial systems (see implementing-iec-62443-security-zones), for general IT compliance frameworks (see auditing-cloud-with-cis-benchmarks), or for physical security of substations without cyber components.

## Prerequisites

- Understanding of NERC CIP standards (CIP-002 through CIP-014)
- BES cyber system inventory with impact ratings (high, medium, low)
- Access to Electronic Security Perimeter (ESP) network diagrams and firewall configurations
- Compliance management system for evidence collection and audit documentation
- Familiarity with NERC Glossary of Terms (BES Cyber Asset, BES Cyber System, Electronic Access Point)

## Workflow

### Step 1: Categorize BES Cyber Systems (CIP-002-5.1a)

Identify and categorize all BES cyber systems based on their impact to the reliable operation of the Bulk Electric System.

```python
#!/usr/bin/env python3
"""NERC CIP BES Cyber System Categorization Tool.

Implements CIP-002-5.1a categorization criteria to classify
BES cyber systems as high, medium, or low impact.
"""

import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime


@dataclass
class BESCyberSystem:
    """Represents a BES Cyber System for CIP-002 categorization."""
    system_id: str
    name: str
    description: str
    location: str
    asset_type: str  # control_center, generation, transmission, distribution
    connected_mw: float = 0
    transmission_kv: float = 0
    is_control_center: bool = False
    is_backup_control_center: bool = False
    has_cranking_path: bool = False
    has_blackstart: bool = False
    is_sps_ras: bool = False  # Special Protection System / Remedial Action Scheme
    impact_rating: str = ""  # high, medium, low
    categorization_basis: str = ""
    cyber_assets: list = field(default_factory=list)


class CIP002Categorizer:
    """NERC CIP-002-5.1a BES Cyber System categorization engine."""

    def __init__(self):
        self.systems = []
        self.categorization_date = datetime.now().isoformat()

    def add_system(self, system: BESCyberSystem):
        self.systems.append(system)

    def categorize_all(self):
        """Apply CIP-002 Attachment 1 criteria to all systems."""
        for system in self.systems:
            self._categorize_system(system)

    def _categorize_system(self, sys):
        """Apply high, medium, low impact criteria per CIP-002 Attachment 1."""

        # HIGH IMPACT criteria (CIP-002 Attachment 1, Criterion 1)
        if sys.is_control_center and sys.asset_type == "control_center":
            # Control Centers that perform the functional obligations
            # of a Reliability Coordinator, Balancing Authority, or TOP
            sys.impact_rating = "high"
            sys.categorization_basis = (
                "CIP-002 Att.1 Criterion 1.1: Control Center performing "
                "RC/BA/TOP functional obligations"
            )
            return

        if sys.is_backup_control_center and sys.asset_type == "control_center":
            sys.impact_rating = "high"
            sys.categorization_basis = (
                "CIP-002 Att.1 Criterion 1.2: Backup Control Center performing "
                "RC/BA/TOP functional obligations"
            )
            return

        if sys.connected_mw >= 3000:
            sys.impact_rating = "high"
            sys.categorization_basis = (
                f"CIP-002 Att.1 Criterion 1.3: Generation >= 3000 MW "
                f"(actual: {sys.connected_mw} MW)"
            )
            return

        # MEDIUM IMPACT criteria (CIP-002 Attachment 1, Criterion 2)
        if sys.connected_mw >= 1500 and sys.asset_type == "generation":
            sys.impact_rating = "medium"
            sys.categorization_basis = (
                f"CIP-002 Att.1 Criterion 2.1: Generation >= 1500 MW "
                f"(actual: {sys.connected_mw} MW)"
            )
            return

        if sys.transmission_kv >= 500:
            sys.impact_rating = "medium"
            sys.categorization_basis = (
                f"CIP-002 Att.1 Criterion 2.5: Transmission >= 500 kV "
                f"(actual: {sys.transmission_kv} kV)"
            )
            return

        if sys.has_cranking_path:
            sys.impact_rating = "medium"
            sys.categorization_basis = (
                "CIP-002 Att.1 Criterion 2.6: Cranking path element"
            )
            return

        if sys.has_blackstart:
            sys.impact_rating = "medium"
            sys.categorization_basis = (
                "CIP-002 Att.1 Criterion 2.7: Blackstart resource"
            )
            return

        if sys.is_sps_ras:
            sys.impact_rating = "medium"
            sys.categorization_basis = (
                "CIP-002 Att.1 Criterion 2.9: SPS/RAS component"
            )
            return

        if sys.is_control_center and sys.asset_type == "generation":
            sys.impact_rating = "medium"
            sys.categorization_basis = (
                "CIP-002 Att.1 Criterion 2.11: Generation control center "
                "for medium impact generation"
            )
            return

        # LOW IMPACT - all other BES Cyber Systems
        sys.impact_rating = "low"
        sys.categorization_basis = (
            "CIP-002 Att.1 Criterion 3: BES Cyber System not meeting "
            "high or medium impact criteria"
        )

    def generate_report(self):
        """Generate CIP-002 categorization report."""
        high = [s for s in self.systems if s.impact_rating == "high"]
        medium = [s for s in self.systems if s.impact_rating == "medium"]
        low = [s for s in self.systems if s.impact_rating == "low"]

        report = []
        report.append("=" * 70)
        report.append("NERC CIP-002-5.1a BES CYBER SYSTEM CATEGORIZATION")
        report.append(f"Date: {self.categorization_date}")
        report.append("=" * 70)
        report.append(f"\nTotal BES Cyber Systems: {len(self.systems)}")
        report.append(f"  High Impact: {len(high)}")
        report.append(f"  Medium Impact: {len(medium)}")
        report.append(f"  Low Impact: {len(low)}")

        for category, systems in [("HIGH", high), ("MEDIUM", medium), ("LOW", low)]:
            if systems:
                report.append(f"\n--- {category} IMPACT SYSTEMS ---")
                for s in systems:
                    report.append(f"  [{s.system_id}] {s.name}")
                    report.append(f"    Location: {s.location}")
                    report.append(f"    Type: {s.asset_type}")
                    report.append(f"    Basis: {s.categorization_basis}")
                    report.append(f"    Cyber Assets: {len(s.cyber_assets)}")

        return "\n".join(report)

    def export_json(self, output_file):
        """Export categorization to JSON for compliance evidence."""
        data = {
            "categorization_date": self.categorization_date,
            "standard": "CIP-002-5.1a",
            "systems": [asdict(s) for s in self.systems],
        }
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)


if __name__ == "__main__":
    categorizer = CIP002Categorizer()

    # Example BES Cyber Systems
    categorizer.add_system(BESCyberSystem(
        system_id="BCS-001", name="Main Energy Control Center EMS",
        description="Energy Management System for BA operations",
        location="Control Center Alpha", asset_type="control_center",
        is_control_center=True))

    categorizer.add_system(BESCyberSystem(
        system_id="BCS-002", name="Wind Farm SCADA",
        description="SCADA for 500MW wind generation facility",
        location="Wind Farm Delta", asset_type="generation",
        connected_mw=500))

    categorizer.add_system(BESCyberSystem(
        system_id="BCS-003", name="Substation Alpha RTU",
        description="345kV transmission substation",
        location="Substation Alpha", asset_type="transmission",
        transmission_kv=345))

    categorizer.categorize_all()
    print(categorizer.generate_report())
```

### Step 2: Implement Electronic Security Perimeters (CIP-005-7)

Define and enforce Electronic Security Perimeters (ESP) around high and medium impact BES cyber systems with Electronic Access Points (EAP) at all boundary crossing points.

```bash
# Electronic Security Perimeter - Firewall Configuration
# CIP-005-7 R1: Electronic Security Perimeter

# Define ESP boundary for Control Center EMS (High Impact)
# All BES Cyber Assets within the ESP boundary

# Palo Alto PA-3260 - ESP Boundary Firewall

# Inbound rules - strictly limit what enters the ESP
# CIP-005-7 R1.3: All inbound/outbound access permissions documented

# Allow ICCP (Inter-Control Center Communications Protocol) from neighbor BA
set rulebase security rules ICCP-Inbound from Corporate-Zone to ESP-Zone
set rulebase security rules ICCP-Inbound source 192.168.100.10
set rulebase security rules ICCP-Inbound destination 10.20.1.50
set rulebase security rules ICCP-Inbound application iccp
set rulebase security rules ICCP-Inbound service application-default
set rulebase security rules ICCP-Inbound action allow
set rulebase security rules ICCP-Inbound log-setting CIP-Audit-Log

# Allow NTP for time synchronization (CIP-007 R5.7)
set rulebase security rules NTP-Inbound from Corporate-Zone to ESP-Zone
set rulebase security rules NTP-Inbound source 192.168.100.1
set rulebase security rules NTP-Inbound destination 10.20.1.1
set rulebase security rules NTP-Inbound application ntp
set rulebase security rules NTP-Inbound action allow

# CIP-005-7 R2: Remote Access Management
# Require Intermediate System for all remote access sessions
# CIP-005-7 R2.4: Multi-factor authentication required (2025 update)

set rulebase security rules RemoteAccess from External to DMZ-Zone
set rulebase security rules RemoteAccess destination 172.16.1.10
set rulebase security rules RemoteAccess application ssl-vpn
set rulebase security rules RemoteAccess action allow
# MFA enforced on Intermediate System (jump server)

# Default deny all other traffic
set rulebase security rules ESP-Default-Deny from any to ESP-Zone
set rulebase security rules ESP-Default-Deny action deny
set rulebase security rules ESP-Default-Deny log-setting CIP-Audit-Log
```

### Step 3: Implement System Security Management (CIP-007-6)

Configure security controls for BES cyber assets including port management, security patching, malicious code prevention, and security event monitoring.

```yaml
# CIP-007-6 Implementation Checklist

cip_007_controls:
  R1_ports_services:
    description: "Ports and Services Management"
    requirements:
      - "Disable or restrict all unnecessary physical ports (USB, serial)"
      - "Disable all unnecessary logical ports and services"
      - "Document all enabled ports/services with business justification"
    implementation:
      windows_servers: |
        # Disable unnecessary services on Windows BES Cyber Assets
        Set-Service -Name "RemoteRegistry" -StartupType Disabled
        Set-Service -Name "WinRM" -StartupType Disabled
        Set-Service -Name "Spooler" -StartupType Disabled
        # Disable USB storage via Group Policy
        # Computer Config > Admin Templates > System > Removable Storage Access
      linux_servers: |
        # Disable unnecessary services
        systemctl disable cups bluetooth avahi-daemon
        systemctl mask cups bluetooth avahi-daemon
        # Disable USB storage
        echo "blacklist usb-storage" > /etc/modprobe.d/disable-usb.conf

  R2_security_patches:
    description: "Security Patch Management"
    requirements:
      - "Track security patches for all BES Cyber Systems"
      - "Evaluate patches within 35 days of availability"
      - "Apply patches or document mitigation plan"
      - "Test patches in non-production before deployment"
    implementation:
      tracking: "Use WSUS/SCCM for Windows; yum/dnf for Linux"
      testing: "Maintain staging environment mirroring production"
      evidence: "Document patch evaluation in compliance tracking system"

  R3_malicious_code:
    description: "Malicious Code Prevention"
    requirements:
      - "Deploy anti-malware on all applicable BES Cyber Assets"
      - "Update signatures or use application allowlisting"
      - "Mitigate threats from transient cyber assets"
    implementation:
      servers: "CrowdFalcon or Carbon Black with OT-optimized policy"
      hmi_stations: "Application allowlisting (Carbon Black App Control)"
      transient_devices: "Scan all removable media before connection to BCA"

  R4_security_event_monitoring:
    description: "Security Event Monitoring"
    requirements:
      - "Log security events on all high/medium impact BCS"
      - "Generate alerts for detected security events"
      - "Retain logs for minimum 90 days (CIP-007-6 R4.3)"
      - "Review logs at minimum every 15 days"
    implementation:
      siem: "Splunk Enterprise Security with CIP content pack"
      log_sources:
        - "ESP boundary firewall logs"
        - "EAP authentication logs"
        - "BES Cyber Asset authentication success/failure"
        - "Remote access session logs"
        - "Malicious code detection events"
      retention: "90 days online, 3 years archived"

  R5_system_access:
    description: "System Access Control"
    requirements:
      - "Enforce authentication for all interactive access"
      - "Implement least-privilege access control"
      - "Change default passwords"
      - "Enforce password complexity (CIP-007-6 R5.5)"
      - "Limit unsuccessful login attempts"
    implementation:
      password_policy:
        min_length: 8
        complexity: "Mixed case + numbers + special characters"
        max_age_days: 365
        lockout_threshold: 5
        lockout_duration_minutes: 30
      shared_accounts: "Document all shared/service accounts with authorization"
```

## Key Concepts

| Term | Definition |
|------|------------|
| BES Cyber System | Group of one or more BES Cyber Assets that perform a reliability function for the Bulk Electric System |
| Electronic Security Perimeter (ESP) | Logical border surrounding a network containing BES Cyber Systems, with all traffic flowing through Electronic Access Points |
| Electronic Access Point (EAP) | Interface on the ESP boundary that controls traffic flowing in and out of the ESP |
| Intermediate System | System used for remote access that prevents direct connectivity to BES Cyber Assets (jump server) |
| Transient Cyber Asset | Device that is directly connected to a BES Cyber System for less than 30 consecutive calendar days (laptops, USB drives) |
| NERC Glossary | Official definitions used in CIP standards; precise terminology required for compliance |

## Tools & Systems

- **Tripwire Enterprise**: Configuration compliance monitoring and file integrity monitoring for CIP-010 baseline management
- **Splunk with CIP Content Pack**: SIEM with pre-built CIP-007 security event monitoring dashboards and alerts
- **Carbon Black App Control**: Application allowlisting for HMI stations and BES cyber assets (CIP-007 R3)
- **Trellix/McAfee ePO**: Endpoint protection with OT-optimized scanning policies for BES cyber assets

## Output Format

```
NERC CIP Compliance Assessment Report
=======================================
Entity: [Registered Entity Name]
Date: YYYY-MM-DD
Standards: CIP-002 through CIP-014

BES CYBER SYSTEM CATEGORIZATION:
  High Impact: [N] systems
  Medium Impact: [N] systems
  Low Impact: [N] systems

COMPLIANCE STATUS BY STANDARD:
  CIP-002: [Compliant/Partial/Non-Compliant]
  CIP-005: [Status] - [N] gaps identified
  CIP-007: [Status] - [N] gaps identified
  CIP-010: [Status] - [N] gaps identified
  CIP-013: [Status] - [N] gaps identified
```
