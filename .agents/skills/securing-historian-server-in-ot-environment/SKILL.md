---
name: securing-historian-server-in-ot-environment
description: >
  This skill covers hardening and securing process historian servers (OSIsoft PI,
  Honeywell PHD, GE Proficy, AVEVA Historian) in OT environments. It addresses
  network placement across Purdue levels, access control for historian interfaces,
  data replication through DMZ using data diodes or PI-to-PI connectors, SQL
  injection prevention in historian queries, and integrity protection of process
  data used for safety analysis, regulatory reporting, and process optimization.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, scada, industrial-control, iec62443, historian, osisoft-pi, data-integrity]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Securing Historian Server in OT Environment

## When to Use

- When deploying a new historian server in an OT environment and configuring it securely from the start
- When hardening an existing historian after a security assessment identified it as a high-risk target
- When designing historian data replication architecture through a DMZ for IT access to process data
- When implementing access controls to prevent unauthorized modification of historical process data
- When investigating suspected historian compromise or data integrity issues

**Do not use** for IT-only database security without OT data (see general database hardening), for real-time SCADA data transmission security (see detecting-attacks-on-scada-systems), or for historian selection and sizing decisions.

## Prerequisites

- Historian platform (OSIsoft PI, Honeywell PHD, GE Proficy, AVEVA Historian) installed and operational
- Network segmentation with historian placed in Level 3 (Site Operations) per Purdue Model
- Understanding of data flows: field devices -> PLCs -> OPC servers -> historian
- Access to historian administration credentials
- DMZ infrastructure for IT-facing data replication

## Workflow

### Step 1: Audit Current Historian Security Configuration

Evaluate the current security posture of the historian server including network exposure, authentication, and access controls.

```python
#!/usr/bin/env python3
"""Historian Security Audit Tool.

Evaluates the security configuration of process historian servers
including network exposure, authentication, access controls,
and data integrity protections.
"""

import json
import socket
import ssl
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime


@dataclass
class AuditFinding:
    finding_id: str
    severity: str
    category: str
    title: str
    detail: str
    remediation: str


class HistorianSecurityAudit:
    """Security audit for OT historian servers."""

    def __init__(self, historian_ip, historian_type="PI"):
        self.ip = historian_ip
        self.type = historian_type
        self.findings = []
        self.counter = 1

    def check_network_exposure(self):
        """Check which network services are exposed by the historian."""
        print(f"[*] Checking network exposure: {self.ip}")

        # Common historian ports
        ports_to_check = {
            5450: ("PI Data Archive", "PI SDK/API connections"),
            5457: ("PI AF Server", "PI Asset Framework"),
            5459: ("PI Notifications", "PI Notification Service"),
            443: ("HTTPS", "PI Vision / Web API"),
            80: ("HTTP", "Unsecured web interface"),
            1433: ("MS SQL Server", "Direct database access"),
            5432: ("PostgreSQL", "Direct database access"),
            3389: ("RDP", "Remote Desktop"),
            135: ("RPC", "Windows RPC"),
            445: ("SMB", "Windows File Sharing"),
            8080: ("HTTP Alt", "Alternative web interface"),
        }

        exposed = []
        for port, (service, desc) in ports_to_check.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((self.ip, port))
                sock.close()
                if result == 0:
                    exposed.append({"port": port, "service": service, "description": desc})
            except Exception:
                pass

        # Flag unnecessary exposed services
        for svc in exposed:
            if svc["port"] in (80, 135, 445, 3389):
                self.findings.append(AuditFinding(
                    finding_id=f"HIST-{self.counter:03d}",
                    severity="high",
                    category="Network Exposure",
                    title=f"Unnecessary service exposed: {svc['service']} (port {svc['port']})",
                    detail=f"Port {svc['port']} ({svc['description']}) is accessible on historian",
                    remediation=f"Disable {svc['service']} or restrict via host firewall",
                ))
                self.counter += 1

        if any(s["port"] == 80 for s in exposed):
            self.findings.append(AuditFinding(
                finding_id=f"HIST-{self.counter:03d}",
                severity="high",
                category="Encryption",
                title="Historian web interface on unencrypted HTTP",
                detail="Port 80 (HTTP) is open, exposing credentials and data in cleartext",
                remediation="Redirect HTTP to HTTPS; disable port 80",
            ))
            self.counter += 1

        return exposed

    def check_authentication(self):
        """Check historian authentication configuration."""
        print(f"[*] Checking authentication configuration")

        # Check if PI Trust authentication is still enabled (legacy, insecure)
        # PI Trust allows IP-based authentication without credentials
        checks = [
            {
                "check": "PI Trust Authentication",
                "risk": "PI Trust allows connections based on IP address alone without credentials",
                "severity": "critical",
                "remediation": "Migrate all PI Trust connections to Windows Integrated Security",
            },
            {
                "check": "Default piadmin account",
                "risk": "Default PI administrator account may have default or weak password",
                "severity": "critical",
                "remediation": "Disable piadmin; use named Windows accounts with PI mappings",
            },
            {
                "check": "PI SDK anonymous access",
                "risk": "Anonymous PI SDK connections may be permitted",
                "severity": "high",
                "remediation": "Require authentication for all PI SDK connections",
            },
        ]

        for check in checks:
            self.findings.append(AuditFinding(
                finding_id=f"HIST-{self.counter:03d}",
                severity=check["severity"],
                category="Authentication",
                title=f"Check: {check['check']}",
                detail=check["risk"],
                remediation=check["remediation"],
            ))
            self.counter += 1

    def check_data_integrity(self):
        """Check data integrity protections."""
        print(f"[*] Checking data integrity protections")

        integrity_checks = [
            AuditFinding(
                finding_id=f"HIST-{self.counter:03d}",
                severity="high",
                category="Data Integrity",
                title="Verify historical data modification audit trail",
                detail="Modifications to historical process data should be logged with before/after values",
                remediation="Enable PI audit trail for all data modifications; restrict edit permissions",
            ),
            AuditFinding(
                finding_id=f"HIST-{self.counter + 1:03d}",
                severity="medium",
                category="Data Integrity",
                title="Verify backup integrity and recovery testing",
                detail="Historian backups should be tested regularly for recovery capability",
                remediation="Implement automated backup verification with quarterly recovery testing",
            ),
        ]
        self.findings.extend(integrity_checks)
        self.counter += len(integrity_checks)

    def generate_report(self):
        """Generate historian security audit report."""
        report = []
        report.append("=" * 70)
        report.append("HISTORIAN SECURITY AUDIT REPORT")
        report.append(f"Target: {self.ip} ({self.type})")
        report.append(f"Date: {datetime.now().isoformat()}")
        report.append("=" * 70)

        for sev in ["critical", "high", "medium", "low"]:
            findings = [f for f in self.findings if f.severity == sev]
            if findings:
                report.append(f"\n--- {sev.upper()} ({len(findings)}) ---")
                for f in findings:
                    report.append(f"  [{f.finding_id}] {f.title}")
                    report.append(f"    {f.detail}")
                    report.append(f"    Fix: {f.remediation}")

        return "\n".join(report)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "10.30.1.50"
    audit = HistorianSecurityAudit(target, "PI")
    audit.check_network_exposure()
    audit.check_authentication()
    audit.check_data_integrity()
    print(audit.generate_report())
```

### Step 2: Harden Historian Server

Apply security hardening based on vendor security guides and IEC 62443 requirements.

```powershell
# OSIsoft PI Server Hardening Script (Windows)
# Based on OSIsoft Security Best Practices Guide

# 1. Disable PI Trust authentication - migrate to Windows Integrated Security
# In PI SMT (System Management Tools):
# Security > Mappings & Trusts > Delete all Trust entries
# Create PI Mappings for Windows groups instead

# 2. Disable the default piadmin account
# In PI SMT: Security > Identities, Users & Groups
# Set piadmin account to disabled

# 3. Configure Windows Firewall for PI Server
New-NetFirewallRule -DisplayName "PI Data Archive" -Direction Inbound `
    -Protocol TCP -LocalPort 5450 -Action Allow `
    -RemoteAddress "10.30.0.0/16","10.20.0.0/16" `
    -Description "Allow PI SDK connections from OT zones only"

New-NetFirewallRule -DisplayName "PI AF Server" -Direction Inbound `
    -Protocol TCP -LocalPort 5457 -Action Allow `
    -RemoteAddress "10.30.0.0/16" `
    -Description "Allow PI AF connections from Operations zone"

New-NetFirewallRule -DisplayName "PI Vision HTTPS" -Direction Inbound `
    -Protocol TCP -LocalPort 443 -Action Allow `
    -RemoteAddress "172.16.0.0/16" `
    -Description "Allow PI Vision HTTPS from DMZ only"

# Block HTTP (force HTTPS)
New-NetFirewallRule -DisplayName "Block HTTP" -Direction Inbound `
    -Protocol TCP -LocalPort 80 -Action Block

# Block RDP from non-authorized sources
New-NetFirewallRule -DisplayName "RDP Restrict" -Direction Inbound `
    -Protocol TCP -LocalPort 3389 -Action Allow `
    -RemoteAddress "10.30.1.100" `
    -Description "Allow RDP from admin jump server only"

# 4. Enable Windows audit policies for CIP-007 compliance
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable

# 5. Configure PI audit trail for data integrity
# In PI SMT: Audit > Enable auditing for security changes
# Enable auditing for: point creation/deletion, data edits, security changes
```

### Step 3: Implement Secure Data Replication to DMZ

Configure historian data replication through the DMZ using PI-to-PI interfaces or data diodes to provide IT access to process data without exposing the OT historian.

```yaml
# Historian DMZ Replication Architecture
#
# OT Historian (Level 3) --> Data Diode --> DMZ Historian (Level 3.5) <-- Enterprise (Level 4)
#
# Key principle: Enterprise users NEVER connect directly to the OT historian.
# Data flows unidirectionally from OT to DMZ.

architecture:
  ot_historian:
    location: "Level 3 - Site Operations"
    server: "PI-OT-01 (10.30.1.50)"
    role: "Primary data collection from OPC servers and PLCs"
    access: "OT operators and engineers only"

  data_diode:
    location: "Between Level 3 and Level 3.5"
    device: "Waterfall Security Unidirectional Gateway"
    direction: "OT -> DMZ (physically enforced one-way)"
    protocol: "PI-to-PI replication protocol"

  dmz_historian:
    location: "Level 3.5 - DMZ"
    server: "PI-DMZ-01 (172.16.1.50)"
    role: "Read-only mirror of OT historian for enterprise access"
    access: "Enterprise users via PI Vision (HTTPS)"
    data_delay: "Near real-time (typically 5-30 second delay)"

  enterprise_access:
    method: "PI Vision web application on DMZ historian"
    authentication: "Windows Integrated Security with MFA"
    protocol: "HTTPS (TLS 1.2+)"
    restrictions:
      - "Read-only access to process data"
      - "No write-back capability to OT historian"
      - "No direct database queries - PI Vision API only"
      - "Session timeout after 30 minutes of inactivity"
```

## Key Concepts

| Term | Definition |
|------|------------|
| Process Historian | Server that collects, stores, and serves time-series process data from industrial control systems at high frequency (sub-second to seconds) |
| PI Trust | Legacy OSIsoft PI authentication method based on IP address/hostname; insecure and should be migrated to Windows Integrated Security |
| Data Diode | Hardware-enforced unidirectional gateway ensuring historian data flows only from OT to DMZ, preventing reverse access |
| PI-to-PI Interface | OSIsoft replication mechanism that synchronizes PI data between servers, used for DMZ data mirroring |
| Audit Trail | Historian feature logging all modifications to historical data with before/after values, user identity, and timestamp |
| Tag Security | Per-tag access control in PI determining which users/applications can read or write specific process data points |

## Tools & Systems

- **OSIsoft PI Server**: Industry-leading process historian by AVEVA (formerly OSIsoft) used in 90%+ of large industrial facilities
- **AVEVA Historian**: Time-series database for process data with SQL-like query interface
- **Waterfall Security**: Hardware data diode for unidirectional historian replication
- **PI Vision**: Web-based visualization tool for PI data, deployed in DMZ for enterprise access

## Output Format

```
Historian Security Assessment Report
=====================================
Historian: [Type and Version]
Server: [Hostname/IP]
Network Zone: [Purdue Level]

AUTHENTICATION:
  PI Trust entries: [N] (should be 0)
  Default accounts: [enabled/disabled]
  Windows auth: [enabled/disabled]

NETWORK EXPOSURE:
  Open ports: [list]
  Unnecessary services: [list]

DATA INTEGRITY:
  Audit trail: [enabled/disabled]
  Backup tested: [date]

DMZ REPLICATION:
  Method: [PI-to-PI / Data Diode / VPN]
  Direction: [Unidirectional / Bidirectional]
```
