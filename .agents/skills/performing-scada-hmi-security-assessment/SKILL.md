---
name: performing-scada-hmi-security-assessment
description: >
  Perform security assessments of SCADA Human-Machine Interface (HMI) systems
  to identify vulnerabilities in web-based HMIs, thin-client configurations,
  authentication mechanisms, and communication channels between HMI and PLCs,
  aligned with IEC 62443 and NIST SP 800-82 guidelines.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, scada, hmi, security-assessment, vulnerability, iec62443, nist-800-82]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing SCADA HMI Security Assessment

## When to Use

- When assessing the security posture of HMI systems in SCADA/DCS environments
- When evaluating web-based HMI interfaces for common web vulnerabilities
- When auditing HMI authentication, authorization, and session management
- When testing communication security between HMIs and PLCs/RTUs
- When preparing for IEC 62443 or NERC CIP compliance assessments

**Do not use** for testing HMIs in active production without a maintenance window and rollback plan, for PLC-level protocol analysis (see performing-s7comm-protocol-security-analysis), or for general web application testing on non-OT systems.

## Prerequisites

- HMI system inventory with vendor, version, and network configuration details
- Lab or test environment mirroring production HMI setup (preferred for active testing)
- Authorization from plant operations for testing during maintenance windows
- NIST SP 800-82 and IEC 62443 security requirements documentation
- Network capture capability on HMI-to-PLC communication segment

## Workflow

### Step 1: Assess HMI Attack Surface

```python
#!/usr/bin/env python3
"""SCADA HMI Security Assessment Tool.

Evaluates HMI security across authentication, communication,
configuration, and web interface categories aligned with
IEC 62443 and NIST SP 800-82 requirements.
"""

import json
import sys
from datetime import datetime
from typing import Dict, List

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)


class HMISecurityAssessment:
    """Performs security assessment of SCADA HMI systems."""

    def __init__(self, hmi_info: dict):
        self.hmi_info = hmi_info
        self.findings = []
        self.checks_run = 0
        self.checks_passed = 0

    def check_authentication(self):
        """Assess HMI authentication mechanisms."""
        checks = [
            {
                "id": "AUTH-01",
                "name": "Password complexity enforcement",
                "iec62443_ref": "ISA-62443-3-3 SR 1.7",
                "description": "HMI must enforce minimum password complexity requirements",
                "test": "Verify minimum length >= 8, complexity rules, history >= 5",
            },
            {
                "id": "AUTH-02",
                "name": "Account lockout policy",
                "iec62443_ref": "ISA-62443-3-3 SR 1.11",
                "description": "HMI must lock accounts after failed login attempts",
                "test": "Verify lockout after 5 failed attempts, lockout duration >= 15 min",
            },
            {
                "id": "AUTH-03",
                "name": "Default credentials changed",
                "iec62443_ref": "ISA-62443-3-3 SR 1.5",
                "description": "All default vendor credentials must be changed",
                "test": "Attempt login with known vendor defaults (admin/admin, operator/operator)",
            },
            {
                "id": "AUTH-04",
                "name": "Role-based access control",
                "iec62443_ref": "ISA-62443-3-3 SR 2.1",
                "description": "HMI must separate operator, engineer, and admin roles",
                "test": "Verify operator role cannot access engineering functions",
            },
            {
                "id": "AUTH-05",
                "name": "Session timeout enforcement",
                "iec62443_ref": "ISA-62443-3-3 SR 1.12",
                "description": "HMI sessions must time out after inactivity",
                "test": "Verify session timeout <= 15 minutes for operator, <= 5 for admin",
            },
            {
                "id": "AUTH-06",
                "name": "Multi-factor authentication for remote access",
                "iec62443_ref": "ISA-62443-3-3 SR 1.13",
                "description": "Remote HMI access requires MFA",
                "test": "Verify MFA is enforced for all non-local HMI connections",
            },
        ]

        print(f"\n--- AUTHENTICATION ASSESSMENT ---")
        for check in checks:
            self.checks_run += 1
            print(f"  [{check['id']}] {check['name']}")
            print(f"    Ref: {check['iec62443_ref']}")
            print(f"    Test: {check['test']}")

    def check_communication_security(self):
        """Assess HMI-to-PLC communication security."""
        checks = [
            {
                "id": "COMM-01",
                "name": "Encrypted HMI-PLC communication",
                "description": "Traffic between HMI and PLCs should use encrypted protocols (OPC UA with TLS)",
                "test": "Capture HMI-PLC traffic and verify encryption (Wireshark TLS handshake)",
            },
            {
                "id": "COMM-02",
                "name": "HMI write command authentication",
                "description": "Write commands from HMI to PLC should be authenticated",
                "test": "Verify that write operations require operator confirmation/authentication",
            },
            {
                "id": "COMM-03",
                "name": "Web HMI uses HTTPS",
                "description": "Web-based HMI interfaces must use TLS 1.2+ with valid certificates",
                "test": "Check TLS version, cipher suites, certificate validity",
            },
            {
                "id": "COMM-04",
                "name": "No cleartext protocols in use",
                "description": "Telnet, FTP, HTTP must not be used for HMI access or management",
                "test": "Port scan HMI for cleartext protocol services",
            },
        ]

        print(f"\n--- COMMUNICATION SECURITY ASSESSMENT ---")
        for check in checks:
            self.checks_run += 1
            print(f"  [{check['id']}] {check['name']}")
            print(f"    Test: {check['test']}")

    def check_web_hmi_security(self):
        """Assess web-based HMI for common web vulnerabilities."""
        hmi_url = self.hmi_info.get("url", "")
        if not hmi_url:
            print(f"\n  [SKIP] No web HMI URL provided")
            return

        checks = [
            {
                "id": "WEB-01",
                "name": "Cross-Site Scripting (XSS)",
                "owasp": "A7:2017",
                "test": "Test input fields with XSS payloads in tag names, alarm messages",
            },
            {
                "id": "WEB-02",
                "name": "Cross-Site Request Forgery (CSRF)",
                "owasp": "A8:2013",
                "test": "Verify CSRF tokens on state-changing operations (setpoint changes)",
            },
            {
                "id": "WEB-03",
                "name": "Insecure Direct Object References",
                "owasp": "A4:2013",
                "test": "Manipulate URL parameters to access other users HMI views",
            },
            {
                "id": "WEB-04",
                "name": "Security Headers",
                "test": "Verify X-Frame-Options, CSP, X-Content-Type-Options headers",
            },
            {
                "id": "WEB-05",
                "name": "Privileged file system access (CVE-2025-0921)",
                "test": "Check Ignition SCADA for privileged file system vulnerability via project files",
            },
        ]

        print(f"\n--- WEB HMI SECURITY ASSESSMENT ---")
        print(f"  Target: {hmi_url}")
        for check in checks:
            self.checks_run += 1
            print(f"  [{check['id']}] {check['name']}")
            print(f"    Test: {check['test']}")

    def check_hardening(self):
        """Assess HMI operating system and application hardening."""
        checks = [
            {
                "id": "HARD-01",
                "name": "OS patch level",
                "test": "Verify HMI OS is patched within SLA (typically 90 days for OT)",
            },
            {
                "id": "HARD-02",
                "name": "Unnecessary services disabled",
                "test": "Verify no unnecessary network services running (RDP if not needed, SMB, etc)",
            },
            {
                "id": "HARD-03",
                "name": "USB port restrictions",
                "test": "Verify USB mass storage is blocked on HMI terminals",
            },
            {
                "id": "HARD-04",
                "name": "Application whitelisting",
                "test": "Verify only authorized HMI applications can execute",
            },
            {
                "id": "HARD-05",
                "name": "Audit logging enabled",
                "test": "Verify operator actions, login events, and setpoint changes are logged",
            },
        ]

        print(f"\n--- HMI HARDENING ASSESSMENT ---")
        for check in checks:
            self.checks_run += 1
            print(f"  [{check['id']}] {check['name']}")
            print(f"    Test: {check['test']}")

    def generate_report(self):
        """Generate assessment report."""
        self.check_authentication()
        self.check_communication_security()
        self.check_web_hmi_security()
        self.check_hardening()

        print(f"\n{'='*70}")
        print("SCADA HMI SECURITY ASSESSMENT SUMMARY")
        print(f"{'='*70}")
        print(f"Date: {datetime.now().isoformat()}")
        print(f"HMI: {self.hmi_info.get('name', 'Unknown')}")
        print(f"Vendor: {self.hmi_info.get('vendor', 'Unknown')}")
        print(f"Version: {self.hmi_info.get('version', 'Unknown')}")
        print(f"Total Checks: {self.checks_run}")
        print(f"Findings: {len(self.findings)}")


if __name__ == "__main__":
    assessment = HMISecurityAssessment(hmi_info={
        "name": "Plant-HMI-01",
        "vendor": "Siemens WinCC",
        "version": "7.5 SP2",
        "ip": "10.10.2.10",
        "url": "https://10.10.2.10:8080",
        "os": "Windows 10 LTSC 2021",
    })
    assessment.generate_report()
```

## Key Concepts

| Term | Definition |
|------|------------|
| HMI | Human-Machine Interface providing operators visual representation and control of industrial processes |
| Web HMI | Browser-based HMI interface accessible via HTTP/HTTPS, subject to standard web vulnerabilities |
| Setpoint | Target value for a process variable that operators can change through the HMI; unauthorized changes can cause process upset |
| Alarm Suppression | Attacker technique of disabling or hiding HMI alarms to mask malicious process manipulation |
| WinCC | Siemens SCADA/HMI software widely deployed in manufacturing and process industries |
| CVE-2025-0921 | Ignition SCADA privileged file system vulnerability exploitable through malicious project uploads |

## Output Format

```
HMI SECURITY ASSESSMENT REPORT
=================================
Date: YYYY-MM-DD
HMI: [name] | Vendor: [vendor] | Version: [version]

FINDINGS BY CATEGORY:
  Authentication: [pass/fail count]
  Communication: [pass/fail count]
  Web Security: [pass/fail count]
  Hardening: [pass/fail count]

CRITICAL FINDINGS:
  1. [finding with remediation]

COMPLIANCE STATUS:
  IEC 62443 SL-T: [target level]
  IEC 62443 SL-A: [achieved level]
```
