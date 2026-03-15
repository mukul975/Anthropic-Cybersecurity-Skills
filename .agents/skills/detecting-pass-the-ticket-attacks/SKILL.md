---
name: detecting-pass-the-ticket-attacks
description: Detect Kerberos Pass-the-Ticket (PtT) attacks by analyzing Windows Event IDs 4768, 4769, and 4771 for anomalous ticket usage patterns in Splunk and Elastic SIEM
domain: cybersecurity
subdomain: threat-detection
tags:
  - kerberos
  - pass-the-ticket
  - active-directory
  - splunk
  - elastic
  - credential-theft
  - windows-security
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting Pass-the-Ticket Attacks

## Overview

Pass-the-Ticket (PtT) is a credential theft technique (MITRE ATT&CK T1550.003) where adversaries steal Kerberos tickets (TGT or TGS) from one system and replay them on another to authenticate without knowing the user's password. This skill teaches detection of PtT attacks by correlating Windows Security Event IDs 4768 (TGT request), 4769 (TGS request), and 4771 (pre-authentication failure) for anomalies such as ticket reuse across different hosts, RC4 encryption downgrades, and unusual service ticket request volumes.

## Prerequisites

- Windows Domain Controller with advanced audit policy enabled (Audit Kerberos Authentication Service, Audit Kerberos Service Ticket Operations)
- Splunk or Elastic SIEM ingesting Windows Security event logs
- Sysmon deployed on endpoints for supplementary process telemetry
- Python 3.8+ with `requests` library

## Steps

1. Enable Kerberos audit logging on Domain Controllers via Group Policy
2. Forward Event IDs 4768, 4769, and 4771 to SIEM platform
3. Deploy detection rules for RC4 encryption downgrade (TicketEncryptionType 0x17)
4. Create correlation rule for ticket reuse across multiple source IPs
5. Build baseline of normal TGS request volume per user/host
6. Alert on standard deviation anomalies in ticket request patterns
7. Investigate flagged events with enrichment from Active Directory

## Expected Output

JSON report containing detected PtT indicators including anomalous ticket requests, RC4 downgrades, cross-host ticket reuse events, and risk-scored users with MITRE ATT&CK technique mapping.
