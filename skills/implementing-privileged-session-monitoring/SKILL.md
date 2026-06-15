---
name: implementing-privileged-session-monitoring
description: 'Implements privileged session monitoring and recording using Privileged
  Access Management (PAM) solutions, focusing on CyberArk Privileged Session Manager
  (PSM) and open-source alternatives. Covers session recording configuration, keystroke
  logging, real-time monitoring, risk-based session analysis, and compliance audit
  trail generation. Activates for requests involving privileged session recording,
  PAM session monitoring, CyberArk PSM configuration, administrator activity monitoring,
  or compliance session auditing.

  '
domain: cybersecurity
subdomain: identity-access-management
tags:
- PAM
- CyberArk
- PSM
- privileged-session
- session-recording
- session-monitoring
- compliance
version: 1.0.0
author: mahipal
license: Apache-2.0
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
- PR.AA-06
mitre_attack:
- T1078
- T1110
- T1556
- T1098
---

# Implementing Privileged Session Monitoring

## When to Use

- Deploying or configuring session recording for all privileged access to critical servers and databases
- Meeting compliance requirements (PCI-DSS 10.2, SOX, HIPAA, ISO 27001) that mandate privileged activity monitoring
- Investigating an incident where an administrator or third-party vendor may have performed unauthorized actions
- Implementing real-time alerting for high-risk commands executed during privileged sessions
- Establishing a forensic audit trail of all administrative actions on production infrastructure

**Do not use** for monitoring standard user sessions or endpoint activity; use EDR/UBA solutions for general user behavior monitoring. Privileged session monitoring focuses specifically on elevated-access sessions.

## Prerequisites

- CyberArk PAM Self-Hosted or Privilege Cloud deployment with Digital Vault configured
- CyberArk Privileged Session Manager (PSM) or PSM for SSH (PSMP) installed on a hardened Windows/Linux jump server
- Network architecture where all privileged access is routed through the PSM proxy (no direct RDP/SSH to targets)
- PVWA (Password Vault Web Access) deployed and accessible for session review
- Active Directory integration for authenticating PAM users
- Sufficient storage for session recordings (estimate: 50-250 KB per minute for RDP, 5-20 KB per minute for SSH)
- Alternatively for open-source: Teleport, Apache Guacamole with session recording, or `script`/`ttyrec` for Linux

## Workflow

### Step 1: Architecture — Route All Privileged Access Through PSM

Ensure no direct privileged access bypasses the recording proxy:

```
Architecture Overview:

  Admin User ──> PVWA (Web Portal) ──> PSM (Jump Server) ──> Target Server
       │                                     │                     │
       │         Credentials never           │   Session is        │
       │         exposed to admin            │   recorded and      │
       │                                     │   stored in Vault   │
       └── MFA + AD Auth ──────────────────> │                     │
                                              └── RDP/SSH proxy ──>│

Network Controls:
- Firewall: DENY direct RDP (3389) and SSH (22) to target servers from user networks
- Firewall: ALLOW RDP/SSH to target servers ONLY from PSM server IPs
- Firewall: ALLOW PVWA access (443) from admin user networks
- PSM server: Hardened, no internet access, local admin access restricted
```

### Step 2: Configure PSM Connection Components

Define how PSM connects to target systems. In the PVWA administration console:

```
PVWA > Administration > Configuration > Connection Components

For Windows RDP targets:
  Connection Component: PSM-RDP
  Protocol: RDP
  Client Application: mstsc.exe
  Recording Settings:
    Record Sessions: Yes
    Recording Format: AVI (video) + Keystrokes (text)
    Record Windows Titles: Yes

For Linux SSH targets:
  Connection Component: PSM-SSH
  Protocol: SSH
  Client Application: PSM-SecureCRT or PSM-Putty
  Recording Settings:
    Record Sessions: Yes
    Recording Format: AVI + Text commands
    Record Unix Commands: Yes

For Database targets (SQL Server Management Studio):
  Connection Component: PSM-SSMS
  Protocol: Custom
  Client Application: SSMS.exe
  Recording Settings:
    Record Sessions: Yes
    Record SQL Queries: Yes (via keystroke logging)
```

### Step 3: Configure Session Recording Policies

Define recording rules based on risk level and compliance requirements:

```
PVWA > Administration > Platform Management > [Platform] > Session Management

Session Recording Settings:
  Enable Session Recording: Yes
  Recording Type: Record and Save (not just Monitor)

  Keystroke Logging:
    Enable Transcript: Yes
    Enable Window Events: Yes

  Storage:
    Recordings Storage Location: Vault (encrypted, tamper-proof)
    Retention Period: 90 days (adjust per compliance requirement)

    PCI-DSS:  Retain for 1 year, available for 3 months
    SOX:      Retain for 7 years
    HIPAA:    Retain for 6 years

  Compression:
    Enable Recording Compression: Yes
    Compression Level: Medium (balance storage vs. quality)
```

For granular control, configure per-safe recording policies:

```
Safe: Production-Servers-Admin
  Record all sessions: Yes

Safe: Development-Servers
  Record all sessions: No (optional for non-production)

Safe: Third-Party-Vendor-Access
  Record all sessions: Yes
  Enable real-time monitoring: Yes
  Require dual authorization: Yes
```

### Step 4: Enable Real-Time Session Monitoring

Configure live session monitoring for SOC analysts:

```
PVWA > Monitoring > Privileged Session Monitoring

Live Monitoring Dashboard:
  - Active Sessions: Shows all current privileged sessions in real-time
  - Session Details: User, target, duration, risk score
  - Actions Available:
    - Watch: View the session in real-time (read-only)
    - Suspend: Temporarily freeze the session
    - Terminate: Immediately end the session

Configure monitoring alerts in CyberArk Privileged Threat Analytics (PTA):

PTA > Configuration > Security Events

Rule: High-Risk Command Detected
  Trigger: Unix command matches pattern
  Patterns:
    - rm -rf /
    - chmod 777
    - iptables -F
    - useradd
    - passwd root
    - dd if=/dev/
    - wget http* | sh
    - curl * | bash
    - nc -e /bin/sh
    - python -c 'import socket,subprocess'
  Action: Alert SOC + Flag session as high-risk

Rule: Credential Access Attempt
  Trigger: Windows process matches
  Patterns:
    - mimikatz.exe
    - procdump.exe targeting lsass
    - ntdsutil.exe
    - secretsdump
  Action: Terminate session + Alert SOC + Lock account

Rule: Unusual Session Duration
  Trigger: Session duration exceeds 4 hours
  Action: Alert SOC for review
```

### Step 5: Configure Session Review Workflow

Set up the post-session review process for auditors:

```
PVWA > Recordings > Search and Review

Search Filters:
  - Date range
  - Target server
  - User who initiated the session
  - Safe name
  - Session risk score (from PTA)
  - Session duration

Review Workflow:
  1. Auditor opens recorded session in PVWA HTML5 player
  2. Video playback with timeline scrubbing
  3. Keystroke transcript displayed alongside video
  4. Window title log shows which applications were opened
  5. Risk events are highlighted on the timeline with markers
  6. Auditor marks session as: Reviewed-OK, Reviewed-Suspicious, or Requires-Investigation

Fast-Forward Features:
  - Jump to keystrokes (skip idle time)
  - Jump to risk events (flagged by PTA)
  - Text search within keystroke transcript
  - Filter by window title changes
```

### Step 6: Open-Source Alternative — Teleport for Session Recording

For environments without CyberArk, Teleport provides session recording for SSH, RDP, and Kubernetes:

```yaml
# /etc/teleport.yaml - Session recording configuration
teleport:
  nodename: teleport-proxy.corp.internal
  data_dir: /var/lib/teleport

auth_service:
  enabled: yes
  session_recording: "node-sync"  # Record at the node level, sync to auth server

  # Session recording storage (S3 for production)
  audit_sessions_uri: "s3://teleport-session-recordings/sessions?region=us-east-1"

  # Enhanced session recording (captures commands even in nested shells)
  enhanced_recording:
    enabled: true
    command_events: true
    network_events: true
    disk_events: true

ssh_service:
  enabled: yes
  enhanced_recording:
    enabled: true

proxy_service:
  enabled: yes
  web_listen_addr: 0.0.0.0:443
```

Query recorded sessions with `tsh`:

```bash
# List recorded sessions
tsh recordings ls --from=2026-03-15 --to=2026-03-19

# Play back a specific session
tsh play <session-id>

# Export session events as JSON (for SIEM ingestion)
tsh recordings export <session-id> --format=json > session_events.json

# Search for sessions containing specific commands
tsh recordings ls --query='command == "rm -rf"'
```

### Step 7: Forward Session Metadata to SIEM

Send session events and alerts to the SIEM for correlation with other security data:

```
CyberArk PTA Integration:
  SIEM Connector: Syslog (CEF format) or REST API
  Target: Splunk, Microsoft Sentinel, QRadar, or Elastic

Events Forwarded:
  - Session start/stop with user, target, and duration
  - High-risk command detection alerts
  - Session termination events
  - Failed connection attempts
  - Dual-authorization requests and approvals/denials

Syslog Configuration (PTA):
  PTA > Configuration > SIEM Integration
  Protocol: TCP + TLS
  Destination: siem.corp.internal:6514
  Format: CEF (Common Event Format)

Example CEF Event:
  CEF:0|CyberArk|PTA|12.6|HighRiskCommand|High Risk Command Detected|8|
  src=10.1.5.42 suser=admin1 dhost=prod-db-01 cs1=rm -rf /var/log
  cs2=PSM-SSH cs3=Production-Servers-Admin
```

## Key Concepts

| Term | Definition |
|------|------------|
| **PSM (Privileged Session Manager)** | CyberArk component that acts as a proxy/jump server, recording all privileged sessions in video and text format |
| **PSMP (PSM for SSH Proxy)** | Linux-based PSM proxy specifically for SSH, SCP, and SFTP sessions |
| **Connection Component** | CyberArk configuration that defines how PSM launches client applications (RDP, SSH, SSMS) to connect to target systems |
| **Privileged Threat Analytics (PTA)** | CyberArk module that applies behavioral analytics and risk scoring to recorded sessions to detect anomalous activity |
| **Dual Authorization** | Security control requiring two authorized users to approve a privileged session before it is established |
| **Session Isolation** | Architecture principle where administrators never directly connect to targets; all access is proxied through the PAM system |
| **Keystroke Transcript** | Text log of all keystrokes typed during a recorded session, searchable for audit and forensic purposes |
| **Vaulting** | Storing privileged credentials in an encrypted digital vault so they are never exposed to the end user |

## Verification

- [ ] All privileged access to production targets routes through PSM (direct RDP/SSH is blocked by firewall)
- [ ] Session recordings are being stored in the Vault with encryption and tamper protection
- [ ] Keystroke transcripts are captured and searchable for SSH and RDP sessions
- [ ] PTA rules trigger alerts for high-risk commands (test with a benign trigger pattern)
- [ ] Real-time monitoring dashboard shows active sessions with correct metadata
- [ ] Session recordings play back correctly in PVWA HTML5 player with timeline and transcript
- [ ] Storage estimates are validated and retention policies match compliance requirements
- [ ] Dual authorization is enforced for vendor and high-risk target access
- [ ] Session metadata and alerts are forwarding to SIEM and correlating correctly
- [ ] Auditors can search, review, and annotate sessions through the PVWA interface
- [ ] Terminated sessions leave a complete recording up to the point of termination
