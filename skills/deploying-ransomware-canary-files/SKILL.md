---
name: deploying-ransomware-canary-files
description: Deploys and monitors ransomware canary files using Python's watchdog library, placing decoy files mimicking high-value targets (financial records, credentials, database exports) where ransomware enumerates first, and alerting via email, Slack, or syslog on any read/modify/rename/delete. Use when setting up early-warning ransomware canary detection on file servers, NAS, or endpoints, or to supplement EDR where agents can't be deployed. Do not use for honeypot shares, decoy systems, or Thinkst Canary appliances - use implementing-honeypot-for-ransomware-detection.
domain: cybersecurity
subdomain: ransomware-defense
tags:
- ransomware
- canary-files
- watchdog
- detection
- early-warning
- deception
- defense
version: 1.0.0
author: mahipal
license: Apache-2.0
nist_csf:
- PR.DS-11
- RS.MA-01
- RC.RP-01
- PR.IR-01
mitre_attack:
- T1486
- T1083
- T1490
- T1485
mitre_f3:
  version: '1.1'
  tactics:
  - monetization
  techniques:
  - id: F1018
    name: Convert to Cryptocurrency
    tactic: monetization
    source: f3
  - id: F1017
    name: Conversion to Physical Monetary Instruments
    tactic: monetization
    source: f3
  - id: F1025.003
    name: 'Electronic Funds Transfer: Wire Transfer'
    tactic: monetization
    source: f3
---
# Deploying Ransomware Canary Files

## When to Use

- Deploying proactive ransomware detection on file servers, NAS devices, or endpoint systems
- Building an early-warning system that detects ransomware before it encrypts business-critical data
- Supplementing EDR solutions with lightweight canary file monitoring on systems where agents cannot be deployed
- Testing ransomware incident response procedures by simulating canary file triggers
- Monitoring shared drives, home directories, and backup volumes for unauthorized file operations

**Do not use** as a replacement for endpoint protection, backup strategy, or network segmentation. Canary files are a detection layer, not a prevention mechanism.

## Prerequisites

- Python 3.8+ with pip
- watchdog library (pip install watchdog)
- Write access to directories where canary files will be placed
- SMTP server credentials or Slack webhook URL for alerting
- Administrative access for placing canaries in system directories

## Workflow

### Step 1: Generate Canary Files

Create decoy files with realistic names and content that attract ransomware scanners. Files should have names like `Passwords.xlsx`, `Financial_Report_2026.docx`, `backup_credentials.csv` and contain plausible-looking but fake data. Place them in directories ransomware typically targets first: user desktops, Documents folders, network share roots, and backup paths.

### Step 2: Deploy Filesystem Monitor

Use Python's watchdog library with a custom `FileSystemEventHandler` that watches canary file paths. The handler triggers on `on_modified`, `on_deleted`, `on_moved`, and `on_created` events for canary files. Any legitimate user or process should never touch these files, so any interaction is a high-confidence indicator of ransomware or unauthorized access.

### Step 3: Configure Alert Pipeline

Wire the filesystem monitor to multiple alert channels: email via SMTP, Slack webhook POST, syslog forwarding to SIEM, and local log file. Include the triggering event type, file path, timestamp, and process information (when available) in alert payloads.

### Step 4: Validate and Test

Simulate ransomware behavior by programmatically modifying, renaming, and deleting canary files to verify the detection pipeline fires correctly. Measure time-to-alert and validate alert delivery across all configured channels.

## Key Concepts

| Term | Definition |
|------|------------|
| **Canary File** | A decoy file placed in a monitored directory that triggers an alert when accessed, modified, or deleted |
| **Watchdog** | Python library that monitors filesystem events using OS-native APIs (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows) |
| **Honey File** | Synonym for canary file; a fake document designed to attract and detect malicious activity |
| **Entropy Check** | Measuring randomness in file content to detect encryption (ransomware produces high-entropy output) |

## Tools & Systems

- **watchdog**: Python filesystem monitoring library using OS-native event APIs
- **smtplib**: Python standard library for SMTP email alerting
- **requests**: HTTP library for Slack webhook integration
- **hashlib**: SHA-256 hashing for canary file integrity verification
- **psutil**: Process information gathering when canary file access is detected

## Output Format

```
RANSOMWARE CANARY ALERT
========================
Timestamp: 2026-03-11T14:23:07Z
Event: FILE_MODIFIED
Canary File: /srv/shares/finance/Passwords.xlsx
Directory: /srv/shares/finance
SHA-256 Before: a3f2...8b4c
SHA-256 After: 7e91...2d3f
Alert Channels: [email, slack, syslog]
Action: Investigate immediately - potential ransomware activity
```
