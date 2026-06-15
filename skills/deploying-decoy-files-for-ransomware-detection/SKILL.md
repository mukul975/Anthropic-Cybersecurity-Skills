---
name: deploying-decoy-files-for-ransomware-detection
description: 'Deploys canary files (honeytokens) across file systems to detect ransomware
  encryption activity in real time. Uses strategically placed decoy documents monitored
  via file integrity monitoring or OS-level watchdogs to trigger alerts when ransomware
  modifies or encrypts them. Activates for requests involving ransomware canary deployment,
  honeyfile setup, deception-based ransomware detection, or file integrity monitoring
  for encryption.

  '
domain: cybersecurity
subdomain: ransomware-defense
tags:
- ransomware
- detection
- canary-files
- honeytokens
- deception
- file-integrity
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
---

# Deploying Decoy Files for Ransomware Detection

## When to Use

- Setting up early-warning detection for ransomware on file servers or endpoints
- Supplementing EDR/AV with a deception-based detection layer that catches unknown ransomware variants
- Creating high-fidelity ransomware alerts that have very low false-positive rates (legitimate users have no reason to touch decoy files)
- Testing ransomware response procedures by validating that canary file modifications trigger the expected alerting pipeline
- Protecting high-value file shares (finance, HR, legal) with tripwire files that indicate unauthorized encryption activity

**Do not use** decoy files as the sole ransomware defense. They are a detection mechanism, not a prevention mechanism, and should complement backups, EDR, and access controls.

## Prerequisites

- Python 3.8+ with `watchdog` library for cross-platform file system monitoring
- Administrative access to target file shares or endpoints for canary placement
- File integrity monitoring (FIM) tool or SIEM integration for alert routing
- Understanding of target directory structure to place canaries in high-value locations
- Windows: NTFS change journal or ReadDirectoryChangesW API access
- Linux: inotify support in kernel (standard in modern kernels)

## Workflow

### Step 1: Design Canary File Strategy

Plan file placement for maximum detection coverage:

```
Canary File Placement Strategy:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Naming Convention:
  - Use names that sort FIRST and LAST alphabetically in each directory
  - Ransomware typically enumerates directories A-Z or Z-A
  - Examples: _AAAA_budget_2024.docx, ~zzzz_report_final.xlsx

Placement Locations:
  - Root of every file share (\\server\share\_AAAA_canary.docx)
  - Desktop, Documents, Downloads on each endpoint
  - Department-specific shares (Finance, HR, Legal)
  - Backup staging directories
  - Home directories of high-privilege accounts

File Types:
  - .docx, .xlsx, .pdf (most targeted by ransomware)
  - .sql, .bak (database files, high value)
  - Mix of file types to detect ransomware that targets specific extensions
```

### Step 2: Generate Realistic Canary Files

Create decoy files with realistic content and metadata:

```python
import os
import time

def create_canary_docx(filepath, content="Q4 Financial Summary - Confidential"):
    """Create a realistic .docx canary file using python-docx."""
    from docx import Document
    doc = Document()
    doc.add_heading("Financial Report - CONFIDENTIAL", level=1)
    doc.add_paragraph(content)
    doc.add_paragraph(f"Generated: {time.strftime('%Y-%m-%d')}")
    doc.save(filepath)

def create_canary_txt(filepath):
    """Create a simple text canary with known content for hash verification."""
    content = "CANARY_TOKEN_DO_NOT_MODIFY\n"
    content += f"Created: {time.strftime('%Y-%m-%dT%H:%M:%S')}\n"
    content += "This file is monitored for unauthorized changes.\n"
    with open(filepath, "w") as f:
        f.write(content)
```

### Step 3: Deploy File System Watcher

Monitor canary files for any modification, rename, or deletion:

```python
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class CanaryHandler(FileSystemEventHandler):
    def __init__(self, canary_paths, alert_callback):
        self.canary_paths = set(canary_paths)
        self.alert_callback = alert_callback

    def on_modified(self, event):
        if event.src_path in self.canary_paths:
            self.alert_callback("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if event.src_path in self.canary_paths:
            self.alert_callback("DELETED", event.src_path)

    def on_moved(self, event):
        if event.src_path in self.canary_paths:
            self.alert_callback("RENAMED", event.src_path)
```

### Step 4: Configure Alerting and Response

Define automated responses when canary files are triggered:

```
Alert Response Matrix:
━━━━━━━━━━━━━━━━━━━━━
Event: Canary MODIFIED
  → Severity: CRITICAL
  → Action: Alert SOC, identify modifying process (PID), isolate endpoint

Event: Canary DELETED
  → Severity: HIGH
  → Action: Alert SOC, check for ransomware note in same directory

Event: Canary RENAMED (new extension added)
  → Severity: CRITICAL
  → Action: Alert SOC, check extension against known ransomware extensions
  → Automated: Kill modifying process, disable network interface

Event: Multiple canaries triggered within 60 seconds
  → Severity: EMERGENCY
  → Action: Network-wide isolation, activate incident response plan
```

### Step 5: Validate Detection Coverage

Test that canary files detect actual ransomware behavior:

```bash
# Simulate ransomware encryption (safe test - modifies canary content)
echo "ENCRYPTED_BY_TEST" > /path/to/canary/_AAAA_budget.docx

# Simulate ransomware rename (adds extension)
mv /path/to/canary/report.xlsx /path/to/canary/report.xlsx.locked

# Verify alerts were generated in SIEM/alerting system
```

## Verification

- Confirm all canary files are present and unmodified using stored hash baselines
- Verify that modifying any canary file generates an alert within the expected timeframe (under 30 seconds)
- Test that alert routing to SOC/SIEM is functional with a controlled modification
- Validate that automated response actions (process kill, network isolation) execute correctly
- Check that canary files survive normal backup and restore operations
- Ensure legitimate users and processes are excluded from false-positive alerts (backup agents, AV scans)

## Key Concepts

| Term | Definition |
|------|------------|
| **Canary File** | A decoy file placed in a directory that is monitored for any access or modification, serving as a tripwire for unauthorized activity |
| **Honeytoken** | A broader category of deception artifacts (files, credentials, database records) designed to alert when accessed |
| **File Integrity Monitoring** | Continuous monitoring of file attributes (hash, size, permissions, timestamps) to detect unauthorized changes |
| **ReadDirectoryChangesW** | Windows API for monitoring file system changes in a directory; used by the watchdog library on Windows |
| **inotify** | Linux kernel subsystem for monitoring file system events; provides near-instant notification of file changes |

## Tools & Systems

- **watchdog (Python)**: Cross-platform file system event monitoring library supporting Windows, Linux, and macOS
- **Canarytokens (Thinkst)**: Free hosted service for generating various types of canary tokens including files, URLs, and DNS tokens
- **OSSEC/Wazuh**: Open-source HIDS with built-in file integrity monitoring and alerting capabilities
- **Elastic Endpoint**: Uses canary files internally for ransomware protection and key capture
- **Sysmon**: Windows system monitor that logs file creation events (Event ID 11) for canary file monitoring
