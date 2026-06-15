---
name: detecting-ransomware-encryption-behavior
description: 'Detects ransomware encryption activity in real time using entropy analysis,
  file system I/O monitoring, and behavioral heuristics. Identifies mass file modification
  patterns, abnormal entropy spikes in written data, and suspicious process behavior
  characteristic of ransomware encryption routines. Activates for requests involving
  ransomware behavioral detection, entropy-based file monitoring, I/O anomaly detection,
  or real-time encryption activity alerting.

  '
domain: cybersecurity
subdomain: ransomware-defense
tags:
- ransomware
- detection
- entropy
- behavioral-analysis
- file-monitoring
- heuristics
version: 1.0.0
author: mahipal
license: Apache-2.0
nist_csf:
- PR.DS-11
- RS.MA-01
- RC.RP-01
- PR.IR-01
mitre_attack:
- T1078
- T1190
- T1059
- T1486
- T1490
---

# Detecting Ransomware Encryption Behavior

## When to Use

- Building or tuning a behavioral detection layer for ransomware that catches unknown/zero-day variants
- Monitoring file servers and endpoints for mass encryption activity that evades signature-based detection
- Implementing entropy-based detection to identify when files are being replaced with encrypted (high-entropy) content
- Analyzing suspicious process behavior patterns: rapid sequential file opens, writes, renames, and deletes
- Validating EDR detection rules against actual ransomware encryption patterns during red team exercises

**Do not use** entropy analysis alone as the only detection signal. Compressed files (ZIP, JPEG, MP4) naturally have high entropy and will cause false positives. Always combine entropy with behavioral signals like I/O rate and file rename patterns.

## Prerequisites

- Python 3.8+ with `watchdog` and `psutil` libraries
- Administrative access for process monitoring and file system event capture
- Understanding of Shannon entropy and its application to file content analysis
- Windows: Sysmon installed for detailed process and file system event logging
- Linux: auditd configured for file access monitoring, or inotify-based watchers
- Baseline entropy values for common file types in the monitored environment

## Workflow

### Step 1: Establish Entropy Baselines

Calculate normal entropy ranges for files in the environment:

```
Entropy Baselines by File Type:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
File Type       Normal Entropy    Encrypted Entropy
.docx           3.5 - 6.5        7.8 - 8.0
.xlsx           4.0 - 6.8        7.8 - 8.0
.pdf            5.0 - 7.2        7.8 - 8.0
.txt            2.0 - 5.0        7.8 - 8.0
.csv            2.0 - 5.5        7.8 - 8.0
.sql            2.5 - 5.0        7.8 - 8.0
.jpg/.png       7.0 - 7.9        7.9 - 8.0 (hard to distinguish)
.zip/.7z        7.5 - 8.0        7.9 - 8.0 (hard to distinguish)

Key insight: Text-based files show the largest entropy jump when encrypted,
making them the best candidates for entropy-based detection.
```

### Step 2: Implement Real-Time Entropy Monitoring

Monitor file writes and calculate entropy of new content:

```python
import math
from collections import Counter

def shannon_entropy(data):
    """Calculate Shannon entropy of byte data (0.0 to 8.0 scale)."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

def is_encryption_entropy(data, threshold=7.5):
    """Check if data entropy indicates encryption."""
    entropy = shannon_entropy(data)
    return entropy >= threshold, entropy
```

### Step 3: Monitor File System I/O Patterns

Track process-level file operations for ransomware patterns:

```
Ransomware I/O Behavior Signatures:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Rapid sequential file modification:
   - >20 files modified per minute by single process
   - Read original → Write encrypted → Rename with new extension
   - Pattern: CreateFile → ReadFile → WriteFile → CloseHandle → MoveFile

2. File extension changes:
   - Original: report.docx → Encrypted: report.docx.locked
   - Many extensions changed within short time window

3. Ransom note creation:
   - Same text file (README.txt, DECRYPT.html) created in multiple directories
   - Created immediately after file encryption in each directory

4. Shadow copy deletion:
   - vssadmin.exe delete shadows /all /quiet
   - wmic.exe shadowcopy delete
   - PowerShell: Get-WmiObject Win32_Shadowcopy | Remove-WmiObject

5. Entropy spike pattern:
   - File read: entropy 3.5 (normal document)
   - File write: entropy 7.9 (encrypted content)
   - Delta > 3.0 is strong ransomware indicator
```

### Step 4: Implement Behavioral Scoring

Combine multiple signals into a composite ransomware score:

```python
def calculate_ransomware_score(process_metrics):
    """Score process behavior for ransomware likelihood (0-100)."""
    score = 0

    # High file modification rate
    files_per_min = process_metrics.get("files_modified_per_minute", 0)
    if files_per_min > 50:
        score += 30
    elif files_per_min > 20:
        score += 15

    # Entropy increase in written files
    avg_entropy_delta = process_metrics.get("avg_entropy_delta", 0)
    if avg_entropy_delta > 3.0:
        score += 30
    elif avg_entropy_delta > 2.0:
        score += 15

    # File extension changes
    extension_changes = process_metrics.get("extension_changes", 0)
    if extension_changes > 10:
        score += 20
    elif extension_changes > 3:
        score += 10

    # Ransom note creation
    if process_metrics.get("ransom_note_created", False):
        score += 20

    return min(score, 100)
```

### Step 5: Configure Automated Response Thresholds

Set detection thresholds and automated containment actions:

```
Detection Thresholds:
━━━━━━━━━━━━━━━━━━━━
Score 0-25:   INFORMATIONAL - Log only, no action
Score 25-50:  LOW - Alert SOC for investigation
Score 50-75:  HIGH - Alert SOC, suspend process, snapshot VM
Score 75-100: CRITICAL - Kill process, isolate endpoint, alert IR team

Automated Response Actions:
  - Suspend/kill the encrypting process
  - Disable network adapter to prevent lateral movement
  - Create volume shadow copy snapshot before further damage
  - Capture process memory dump for forensic analysis
  - Send SIEM alert with process details, affected files, and timeline
```

## Verification

- Test detection against known ransomware samples in an isolated sandbox environment
- Verify that entropy monitoring correctly identifies encrypted vs. compressed files
- Confirm that behavioral scoring produces low false-positive rates on normal workloads
- Validate automated response actions execute within acceptable time (under 5 seconds)
- Test with multiple ransomware families (LockBit, BlackCat, Conti) to verify coverage
- Benchmark monitoring overhead to ensure it does not degrade endpoint performance

## Key Concepts

| Term | Definition |
|------|------------|
| **Shannon Entropy** | Mathematical measure of randomness in data (0-8 for bytes); encrypted data approaches 8.0, while text files are typically 2-5 |
| **Differential Entropy** | The change in entropy between a file's original and modified content; a spike indicates encryption |
| **I/O Rate Anomaly** | Abnormally high rate of file read/write operations by a single process, characteristic of bulk encryption |
| **Behavioral Scoring** | Combining multiple weak signals (entropy, I/O rate, file renames) into a composite confidence score |
| **Entropy Evasion** | Techniques used by advanced ransomware to defeat entropy detection, such as Base64 encoding output or partial encryption |

## Tools & Systems

- **Sysmon**: Windows system monitor providing detailed file system and process events for behavioral analysis
- **watchdog (Python)**: Cross-platform file system monitoring library for real-time file change detection
- **psutil (Python)**: Process and system monitoring library for tracking per-process I/O statistics
- **Elastic Endpoint**: Commercial endpoint protection with built-in ransomware behavioral detection using canary files
- **Wazuh**: Open-source security platform with file integrity monitoring and active response capabilities
