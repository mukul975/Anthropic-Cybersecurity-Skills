---
name: performing-log-analysis-for-forensic-investigation
description: Collect, parse, and correlate system, application, and security logs to reconstruct events and establish timelines during forensic investigations.
domain: cybersecurity
subdomain: digital-forensics
tags: [forensics, log-analysis, siem, event-correlation, timeline-analysis, evidence-collection]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Log Analysis for Forensic Investigation

## When to Use
- When reconstructing the timeline of a security incident from available log sources
- During post-breach investigation to identify initial access, lateral movement, and exfiltration
- When correlating events across multiple systems and log sources
- For establishing evidence of unauthorized access or policy violations
- When preparing forensic reports requiring detailed event chronology

## Prerequisites
- Access to collected log files (Windows Event Logs, syslog, application logs)
- Log parsing tools (LogParser, jq, awk, or ELK stack)
- Understanding of log formats (EVTX, syslog, JSON, CSV)
- NTP-synchronized timestamps across all log sources for correlation
- Sufficient storage for log aggregation and indexing
- Timeline analysis tools (log2timeline, Plaso)

## Workflow

### Step 1: Collect and Preserve Log Sources

```bash
# Create case log directory structure
mkdir -p /cases/case-2024-001/logs/{windows,linux,network,application,web}

# Extract Windows Event Logs from forensic image
cp /mnt/evidence/Windows/System32/winevt/Logs/*.evtx /cases/case-2024-001/logs/windows/

# Key Windows Event Logs to collect
# Security.evtx - Authentication, access control, policy changes
# System.evtx - Service starts/stops, driver loads, system errors
# Application.evtx - Application errors and events
# Microsoft-Windows-PowerShell%4Operational.evtx - PowerShell execution
# Microsoft-Windows-Sysmon%4Operational.evtx - Sysmon detailed events
# Microsoft-Windows-TaskScheduler%4Operational.evtx - Scheduled tasks
# Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx - RDP

# Collect Linux logs
cp /mnt/evidence/var/log/auth.log* /cases/case-2024-001/logs/linux/
cp /mnt/evidence/var/log/syslog* /cases/case-2024-001/logs/linux/
cp /mnt/evidence/var/log/kern.log* /cases/case-2024-001/logs/linux/
cp /mnt/evidence/var/log/secure* /cases/case-2024-001/logs/linux/
cp /mnt/evidence/var/log/audit/audit.log* /cases/case-2024-001/logs/linux/

# Collect web server logs
cp /mnt/evidence/var/log/apache2/access.log* /cases/case-2024-001/logs/web/
cp /mnt/evidence/var/log/nginx/access.log* /cases/case-2024-001/logs/web/

# Hash all collected logs for integrity
find /cases/case-2024-001/logs/ -type f -exec sha256sum {} \; > /cases/case-2024-001/logs/log_hashes.txt
```

### Step 2: Parse Windows Event Logs

```bash
# Install python-evtx for EVTX parsing
pip install python-evtx

# Convert EVTX to XML/JSON for analysis
python3 -c "
import Evtx.Evtx as evtx
import json, xml.etree.ElementTree as ET

with evtx.Evtx('/cases/case-2024-001/logs/windows/Security.evtx') as log:
    for record in log.records():
        print(record.xml())
" > /cases/case-2024-001/logs/windows/Security_parsed.xml

# Using evtxexport (libevtx-utils)
sudo apt-get install libevtx-utils
evtxexport /cases/case-2024-001/logs/windows/Security.evtx \
   > /cases/case-2024-001/logs/windows/Security_exported.txt

# Key Security Event IDs to investigate
# 4624 - Successful logon
# 4625 - Failed logon
# 4648 - Logon using explicit credentials (runas, lateral movement)
# 4672 - Special privileges assigned (admin logon)
# 4688 - Process creation (with command line if auditing enabled)
# 4697 - Service installed
# 4698/4702 - Scheduled task created/updated
# 4720 - User account created
# 4732 - Member added to security-enabled local group
# 1102 - Audit log cleared

# Extract specific events with python-evtx
python3 << 'PYEOF'
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

target_events = ['4624', '4625', '4648', '4672', '4688', '4697', '1102']

with evtx.Evtx('/cases/case-2024-001/logs/windows/Security.evtx') as log:
    for record in log.records():
        root = ET.fromstring(record.xml())
        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        event_id = root.find('.//ns:EventID', ns).text
        if event_id in target_events:
            time = root.find('.//ns:TimeCreated', ns).get('SystemTime')
            print(f"[{time}] EventID: {event_id}")
            for data in root.findall('.//ns:Data', ns):
                print(f"  {data.get('Name')}: {data.text}")
            print()
PYEOF
```

### Step 3: Parse and Analyze Linux/Syslog Entries

```bash
# Parse auth.log for SSH and sudo events
grep -E '(sshd|sudo|su\[|passwd|useradd|usermod)' \
   /cases/case-2024-001/logs/linux/auth.log* | \
   sort > /cases/case-2024-001/analysis/auth_events.txt

# Extract failed SSH login attempts
grep 'Failed password' /cases/case-2024-001/logs/linux/auth.log* | \
   awk '{print $1,$2,$3,$9,$11}' | sort | uniq -c | sort -rn \
   > /cases/case-2024-001/analysis/failed_ssh.txt

# Extract successful SSH logins
grep 'Accepted' /cases/case-2024-001/logs/linux/auth.log* | \
   awk '{print $1,$2,$3,$9,$11}' > /cases/case-2024-001/analysis/successful_ssh.txt

# Parse audit logs for file access and command execution
ausearch -if /cases/case-2024-001/logs/linux/audit.log \
   --start 2024-01-15 --end 2024-01-20 \
   -m EXECVE > /cases/case-2024-001/analysis/audit_commands.txt

ausearch -if /cases/case-2024-001/logs/linux/audit.log \
   -m USER_AUTH,USER_LOGIN,USER_CMD \
   > /cases/case-2024-001/analysis/audit_auth.txt

# Parse web access logs for suspicious requests
cat /cases/case-2024-001/logs/web/access.log* | \
   grep -iE '(union.*select|<script|\.\.\/|cmd\.exe|/etc/passwd)' \
   > /cases/case-2024-001/analysis/web_attacks.txt

# Extract unique IP addresses from web logs
awk '{print $1}' /cases/case-2024-001/logs/web/access.log* | \
   sort | uniq -c | sort -rn > /cases/case-2024-001/analysis/web_ips.txt
```

### Step 4: Correlate Events Across Sources

```bash
# Normalize timestamps and merge log sources
python3 << 'PYEOF'
import csv
import datetime
from collections import defaultdict

events = []

# Parse Windows Security events (pre-exported to CSV)
with open('/cases/case-2024-001/analysis/windows_events.csv') as f:
    reader = csv.DictReader(f)
    for row in reader:
        events.append({
            'timestamp': row['TimeCreated'],
            'source': 'Windows-Security',
            'event_id': row['EventID'],
            'description': row['Description'],
            'details': row.get('Details', '')
        })

# Parse Linux auth events
with open('/cases/case-2024-001/analysis/auth_events.txt') as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) >= 6:
            events.append({
                'timestamp': ' '.join(parts[:3]),
                'source': 'Linux-Auth',
                'event_id': parts[4].rstrip(':'),
                'description': ' '.join(parts[5:]),
                'details': ''
            })

# Sort by timestamp
events.sort(key=lambda x: x['timestamp'])

# Write correlated timeline
with open('/cases/case-2024-001/analysis/correlated_timeline.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['timestamp', 'source', 'event_id', 'description', 'details'])
    writer.writeheader()
    writer.writerows(events)

print(f"Total correlated events: {len(events)}")
PYEOF

# Quick correlation: find events within time windows
# Look for lateral movement patterns
grep "4648\|4624.*Type.*3\|4624.*Type.*10" /cases/case-2024-001/analysis/windows_events.csv | \
   sort > /cases/case-2024-001/analysis/lateral_movement.txt
```

### Step 5: Generate Forensic Timeline Report

```bash
# Create structured investigation report
cat << 'REPORT' > /cases/case-2024-001/analysis/log_analysis_report.txt
LOG ANALYSIS FORENSIC REPORT
=============================
Case: 2024-001
Analyst: [Examiner Name]
Date: $(date -u)

LOG SOURCES ANALYZED:
- Windows Security Event Log (Security.evtx) - 245,678 events
- Windows System Event Log (System.evtx) - 45,234 events
- Windows PowerShell Operational - 12,456 events
- Linux auth.log - 34,567 entries
- Apache access.log - 567,890 entries
- Linux audit.log - 89,012 entries

KEY FINDINGS:
1. Initial Access: [timestamp] - Successful RDP login from external IP
2. Privilege Escalation: [timestamp] - New admin account created
3. Lateral Movement: [timestamp] - Pass-the-hash detected across 3 systems
4. Data Exfiltration: [timestamp] - Large data transfer to external IP
5. Log Tampering: [timestamp] - Security event log cleared (Event 1102)

TIMELINE OF EVENTS:
[See correlated_timeline.csv for complete chronology]
REPORT

# Package analysis artifacts
tar -czf /cases/case-2024-001/log_analysis_package.tar.gz \
   /cases/case-2024-001/analysis/
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Event correlation | Linking related events across multiple log sources by time, IP, user, or session |
| Log normalization | Converting diverse log formats into a common schema for unified analysis |
| Timeline analysis | Chronological ordering of events to reconstruct incident sequence |
| Log integrity | Verifying logs have not been tampered with using hashes and chain of custody |
| Logon types | Windows categorization of authentication methods (2=interactive, 3=network, 10=RDP) |
| Audit policy | System configuration determining which events are recorded in logs |
| Log rotation | Automatic archiving of log files that affects evidence availability |
| Anti-forensics | Attacker techniques for clearing or modifying logs to cover tracks |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| python-evtx | Python library for parsing Windows EVTX event log files |
| evtxexport | Command-line EVTX export utility from libevtx |
| LogParser | Microsoft SQL-like query engine for Windows logs |
| ausearch | Linux audit log search utility |
| jq | JSON query tool for parsing structured log formats |
| ELK Stack | Elasticsearch, Logstash, Kibana for log aggregation and visualization |
| Chainsaw | Sigma-based Windows Event Log analysis tool |
| Hayabusa | Fast Windows Event Log forensic timeline generator |

## Common Scenarios

**Scenario 1: Brute Force Attack Detection**
Filter Security.evtx for Event ID 4625 (failed logons), group by source IP and target account, identify patterns of rapid successive failures, find the successful logon (4624) that followed, trace subsequent activity from the compromised account.

**Scenario 2: Insider Threat Investigation**
Collect all log sources from the suspect's workstation and accessed servers, correlate file access events with authentication events, build timeline of data access during non-business hours, identify data transfers to external media or cloud storage.

**Scenario 3: Web Application Compromise**
Parse web server access logs for SQLi, XSS, and path traversal patterns, identify the attack IP and timeline, correlate with application logs for successful exploitation, trace post-exploitation activity through system and auth logs.

**Scenario 4: Ransomware Incident Timeline**
Identify the initial execution through process creation events (4688), trace privilege escalation through service installation (4697), map lateral movement via network logons (4624 Type 3), identify encryption start from file system activity, find the earliest IoC for remediation scoping.

## Output Format

```
Log Analysis Summary:
  Investigation Period: 2024-01-15 00:00 to 2024-01-20 23:59 UTC
  Total Events Analyzed: 894,567
  Log Sources: 6 (3 Windows, 3 Linux)

  Critical Events:
    Failed Logons:       1,234 (from 5 unique IPs)
    Successful Logons:   456 (3 anomalous)
    Account Changes:     12 (1 unauthorized admin creation)
    Process Creations:   8,234 (15 suspicious)
    Log Clearings:       2 (Security log cleared at 2024-01-18 03:00 UTC)
    Service Installs:    3 (1 unknown service)

  Attack Timeline:
    2024-01-15 14:32 - Initial access via RDP brute force
    2024-01-15 14:45 - Admin account "svcbackup" created
    2024-01-16 02:15 - Lateral movement to 3 servers
    2024-01-17 03:00 - Data staging in C:\ProgramData\temp\
    2024-01-18 01:30 - 4.2 GB exfiltrated to 185.x.x.x
    2024-01-18 03:00 - Security logs cleared

  Report: /cases/case-2024-001/analysis/log_analysis_report.txt
```
