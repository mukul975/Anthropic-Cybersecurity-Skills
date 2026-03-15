---
name: analyzing-security-logs-with-splunk
description: >
  Leverages Splunk Enterprise Security and SPL (Search Processing Language) to
  investigate security incidents through log correlation, timeline reconstruction,
  and anomaly detection. Covers Windows event logs, firewall logs, proxy logs, and
  authentication data analysis. Activates for requests involving Splunk investigation,
  SPL queries, SIEM log analysis, security event correlation, or log-based incident
  investigation.
domain: cybersecurity
subdomain: incident-response
tags: [splunk, SPL, SIEM, log-analysis, security-monitoring]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Analyzing Security Logs with Splunk

## When to Use

- Investigating a security incident that requires correlation across multiple log sources
- Hunting for adversary activity using known TTPs and IOCs
- Building detection rules for specific attack patterns
- Reconstructing an incident timeline from disparate log sources
- Analyzing authentication anomalies, lateral movement, or data exfiltration patterns

**Do not use** for real-time packet-level analysis; use Wireshark or Zeek for full packet capture analysis.

## Prerequisites

- Splunk Enterprise or Splunk Cloud with Enterprise Security (ES) app installed
- Log sources ingested: Windows Event Logs (via Splunk Universal Forwarder or WEF), firewall, proxy, DNS, EDR, email gateway
- Splunk CIM (Common Information Model) data models configured for normalized field names
- SPL proficiency at intermediate level or higher
- Role-based access with `search` and `accelerate_search` capabilities in Splunk

## Workflow

### Step 1: Scope the Investigation in Splunk

Define search parameters based on incident triage data:

```spl
| Set initial investigation scope
index=windows OR index=firewall OR index=proxy
  earliest="2025-11-14T00:00:00" latest="2025-11-16T00:00:00"
  (host="WKSTN-042" OR src_ip="10.1.5.42" OR user="jsmith")
| stats count by index, sourcetype, host
| sort -count
```

This query establishes which log sources contain relevant data for the investigation timeframe and affected assets.

### Step 2: Analyze Authentication Events

Investigate suspicious authentication patterns using Windows Security Event Logs:

```spl
| Detect brute force and credential stuffing
index=windows sourcetype="WinEventLog:Security" EventCode=4625
  earliest=-24h
| stats count as failed_attempts, values(src_ip) as source_ips,
  dc(src_ip) as unique_sources by TargetUserName
| where failed_attempts > 10
| sort -failed_attempts

| Detect pass-the-hash (Logon Type 9 - NewCredentials)
index=windows sourcetype="WinEventLog:Security" EventCode=4624
  Logon_Type=9
| table _time, host, TargetUserName, src_ip, LogonProcessName

| Detect lateral movement via RDP
index=windows sourcetype="WinEventLog:Security" EventCode=4624
  Logon_Type=10
| stats count, values(host) as targets by TargetUserName, src_ip
| where count > 3
| sort -count
```

### Step 3: Trace Process Execution

Use Sysmon logs to reconstruct process execution chains:

```spl
| Process creation with parent chain (Sysmon Event ID 1)
index=sysmon EventCode=1 host="WKSTN-042"
  earliest="2025-11-15T14:00:00" latest="2025-11-15T15:00:00"
| table _time, ParentImage, ParentCommandLine, Image, CommandLine, User, Hashes
| sort _time

| Detect suspicious PowerShell execution
index=sysmon EventCode=1 Image="*\\powershell.exe"
  (CommandLine="*-enc*" OR CommandLine="*-encodedcommand*"
   OR CommandLine="*downloadstring*" OR CommandLine="*iex*")
| table _time, host, User, ParentImage, CommandLine
| sort _time

| Detect LSASS credential dumping
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
  GrantedAccess=0x1010
| table _time, host, SourceImage, SourceUser, GrantedAccess
```

### Step 4: Analyze Network Activity

Correlate network logs with endpoint events:

```spl
| Detect C2 beaconing pattern
index=proxy OR index=firewall dest_ip="185.220.101.42"
| timechart span=1m count by src_ip
| where count > 0

| Detect DNS tunneling (high query volume to single domain)
index=dns
| rex field=query "(?<subdomain>[^\.]+)\.(?<domain>[^\.]+\.[^\.]+)$"
| stats count, avg(len(query)) as avg_query_len by domain, src_ip
| where count > 500 AND avg_query_len > 40
| sort -count

| Detect large data transfers (potential exfiltration)
index=proxy action=allowed
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_host
| eval total_MB=round(total_bytes/1024/1024,2)
| where total_MB > 100
| sort -total_MB
```

### Step 5: Build the Incident Timeline

Reconstruct a unified timeline across all log sources:

```spl
| Unified incident timeline
index=windows OR index=sysmon OR index=proxy OR index=firewall
  (host="WKSTN-042" OR src_ip="10.1.5.42" OR user="jsmith")
  earliest="2025-11-15T14:00:00" latest="2025-11-15T16:00:00"
| eval event_summary=case(
    sourcetype=="WinEventLog:Security" AND EventCode==4624, "Logon: ".TargetUserName." from ".src_ip,
    sourcetype=="WinEventLog:Security" AND EventCode==4625, "Failed logon: ".TargetUserName,
    sourcetype=="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" AND EventCode==1,
      "Process: ".Image." by ".User,
    sourcetype=="proxy", "Web: ".http_method." ".url,
    1==1, sourcetype.": ".EventCode)
| table _time, sourcetype, host, event_summary
| sort _time
```

### Step 6: Create Detection Rules

Convert investigation findings into persistent Splunk correlation searches:

```spl
| Correlation search: PowerShell spawned by Office applications
index=sysmon EventCode=1
  Image="*\\powershell.exe"
  (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe"
   OR ParentImage="*\\outlook.exe")
| eval severity="high"
| eval mitre_technique="T1059.001"
| collect index=notable_events
```

## Key Concepts

| Term | Definition |
|------|------------|
| **SPL (Search Processing Language)** | Splunk's query language for searching, filtering, transforming, and visualizing machine data |
| **CIM (Common Information Model)** | Splunk's field normalization standard that maps vendor-specific field names to common names for cross-source queries |
| **Notable Event** | An event in Splunk Enterprise Security flagged for analyst review based on a correlation search match |
| **Data Model** | Structured representation of indexed data in Splunk enabling accelerated searches and pivot-based analysis |
| **Sourcetype** | Classification label in Splunk that defines the format and parsing rules for a specific log type |
| **Correlation Search** | Scheduled Splunk search that runs continuously and generates notable events when conditions are met |
| **Timechart** | SPL command that creates time-series visualizations for identifying patterns, anomalies, and trends |

## Tools & Systems

- **Splunk Enterprise Security (ES)**: Premium SIEM application providing correlation searches, risk-based alerting, and investigation workbench
- **Splunk SOAR**: Orchestration platform integrated with Splunk ES for automated response playbooks
- **Sysmon**: Microsoft system monitoring tool providing detailed process, network, and file change telemetry ingested into Splunk
- **Splunk Attack Analyzer**: Automated threat analysis that detonates suspicious files and URLs, feeding results into Splunk
- **BOSS of the SOC (BOTS)**: SANS/Splunk training dataset for practicing incident investigation SPL queries

## Common Scenarios

### Scenario: Investigating Credential Stuffing Leading to Account Takeover

**Context**: Security operations receives an alert for multiple successful logins to a single account from geographically dispersed IP addresses within a 30-minute window.

**Approach**:
1. Query Event ID 4624 for the affected account to map all login sources and times
2. Correlate login IPs against threat intelligence feeds using a Splunk lookup table
3. Check proxy logs for suspicious activity from the authenticated sessions
4. Search for lateral movement from the compromised account (Event ID 4624 Type 3 to other hosts)
5. Build a timeline showing credential stuffing attempts, successful login, and post-compromise activity
6. Create a correlation search to detect similar patterns on other accounts

**Pitfalls**:
- Searching only the last 24 hours when the credential stuffing may have occurred over weeks
- Not checking for VPN logs that may show the same account authenticating from impossible travel distances
- Failing to normalize timestamps across log sources in different time zones

## Output Format

```
SPLUNK INVESTIGATION REPORT
============================
Incident:        INC-2025-1547
Analyst:         [Name]
Investigation Period: 2025-11-14 00:00 UTC - 2025-11-16 00:00 UTC

SEARCH SCOPE
Indexes:         windows, sysmon, proxy, firewall, dns
Hosts:           WKSTN-042, SRV-FILE01
Users:           jsmith, svc-backup
Source IPs:      10.1.5.42, 10.1.10.15

KEY FINDINGS
1. [timestamp] - Initial compromise via phishing (Sysmon Event 1)
2. [timestamp] - C2 established (proxy logs, beacon pattern detected)
3. [timestamp] - Credential theft (Sysmon Event 10, LSASS access)
4. [timestamp] - Lateral movement to SRV-FILE01 (Event 4624 Type 3)
5. [timestamp] - Data staging and exfiltration (proxy bytes_out anomaly)

SPL QUERIES USED
[numbered list of key queries with descriptions]

DETECTION GAPS IDENTIFIED
- No Sysmon deployed on SRV-FILE01 (blind spot)
- Proxy logs missing SSL inspection for C2 domain
- PowerShell ScriptBlock logging not enabled

RECOMMENDED DETECTIONS
1. Correlation search for Office-spawned PowerShell
2. Threshold alert for LSASS access patterns
3. Behavioral rule for beacon-interval network traffic
```
