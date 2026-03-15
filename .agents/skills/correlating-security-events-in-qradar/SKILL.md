---
name: correlating-security-events-in-qradar
description: >
  Correlates security events in IBM QRadar SIEM using AQL (Ariel Query Language), custom rules,
  building blocks, and offense management to detect multi-stage attacks across network, endpoint,
  and application log sources. Use when SOC analysts need to investigate QRadar offenses, build
  correlation rules, or tune detection logic for reducing false positives.
domain: cybersecurity
subdomain: soc-operations
tags: [soc, qradar, siem, aql, correlation, offense-management, ibm]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Correlating Security Events in QRadar

## When to Use

Use this skill when:
- SOC analysts need to investigate QRadar offenses and correlate events across multiple log sources
- Detection engineers build custom correlation rules to identify multi-stage attacks
- Alert tuning is required to reduce false positive offenses and improve signal quality
- The team migrates from basic event monitoring to behavior-based correlation

**Do not use** for log source onboarding or parsing — that requires QRadar administrator access and DSM editor knowledge.

## Prerequisites

- IBM QRadar SIEM 7.5+ with offense management enabled
- AQL knowledge for ad-hoc event and flow queries
- Log sources normalized with proper QID mappings (Windows, firewall, proxy, endpoint)
- User role with offense management, rule creation, and AQL search permissions
- Reference sets/maps configured for whitelist and watchlist management

## Workflow

### Step 1: Investigate an Offense with AQL

Open an offense in QRadar and query contributing events using AQL (Ariel Query Language):

```sql
SELECT DATEFORMAT(startTime, 'yyyy-MM-dd HH:mm:ss') AS event_time,
       sourceIP, destinationIP, username,
       LOGSOURCENAME(logSourceId) AS log_source,
       QIDNAME(qid) AS event_name,
       category, magnitude
FROM events
WHERE INOFFENSE(12345)
ORDER BY startTime ASC
LIMIT 500
```

Pivot on the source IP to find all activity:

```sql
SELECT DATEFORMAT(startTime, 'yyyy-MM-dd HH:mm:ss') AS event_time,
       destinationIP, destinationPort, username,
       QIDNAME(qid) AS event_name,
       eventCount, category
FROM events
WHERE sourceIP = '192.168.1.105'
  AND startTime > NOW() - 24*60*60*1000
ORDER BY startTime ASC
LIMIT 1000
```

### Step 2: Build a Custom Correlation Rule

Create a multi-condition rule detecting brute force followed by successful login:

**Rule 1 — Brute Force Detection (Building Block):**
```
Rule Type: Event
Rule Name: BB: Multiple Failed Logins from Same Source
Tests:
  - When the event(s) were detected by one or more of [Local]
  - AND when the event QID is one of [Authentication Failure (5000001)]
  - AND when at least 10 events are seen with the same Source IP
    in 5 minutes
Rule Action: Dispatch new event (Category: Authentication, QID: Custom_BruteForce)
```

**Rule 2 — Brute Force Succeeded (Correlation Rule):**
```
Rule Type: Offense
Rule Name: COR: Brute Force with Subsequent Successful Login
Tests:
  - When an event matches the building block BB: Multiple Failed Logins from Same Source
  - AND when an event with QID [Authentication Success (5000000)] is detected
    from the same Source IP within 10 minutes
  - AND the Destination IP is the same for both events
Rule Action: Create offense, set severity to High, set relevance to 8
```

### Step 3: Use AQL for Cross-Source Correlation

Correlate authentication failures with network flows to detect lateral movement:

```sql
SELECT e.sourceIP, e.destinationIP, e.username,
       QIDNAME(e.qid) AS event_name,
       e.eventCount,
       f.sourceBytes, f.destinationBytes
FROM events e
LEFT JOIN flows f ON e.sourceIP = f.sourceIP
  AND e.destinationIP = f.destinationIP
  AND f.startTime BETWEEN e.startTime AND e.startTime + 300000
WHERE e.category = 'Authentication'
  AND e.sourceIP IN (
    SELECT sourceIP FROM events
    WHERE QIDNAME(qid) = 'Authentication Failure'
      AND startTime > NOW() - 3600000
    GROUP BY sourceIP
    HAVING COUNT(*) > 20
  )
  AND e.startTime > NOW() - 3600000
ORDER BY e.startTime ASC
```

Detect data exfiltration by correlating DNS queries with large outbound flows:

```sql
SELECT sourceIP, destinationIP,
       SUM(sourceBytes) AS total_bytes_out,
       COUNT(*) AS flow_count
FROM flows
WHERE sourceIP IN (
    SELECT sourceIP FROM events
    WHERE QIDNAME(qid) ILIKE '%DNS%'
      AND destinationIP NOT IN (
        SELECT ip FROM reference_data.sets('Internal_DNS_Servers')
      )
      AND startTime > NOW() - 86400000
    GROUP BY sourceIP
    HAVING COUNT(*) > 500
  )
  AND destinationPort NOT IN (80, 443, 53)
  AND startTime > NOW() - 86400000
GROUP BY sourceIP, destinationIP
HAVING SUM(sourceBytes) > 104857600
ORDER BY total_bytes_out DESC
```

### Step 4: Configure Reference Sets for Context Enrichment

Create reference sets for dynamic whitelists and watchlists:

```bash
# Create reference set via QRadar API
curl -X POST "https://qradar.example.com/api/reference_data/sets" \
  -H "SEC: YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Known_Pen_Test_IPs",
    "element_type": "IP",
    "timeout_type": "LAST_SEEN",
    "time_to_live": "30 days"
  }'

# Add entries
curl -X POST "https://qradar.example.com/api/reference_data/sets/Known_Pen_Test_IPs" \
  -H "SEC: YOUR_API_TOKEN" \
  -d "value=10.0.5.100"
```

Use reference sets in rule conditions to exclude known benign activity:

```
Test: AND when the Source IP is NOT contained in any of [Known_Pen_Test_IPs]
Test: AND when the Destination IP is contained in any of [Critical_Asset_IPs]
```

### Step 5: Tune Offense Generation

Reduce false positives by adding building block filters:

```sql
-- Find top false positive generators
SELECT QIDNAME(qid) AS event_name,
       LOGSOURCENAME(logSourceId) AS log_source,
       COUNT(*) AS event_count,
       COUNT(DISTINCT sourceIP) AS unique_sources
FROM events
WHERE INOFFENSE(
    SELECT offenseId FROM offenses
    WHERE status = 'CLOSED'
      AND closeReason = 'False Positive'
      AND startTime > NOW() - 30*24*60*60*1000
  )
GROUP BY qid, logSourceId
ORDER BY event_count DESC
LIMIT 20
```

Apply tuning:
- Add high-frequency false positive sources to reference set exclusions
- Increase event thresholds on noisy rules (e.g., 10 failed logins -> 25 for service accounts)
- Set offense coalescing to group related events under a single offense

### Step 6: Build Custom Dashboard for Correlation Monitoring

Create a QRadar Pulse dashboard with key correlation metrics:

```sql
-- Active offenses by category
SELECT offenseType, status, COUNT(*) AS offense_count,
       AVG(magnitude) AS avg_magnitude
FROM offenses
WHERE status = 'OPEN'
GROUP BY offenseType, status
ORDER BY offense_count DESC

-- Mean time to close offenses
SELECT DATEFORMAT(startTime, 'yyyy-MM-dd') AS day,
       AVG(closeTime - startTime) / 60000 AS avg_close_minutes,
       COUNT(*) AS closed_count
FROM offenses
WHERE status = 'CLOSED'
  AND startTime > NOW() - 30*24*60*60*1000
GROUP BY DATEFORMAT(startTime, 'yyyy-MM-dd')
ORDER BY day
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **AQL** | Ariel Query Language — QRadar's SQL-like query language for searching events, flows, and offenses |
| **Offense** | QRadar's correlated incident grouping multiple events/flows under a single investigation unit |
| **Building Block** | Reusable rule component that categorizes events without generating offenses, used as input to correlation rules |
| **Magnitude** | QRadar's calculated offense severity combining relevance, severity, and credibility scores (1-10) |
| **Reference Set** | Dynamic lookup table in QRadar for whitelists, watchlists, and enrichment data used in rules |
| **QID** | QRadar Identifier — unique numeric ID mapping vendor-specific events to normalized categories |
| **Coalescing** | QRadar's mechanism for grouping related events into a single offense to reduce analyst workload |

## Tools & Systems

- **IBM QRadar SIEM**: Enterprise SIEM platform with event correlation, offense management, and AQL query engine
- **QRadar Pulse**: Dashboard framework for building custom visualizations of offense and event metrics
- **QRadar API**: RESTful API for automating reference set management, offense operations, and rule deployment
- **QRadar Use Case Manager**: App for mapping detection rules to MITRE ATT&CK framework coverage
- **QRadar Assistant**: AI-powered analysis tool helping analysts investigate offenses with natural language

## Common Scenarios

- **Brute Force to Compromise**: Correlate failed auth events with subsequent successful login from same source
- **Lateral Movement Chain**: Track authentication events across multiple internal hosts from a single source
- **C2 Beaconing**: Correlate periodic DNS queries with low-entropy payloads to unusual domains
- **Privilege Escalation**: Correlate user account changes (group additions) with prior suspicious authentication
- **Data Exfiltration**: Correlate large outbound flow volumes with prior internal reconnaissance activity

## Output Format

```
QRADAR OFFENSE INVESTIGATION — Offense #12345
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Offense Type:   Brute Force with Subsequent Access
Magnitude:      8/10 (Severity: 8, Relevance: 9, Credibility: 7)
Created:        2024-03-15 14:23:07 UTC
Contributing:   247 events from 3 log sources

Correlation Chain:
  14:10-14:22  — 234 Authentication Failures (EventCode 4625) from 192.168.1.105 to DC-01
  14:23:07     — Authentication Success (EventCode 4624) from 192.168.1.105 to DC-01 (user: admin)
  14:25:33     — New Process: cmd.exe spawned by admin on DC-01
  14:26:01     — Net.exe user /add detected on DC-01

Sources Correlated:
  Windows Security Logs (DC-01)
  Sysmon (DC-01)
  Firewall (Palo Alto PA-5260)

Disposition:    TRUE POSITIVE — Escalated to Incident Response
Ticket:         IR-2024-0432
```
