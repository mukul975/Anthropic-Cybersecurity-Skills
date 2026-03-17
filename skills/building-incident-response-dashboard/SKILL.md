---
name: building-incident-response-dashboard
description: >
  Builds real-time incident response dashboards in Splunk, Elastic, or Grafana to provide SOC
  analysts and leadership with situational awareness during active incidents, tracking affected
  systems, containment status, IOC spread, and response timeline. Use when IR teams need unified
  visibility during incident coordination and post-incident reporting.
domain: cybersecurity
subdomain: soc-operations
tags: [soc, dashboard, incident-response, splunk, visualization, situational-awareness, metrics]
mitre_attack: ["T1190", "T1566", "T1486"]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Building Incident Response Dashboard

## When to Use

Use this skill when:
- IR teams need real-time dashboards during active incidents for coordination and tracking
- SOC leadership requires operational dashboards showing incident status and analyst workload
- Post-incident reviews need visual timelines and impact assessments
- Executive briefings require high-level incident metrics and trend analysis

**Do not use** for day-to-day SOC monitoring dashboards (use Incident Review instead) — IR dashboards are designed for active incident coordination and management reporting.

## Prerequisites

- SIEM platform (Splunk with Dashboard Studio, Elastic Kibana, or Grafana)
- Notable event and incident data in SIEM (Splunk ES incident_review index)
- Ticketing system integration (ServiceNow, Jira) for remediation tracking
- Asset and identity lookup tables for context enrichment
- Dashboard publishing access for SOC team and management distribution

## Workflow

### Step 1: Design Active Incident Dashboard Layout

Build a Splunk Dashboard Studio dashboard for active incident tracking:

```xml
<dashboard version="2" theme="dark">
  <label>Active Incident Response Dashboard</label>
  <description>Real-time tracking for IR-2024-0450</description>

  <row>
    <panel>
      <title>Incident Summary</title>
      <single>
        <search>
          <query>
| makeresults
| eval incident_id="IR-2024-0450",
       status="CONTAINMENT",
       severity="Critical",
       affected_hosts=7,
       contained_hosts=5,
       iocs_identified=23,
       hours_elapsed=round((now()-strptime("2024-03-15 14:00","%Y-%m-%d %H:%M"))/3600,1)
| table incident_id, status, severity, affected_hosts, contained_hosts, iocs_identified, hours_elapsed
          </query>
        </search>
      </single>
    </panel>
  </row>
</dashboard>
```

### Step 2: Build Real-Time Affected Systems Panel

Track affected systems and their containment status:

```spl
| inputlookup ir_affected_systems.csv
| eval status_color = case(
    status="Contained", "#2ecc71",
    status="Compromised", "#e74c3c",
    status="Investigating", "#f39c12",
    status="Recovered", "#3498db",
    1=1, "#95a5a6"
  )
| stats count by status
| eval order = case(status="Compromised", 1, status="Investigating", 2,
                    status="Contained", 3, status="Recovered", 4)
| sort order
| table status, count

--- Detailed host table
| inputlookup ir_affected_systems.csv
| lookup asset_lookup_by_cidr ip AS host_ip OUTPUT category, owner, priority
| table hostname, host_ip, category, owner, status, containment_time,
        compromise_vector, analyst_assigned
| sort status, hostname
```

### Step 3: Build IOC Tracking Panel

Monitor IOC spread across the environment:

```spl
--- IOCs identified during incident
index=* (src_ip IN ("185.234.218.50", "45.77.123.45") OR
         dest IN ("evil-c2.com", "malware-drop.com") OR
         file_hash IN ("a1b2c3d4...", "e5f6a7b8..."))
earliest="2024-03-14"
| stats count AS hits, dc(src_ip) AS unique_sources,
        dc(dest) AS unique_dests, latest(_time) AS last_seen
  by sourcetype
| sort - hits

--- IOC timeline
index=* (src_ip IN ("185.234.218.50") OR dest="evil-c2.com")
earliest="2024-03-14"
| timechart span=1h count by sourcetype

--- New IOC discovery tracking
| inputlookup ir_ioc_list.csv
| stats count by ioc_type, source, discovery_time
| sort discovery_time
| table discovery_time, ioc_type, ioc_value, source, status
```

### Step 4: Build Response Timeline Panel

Create chronological incident timeline:

```spl
| inputlookup ir_timeline.csv
| sort _time
| eval phase = case(
    action_type="detection", "Detection",
    action_type="triage", "Triage",
    action_type="containment", "Containment",
    action_type="eradication", "Eradication",
    action_type="recovery", "Recovery",
    1=1, "Other"
  )
| eval phase_color = case(
    phase="Detection", "#e74c3c",
    phase="Triage", "#f39c12",
    phase="Containment", "#e67e22",
    phase="Eradication", "#2ecc71",
    phase="Recovery", "#3498db"
  )
| table _time, phase, action, analyst, details
```

Example timeline data:
```csv
_time,action_type,action,analyst,details
2024-03-15 14:00,detection,Alert triggered - Cobalt Strike beacon detected,splunk_es,Notable event NE-2024-08921
2024-03-15 14:12,triage,Alert triaged - confirmed true positive,analyst_jdoe,VT score 52/72 on beacon hash
2024-03-15 14:23,containment,Host WORKSTATION-042 isolated,analyst_jdoe,CrowdStrike network isolation
2024-03-15 14:35,containment,C2 domain blocked on firewall,analyst_msmith,Palo Alto rule deployed
2024-03-15 15:00,eradication,Enterprise-wide IOC scan initiated,analyst_jdoe,Splunk search across all indices
2024-03-15 15:30,containment,3 additional hosts identified and isolated,analyst_msmith,Lateral movement confirmed
2024-03-15 16:00,eradication,Malware removed from all affected hosts,analyst_tier3,CrowdStrike RTR cleanup
2024-03-15 18:00,recovery,Systems restored and monitored,analyst_msmith,72-hour monitoring period started
```

### Step 5: Build SOC Operations Dashboard

Track overall SOC performance metrics:

```spl
--- Incident volume by severity (last 30 days)
index=notable earliest=-30d
| stats count by urgency
| eval order = case(urgency="critical", 1, urgency="high", 2, urgency="medium", 3,
                    urgency="low", 4, urgency="informational", 5)
| sort order

--- MTTD (Mean Time to Detect)
index=notable earliest=-30d status_label="Resolved*"
| eval mttd_minutes = round((time_of_first_event - orig_time) / 60, 1)
| stats avg(mttd_minutes) AS avg_mttd, median(mttd_minutes) AS med_mttd,
        perc95(mttd_minutes) AS p95_mttd

--- MTTR (Mean Time to Respond/Resolve)
index=notable earliest=-30d status_label="Resolved*"
| eval mttr_hours = round((status_end - _time) / 3600, 1)
| stats avg(mttr_hours) AS avg_mttr, median(mttr_hours) AS med_mttr by urgency

--- Analyst workload distribution
index=notable earliest=-7d
| stats count by owner
| sort - count

--- Alert disposition breakdown
index=notable earliest=-30d status_label IN ("Resolved*", "Closed*")
| stats count by disposition
| eval percentage = round(count / sum(count) * 100, 1)
| sort - count
```

### Step 6: Build Executive Briefing Dashboard

Create a high-level dashboard for leadership during major incidents:

```spl
--- Executive summary panel
| makeresults
| eval metrics = "Business Impact: 1 file server offline (Finance dept), "
                ."Estimated Recovery: 4 hours, "
                ."Data Loss Risk: Low (backups verified), "
                ."Customer Impact: None, "
                ."Regulatory Notification: Not required (no PII exposure confirmed)"

--- Trend comparison (this month vs last month)
index=notable earliest=-60d
| eval period = if(_time > relative_time(now(), "-30d"), "Current Month", "Previous Month")
| stats count by period, urgency
| chart sum(count) AS incidents by period, urgency

--- Top threat categories
index=notable earliest=-30d
| top rule_name limit=10
| table rule_name, count, percent
```

### Step 7: Automate Dashboard Updates

Use Splunk scheduled searches to maintain dashboard data:

```spl
--- Scheduled search to update affected systems lookup (runs every 5 minutes)
index=* (src_ip IN [| inputlookup ir_ioc_list.csv | search ioc_type="ip"
                    | fields ioc_value | rename ioc_value AS src_ip])
earliest=-1h
| stats latest(_time) AS last_seen, count AS event_count,
        values(sourcetype) AS data_sources by src_ip
| eval status = if(last_seen > relative_time(now(), "-15m"), "Active", "Dormant")
| outputlookup ir_affected_systems_auto.csv
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Situational Awareness** | Real-time understanding of incident scope, affected systems, and response progress |
| **MTTD** | Mean Time to Detect — average time from threat occurrence to SOC alert generation |
| **MTTR** | Mean Time to Respond — average time from alert to incident resolution or containment |
| **Containment Rate** | Percentage of affected systems successfully isolated relative to total compromised systems |
| **Burn-Down Chart** | Visual tracking of remaining open investigation tasks over time during an incident |
| **Executive Briefing** | Non-technical summary dashboard showing business impact, timeline, and recovery status |

## Tools & Systems

- **Splunk Dashboard Studio**: Modern dashboard framework with drag-and-drop visualization and real-time data
- **Elastic Kibana Dashboard**: Visualization platform with Lens, Maps, and Canvas for security dashboards
- **Grafana**: Open-source visualization platform supporting multiple data sources including Elasticsearch and Splunk
- **Microsoft Sentinel Workbooks**: Azure-native dashboard framework with Kusto-based analytics visualization
- **TheHive**: Open-source incident response platform with built-in case tracking and metrics dashboards

## Common Scenarios

- **Active Ransomware Incident**: Dashboard showing encryption spread, containment status, backup verification, recovery progress
- **Data Breach Investigation**: Dashboard tracking affected data stores, exfiltration volume, notification requirements
- **Phishing Campaign Response**: Dashboard showing recipient count, click rate, credential exposure, remediation status
- **Monthly SOC Report**: Leadership dashboard with incident trends, MTTD/MTTR metrics, analyst performance
- **Compliance Audit**: Dashboard demonstrating detection coverage, response SLA compliance, and incident closure metrics

## Output Format

```
INCIDENT RESPONSE DASHBOARD — IR-2024-0450
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

STATUS: CONTAINMENT PHASE (6h 30m elapsed)

Affected Systems:          Containment Progress:
  Compromised:   2         [==========----------] 71%
  Investigating: 1         5 of 7 systems contained
  Contained:     3
  Recovered:     1

IOC Summary:               Response Timeline:
  IPs:      4              14:00 — Alert triggered
  Domains:  2              14:12 — Confirmed malicious
  Hashes:   3              14:23 — First host isolated
  URLs:     5              15:00 — Enterprise scan started
  Emails:   1              15:30 — 3 more hosts isolated

Key Metrics:
  MTTD:    12 minutes
  MTTC:    23 minutes (first host)
  Analysts Active: 3 (Tier 2: 2, Tier 3: 1)

Business Impact: LOW — Finance file server offline, no customer-facing systems affected
```
