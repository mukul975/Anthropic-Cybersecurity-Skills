---
name: performing-user-behavior-analytics
description: >
  Performs User and Entity Behavior Analytics (UEBA) to detect anomalous user activities including
  impossible travel, unusual access patterns, privilege abuse, and insider threats using SIEM-based
  behavioral baselines and statistical analysis. Use when SOC teams need to identify compromised
  accounts or insider threats through deviation from established behavioral norms.
domain: cybersecurity
subdomain: soc-operations
tags: [soc, ueba, user-behavior, insider-threat, anomaly-detection, splunk, baseline]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing User Behavior Analytics

## When to Use

Use this skill when:
- SOC teams need to detect compromised accounts through abnormal authentication patterns
- Insider threat programs require behavioral monitoring beyond rule-based detection
- Impossible travel or geographic anomalies indicate credential compromise
- Privileged account monitoring requires baseline deviation detection

**Do not use** as the sole basis for disciplinary action — UEBA findings are indicators requiring investigation, not proof of malicious intent.

## Prerequisites

- SIEM with 30+ days of authentication and access log history for baseline creation
- VPN, O365, and Active Directory authentication logs normalized to CIM
- GeoIP database (MaxMind GeoLite2) for location-based anomaly detection
- Identity enrichment data (department, role, manager, typical work hours)
- Splunk Enterprise Security with UBA module or equivalent UEBA capability

## Workflow

### Step 1: Build User Authentication Baselines

Create behavioral baselines from historical data:

```spl
index=auth sourcetype IN ("o365:management:activity", "vpn_logs", "WinEventLog:Security")
earliest=-30d latest=-1d
| stats dc(src_ip) AS unique_ips,
        dc(src_country) AS unique_countries,
        dc(app) AS unique_apps,
        count AS total_logins,
        earliest(_time) AS first_login,
        latest(_time) AS last_login,
        values(src_country) AS countries,
        avg(eval(strftime(_time, "%H"))) AS avg_login_hour,
        stdev(eval(strftime(_time, "%H"))) AS stdev_login_hour
  by user
| eval avg_daily_logins = round(total_logins / 30, 1)
| eval login_hour_range = round(avg_login_hour, 0)." +/- ".round(stdev_login_hour, 1)." hrs"
| table user, unique_ips, unique_countries, unique_apps, avg_daily_logins,
        login_hour_range, countries
```

### Step 2: Detect Impossible Travel

Identify logins from geographically distant locations within impossible timeframes:

```spl
index=auth sourcetype IN ("o365:management:activity", "vpn_logs")
action=success earliest=-24h
| iplocation src_ip
| sort user, _time
| streamstats current=f last(lat) AS prev_lat, last(lon) AS prev_lon,
              last(_time) AS prev_time, last(City) AS prev_city,
              last(Country) AS prev_country, last(src_ip) AS prev_ip
  by user
| where isnotnull(prev_lat)
| eval distance_km = round(
    6371 * acos(
      cos(pi()/180 * lat) * cos(pi()/180 * prev_lat) *
      cos(pi()/180 * (lon - prev_lon)) +
      sin(pi()/180 * lat) * sin(pi()/180 * prev_lat)
    ), 0)
| eval time_diff_hours = round((_time - prev_time) / 3600, 2)
| eval speed_kmh = if(time_diff_hours > 0, round(distance_km / time_diff_hours, 0), 0)
| where speed_kmh > 900 AND distance_km > 500
| eval alert = "IMPOSSIBLE TRAVEL: ".prev_city.", ".prev_country." -> ".City.", ".Country
| table _time, user, prev_city, prev_country, City, Country, distance_km,
        time_diff_hours, speed_kmh, alert
| sort - speed_kmh
```

### Step 3: Detect Anomalous Login Timing

Identify logins outside a user's normal working hours:

```spl
index=auth action=success earliest=-7d
| eval hour = strftime(_time, "%H")
| eval day_of_week = strftime(_time, "%A")
| eval is_weekend = if(day_of_week IN ("Saturday", "Sunday"), 1, 0)
| eval is_off_hours = if(hour < 6 OR hour > 22, 1, 0)
| join user type=left [
    search index=auth action=success earliest=-60d latest=-7d
    | eval hour = strftime(_time, "%H")
    | stats avg(hour) AS baseline_avg_hour, stdev(hour) AS baseline_stdev_hour,
            perc95(hour) AS baseline_latest_hour by user
  ]
| where (is_off_hours=1 OR is_weekend=1) AND
        (hour > baseline_latest_hour + 2 OR hour < baseline_avg_hour - baseline_stdev_hour * 2)
| stats count, values(hour) AS login_hours, values(day_of_week) AS login_days,
        values(src_ip) AS source_ips
  by user, baseline_avg_hour, baseline_latest_hour
| where count > 0
| sort - count
```

### Step 4: Detect Unusual Data Access Patterns

Monitor for abnormal file or database access volumes:

```spl
index=file_access OR index=sharepoint earliest=-24h
| stats sum(bytes) AS total_bytes, dc(file_path) AS unique_files,
        count AS access_count by user
| join user type=left [
    search index=file_access OR index=sharepoint earliest=-30d latest=-1d
    | stats avg(eval(count)) AS baseline_avg_files,
            stdev(eval(count)) AS baseline_stdev_files,
            avg(eval(sum(bytes))) AS baseline_avg_bytes
      by user
  ]
| eval bytes_gb = round(total_bytes / 1073741824, 2)
| eval z_score_files = round((unique_files - baseline_avg_files) / baseline_stdev_files, 2)
| where z_score_files > 3 OR bytes_gb > 5
| eval anomaly_level = case(
    z_score_files > 5, "CRITICAL",
    z_score_files > 3, "HIGH",
    bytes_gb > 10, "CRITICAL",
    bytes_gb > 5, "HIGH",
    1=1, "MEDIUM"
  )
| sort - z_score_files
| table user, unique_files, bytes_gb, baseline_avg_files, z_score_files, anomaly_level
```

### Step 5: Detect Privilege Abuse Patterns

Monitor privileged account usage anomalies:

```spl
index=wineventlog sourcetype="WinEventLog:Security"
(EventCode=4672 OR EventCode=4624 OR EventCode=4648) earliest=-24h
| eval is_privileged = if(EventCode=4672, 1, 0)
| eval is_explicit_cred = if(EventCode=4648, 1, 0)
| stats sum(is_privileged) AS priv_events,
        sum(is_explicit_cred) AS explicit_cred_events,
        dc(ComputerName) AS unique_hosts,
        values(ComputerName) AS hosts_accessed
  by TargetUserName, src_ip
| join TargetUserName type=left [
    search index=wineventlog EventCode IN (4672, 4624, 4648) earliest=-30d latest=-1d
    | stats dc(ComputerName) AS baseline_hosts,
            avg(eval(count)) AS baseline_daily_events by TargetUserName
  ]
| where unique_hosts > baseline_hosts * 2 OR priv_events > baseline_daily_events * 3
| eval risk_score = (unique_hosts / baseline_hosts * 30) + (priv_events / baseline_daily_events * 20)
| sort - risk_score
| table TargetUserName, src_ip, unique_hosts, baseline_hosts, priv_events,
        baseline_daily_events, risk_score, hosts_accessed
```

### Step 6: Generate Risk Score and Prioritize Investigation

Aggregate all UEBA signals into a composite risk score:

```spl
| inputlookup ueba_impossible_travel.csv
| append [| inputlookup ueba_off_hours_access.csv]
| append [| inputlookup ueba_data_access_anomaly.csv]
| append [| inputlookup ueba_privilege_abuse.csv]
| stats sum(risk_points) AS total_risk,
        values(anomaly_type) AS anomaly_types,
        dc(anomaly_type) AS anomaly_count
  by user
| lookup identity_lookup_expanded identity AS user
  OUTPUT department, managedBy, priority AS user_priority
| eval final_risk = total_risk * case(
    user_priority="critical", 2.0,
    user_priority="high", 1.5,
    user_priority="medium", 1.0,
    1=1, 0.8
  )
| sort - final_risk
| head 20
| table user, department, managedBy, anomaly_types, anomaly_count, total_risk, final_risk
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **UEBA** | User and Entity Behavior Analytics — behavioral analysis detecting anomalies against established baselines |
| **Impossible Travel** | Login events from geographically distant locations within timeframes making physical travel impossible |
| **Behavioral Baseline** | Statistical profile of normal user activity patterns built from 30-90 days of historical data |
| **Z-Score** | Statistical measure of how many standard deviations an observation is from the mean — values > 3 indicate anomalies |
| **Risk Score** | Composite numerical score aggregating multiple behavioral anomalies weighted by asset criticality |
| **Peer Group Analysis** | Comparing a user's behavior to others in the same department/role to identify outliers |

## Tools & Systems

- **Splunk UBA**: Dedicated User Behavior Analytics module integrating with Splunk ES for ML-driven anomaly detection
- **Microsoft Sentinel UEBA**: Built-in UEBA capability in Azure Sentinel with entity pages and investigation graphs
- **Exabeam Advanced Analytics**: Standalone UEBA platform with session stitching and automatic timeline creation
- **Securonix**: Cloud-native SIEM/UEBA with pre-built behavioral models for insider threat detection

## Common Scenarios

- **Compromised Account**: Impossible travel + off-hours login + unusual app access = likely credential compromise
- **Insider Data Theft**: Employee accessing 10x normal file volume in notice period before departure
- **Privilege Escalation Abuse**: Admin account used from unusual location accessing systems outside normal scope
- **Shared Account Detection**: Service account logging in from multiple geographies simultaneously
- **Dormant Account Reactivation**: Account with no activity for 90+ days suddenly performing privileged operations

## Output Format

```
UEBA ANOMALY REPORT — Weekly Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Period:       2024-03-11 to 2024-03-17
Users Baselined:  2,847
Anomalies Detected: 23

TOP RISK USERS:
#  User          Dept       Risk   Anomalies
1. jsmith        Finance    94.5   Impossible travel (NYC->Moscow, 2h), off-hours access, 15GB download
2. admin_svc01   IT Ops     82.0   Login from 12 new IPs, 47 hosts accessed (baseline: 8)
3. mwilson       HR         67.3   Off-hours file access (2AM), 3x normal download volume

INVESTIGATION STATUS:
  jsmith:      Escalated to Tier 2 — possible account compromise (IR-2024-0445)
  admin_svc01: Under review — may be new automation deployment (checking with IT Ops)
  mwilson:     Pending HR context — employee on notice period, monitoring increased
```
