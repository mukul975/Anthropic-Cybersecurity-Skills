---
name: investigating-insider-threat-indicators
description: >
  Investigates insider threat indicators including data exfiltration attempts, unauthorized access
  patterns, policy violations, and pre-departure behaviors using SIEM analytics, DLP alerts, and
  HR data correlation. Use when SOC teams receive insider threat referrals from HR, detect anomalous
  data movement by employees, or need to build investigation timelines for potential insider threats.
domain: cybersecurity
subdomain: soc-operations
tags: [soc, insider-threat, data-exfiltration, dlp, ueba, investigation, hr-correlation]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Investigating Insider Threat Indicators

## When to Use

Use this skill when:
- HR refers a departing employee for monitoring during their notice period
- DLP alerts indicate bulk data downloads or transfers to personal storage
- UEBA detects anomalous access patterns deviating significantly from peer baselines
- Management reports concerns about an employee accessing sensitive data outside their role

**Do not use** without proper legal authorization — insider threat investigations must be coordinated with HR, Legal, and Privacy teams before monitoring begins.

## Prerequisites

- Legal authorization and HR referral documenting investigation justification
- SIEM with DLP, endpoint, email, proxy, and authentication log sources
- Data Loss Prevention (DLP) system (Microsoft Purview, Symantec, Forcepoint) with policy alerts
- Endpoint monitoring capability (EDR with USB/removable media logging)
- HR data feed providing employment status, notice dates, and access entitlements
- Chain of custody procedures for evidence preservation

## Workflow

### Step 1: Establish Investigation Scope and Legal Authorization

Before any monitoring, ensure proper authorization:

```
INSIDER THREAT INVESTIGATION AUTHORIZATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Case ID:           IT-2024-0089
Subject:           [Employee Name] — [Department]
Authorized By:     [CISO / General Counsel]
Referral Source:   HR — Employee submitted resignation, 2-week notice
Justification:     Employee has access to trade secrets and customer PII
Scope:             Email, file access, USB, cloud storage, printing
Duration:          2024-03-15 to 2024-03-29 (notice period)
Privacy Review:    Completed — compliant with acceptable use policy
```

### Step 2: Build Activity Timeline from SIEM

Query comprehensive activity for the subject:

```spl
index=* (user="jsmith" OR src_user="jsmith" OR sender="jsmith@company.com"
         OR SubjectUserName="jsmith")
earliest="2024-03-01" latest=now
| eval event_category = case(
    sourcetype LIKE "%dlp%", "DLP",
    sourcetype LIKE "%proxy%", "Web Access",
    sourcetype LIKE "%email%", "Email",
    sourcetype LIKE "%WinEventLog%", "Endpoint",
    sourcetype LIKE "%o365%", "Cloud",
    sourcetype LIKE "%vpn%", "VPN",
    sourcetype LIKE "%badge%", "Physical Access",
    1=1, sourcetype
  )
| stats count by event_category, sourcetype, _time
| timechart span=1d count by event_category
```

### Step 3: Detect Data Exfiltration Indicators

**Bulk File Downloads (SharePoint/OneDrive):**

```spl
index=o365 sourcetype="o365:management:activity" Operation IN ("FileDownloaded", "FileSynced")
UserId="jsmith@company.com" earliest=-30d
| stats count AS downloads, sum(eval(if(isnotnull(FileSize), FileSize, 0))) AS total_bytes,
        dc(SourceFileName) AS unique_files
  by UserId, SiteUrl, _time
| bin _time span=1d
| eval total_gb = round(total_bytes / 1073741824, 2)
| where downloads > 50 OR total_gb > 1
| sort - total_gb
```

**USB/Removable Media Usage:**

```spl
index=sysmon EventCode=1 Computer="WORKSTATION-JSMITH"
(CommandLine="*removable*" OR CommandLine="*usb*"
 OR Image="*\\xcopy*" OR Image="*\\robocopy*")
| table _time, Computer, User, Image, CommandLine
| append [
    search index=endpoint sourcetype="endpoint:device_connect"
    user="jsmith" device_type="removable"
    | table _time, user, device_name, device_serial, action
  ]
| sort _time
```

**Email-Based Exfiltration:**

```spl
index=email sourcetype="o365:messageTrace"
SenderAddress="jsmith@company.com"
| eval is_external = if(match(RecipientAddress, "@company\.com$"), 0, 1)
| eval has_attachment = if(isnotnull(AttachmentName), 1, 0)
| stats count AS total_emails,
        sum(is_external) AS external_emails,
        sum(has_attachment) AS with_attachments,
        sum(eval(if(is_external=1 AND has_attachment=1, 1, 0))) AS external_with_attach,
        sum(Size) AS total_size_bytes
  by SenderAddress
| eval external_attach_pct = round(external_with_attach / total_emails * 100, 1)
| eval total_size_mb = round(total_size_bytes / 1048576, 1)
```

**Cloud Storage Upload Detection:**

```spl
index=proxy user="jsmith"
(dest IN ("*dropbox.com", "*drive.google.com", "*onedrive.live.com",
          "*box.com", "*wetransfer.com", "*mega.nz")
 OR category="cloud-storage")
http_method=POST
| stats count AS uploads, sum(bytes_out) AS total_uploaded
  by user, dest, category
| eval uploaded_mb = round(total_uploaded / 1048576, 1)
| sort - uploaded_mb
```

### Step 4: Analyze Access Pattern Anomalies

**Accessing Sensitive Systems Outside Normal Scope:**

```spl
index=auth user="jsmith" action=success earliest=-30d
| stats dc(app) AS unique_apps, values(app) AS apps_accessed by user
| join user type=left [
    | inputlookup role_app_mapping.csv
    | search role="Financial Analyst"
    | stats values(authorized_app) AS authorized_apps by role
    | eval user="jsmith"
  ]
| eval unauthorized = mvfilter(NOT match(apps_accessed, mvjoin(authorized_apps, "|")))
| where isnotnull(unauthorized)
| table user, unauthorized, authorized_apps
```

**After-Hours and Weekend Activity:**

```spl
index=* user="jsmith" earliest=-30d
| eval hour = tonumber(strftime(_time, "%H"))
| eval is_offhours = if(hour < 7 OR hour > 19, 1, 0)
| eval day = strftime(_time, "%A")
| eval is_weekend = if(day IN ("Saturday", "Sunday"), 1, 0)
| stats count AS total, sum(is_offhours) AS offhours, sum(is_weekend) AS weekend by user
| eval offhours_pct = round(offhours / total * 100, 1)
| eval weekend_pct = round(weekend / total * 100, 1)
```

### Step 5: Correlate with HR and Physical Security Data

**Compare activity to resignation timeline:**

```spl
| makeresults
| eval user="jsmith",
       resignation_date="2024-03-15",
       last_day="2024-03-29",
       access_revocation="2024-03-29 17:00"
| join user [
    search index=* user="jsmith" earliest=-90d
    | bin _time span=1d
    | stats count AS daily_events, dc(sourcetype) AS data_sources by user, _time
  ]
| eval phase = case(
    _time < relative_time(now(), "-30d"), "Normal (Pre-Resignation)",
    _time >= strptime(resignation_date, "%Y-%m-%d") AND _time <= strptime(last_day, "%Y-%m-%d"),
      "Notice Period",
    1=1, "Transition"
  )
| chart avg(daily_events) AS avg_events by phase
```

**Badge/Physical Access Correlation:**

```spl
index=badge_access employee_id="jsmith" earliest=-30d
| stats count AS badge_events, values(door_name) AS doors_accessed,
        earliest(_time) AS first_badge, latest(_time) AS last_badge by employee_id
| eval areas = mvcount(doors_accessed)
```

### Step 6: Preserve Evidence and Document Findings

Maintain chain of custody for all collected evidence:

```python
import hashlib
import json
from datetime import datetime

evidence_log = {
    "case_id": "IT-2024-0089",
    "investigator": "soc_analyst_tier2",
    "collection_time": datetime.utcnow().isoformat(),
    "items": [
        {
            "item_id": "EV-001",
            "description": "Splunk export — all user activity 2024-03-01 to 2024-03-15",
            "file": "jsmith_activity_export.csv",
            "sha256": hashlib.sha256(open("jsmith_activity_export.csv", "rb").read()).hexdigest(),
            "collected_by": "analyst_doe",
            "collection_method": "Splunk search export"
        },
        {
            "item_id": "EV-002",
            "description": "DLP alert details — 47 policy violations",
            "file": "dlp_alerts_jsmith.json",
            "sha256": hashlib.sha256(open("dlp_alerts_jsmith.json", "rb").read()).hexdigest(),
            "collected_by": "analyst_doe",
            "collection_method": "Microsoft Purview export"
        }
    ]
}

with open(f"evidence_log_{evidence_log['case_id']}.json", "w") as f:
    json.dump(evidence_log, f, indent=2)
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Insider Threat** | Risk posed by individuals with legitimate access who misuse it for unauthorized purposes |
| **Data Exfiltration** | Unauthorized transfer of data outside the organization via email, USB, cloud, or other channels |
| **DLP** | Data Loss Prevention — technology monitoring and blocking unauthorized data transfers based on content policies |
| **Notice Period Monitoring** | Enhanced surveillance of departing employees during their resignation-to-departure window |
| **Chain of Custody** | Documented evidence handling procedures ensuring forensic integrity for potential legal proceedings |
| **Need-to-Know Violation** | Accessing information or systems beyond what is required for an employee's role or current tasks |

## Tools & Systems

- **Microsoft Purview (formerly DLP)**: Data classification and loss prevention platform monitoring endpoints, email, and cloud storage
- **Splunk UBA**: User behavior analytics detecting insider threat patterns through ML-based anomaly detection
- **Forcepoint Insider Threat**: Dedicated insider threat detection platform with behavioral indicators and risk scoring
- **DTEX InTERCEPT**: Endpoint-based insider threat detection focusing on user activity metadata collection
- **Code42 Incydr**: Data risk detection platform specializing in file exfiltration monitoring across endpoints and cloud

## Common Scenarios

- **Departing Employee**: Bulk download of customer lists and product roadmaps during two-week notice period
- **Disgruntled Employee**: After negative performance review, employee accesses executive salary data outside their role
- **Contractor Overreach**: External consultant accessing systems beyond contracted scope, downloading source code
- **Account Misuse**: Employee sharing credentials with unauthorized third party for competitive intelligence
- **Sabotage Indicator**: IT admin creating backdoor accounts and modifying system configurations before departure

## Output Format

```
INSIDER THREAT INVESTIGATION REPORT — IT-2024-0089
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Subject:      jsmith (Financial Analyst, Finance Dept)
Period:       2024-03-01 to 2024-03-15
Status:       Employee resigned 2024-03-15, last day 2024-03-29

Key Findings:
  [HIGH]  3,847 files downloaded from SharePoint (12.4 GB) — 10x peer average
  [HIGH]  USB device connected 14 times during notice period (0 times prior month)
  [HIGH]  187 emails with attachments sent to personal Gmail
  [MEDIUM] After-hours activity increased 340% during notice period
  [MEDIUM] Accessed HR salary database 3 times (not authorized for role)

Timeline:
  Mar 01-14:  Normal activity baseline (avg 150 events/day)
  Mar 15:     Resignation submitted (activity spike to 890 events)
  Mar 16-17:  Weekend access — 2,100 SharePoint downloads
  Mar 18:     USB device first connected, DLP alert triggered

Evidence Collected:   4 items (SHA-256 verified, chain of custody documented)
Recommendation:       Immediate access revocation recommended
                      Evidence package prepared for Legal review
```
