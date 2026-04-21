---
name: detecting-aws-cloudtrail-anomalies
description: Detect unusual API call patterns in AWS CloudTrail logs using boto3, statistical baselining, and behavioral analysis
  to identify credential compromise, privilege escalation, and unauthorized resource access.
domain: cybersecurity
subdomain: cloud-security
tags:
- cloud-security
- aws
- cloudtrail
- anomaly-detection
- threat-detection
- boto3
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---
# Detecting AWS CloudTrail Anomalies

## Overview

AWS CloudTrail records API calls across AWS services. This skill covers querying CloudTrail events with boto3's `lookup_events` API, building statistical baselines of normal API activity, detecting anomalies such as unusual event sources, geographic anomalies, high-frequency API calls, and first-time API usage patterns that indicate compromised credentials or insider threats.


## When to Use

- When investigating a potential AWS credential compromise and need to reconstruct attacker API activity
- When building automated CloudTrail alerting rules and want to baseline normal behavior before tuning thresholds
- When a SOC alert triggers on an AWS API call and you need to determine whether the activity is anomalous
- When auditing an AWS account for signs of privilege escalation, lateral movement, or unauthorized resource access

**Do not use** for real-time streaming detection; use CloudWatch Metric Filters or Amazon Detective for sub-minute alerting.

## Prerequisites

- Python 3.9+ with `boto3` library (`pip install boto3`)
- AWS credentials with CloudTrail read permissions (`cloudtrail:LookupEvents`)
- CloudTrail enabled in the target AWS account (management events at minimum)
- Understanding of AWS IAM and common API call patterns for the services in scope

## Workflow

### Step 1: Query CloudTrail Events with Pagination

```python
import boto3
from datetime import datetime, timedelta, timezone
from collections import defaultdict

ct = boto3.client("cloudtrail", region_name="us-east-1")

def get_cloudtrail_events(hours_back: int = 24) -> list[dict]:
    """Retrieve all CloudTrail management events for the past N hours."""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours_back)

    events = []
    paginator = ct.get_paginator("lookup_events")
    page_iterator = paginator.paginate(
        StartTime=start_time,
        EndTime=end_time,
        LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
    )
    for page in page_iterator:
        events.extend(page["Events"])

    print(f"Retrieved {len(events)} write-API events from the past {hours_back}h")
    return events

events = get_cloudtrail_events(hours_back=24)
```

### Step 2: Build an Activity Baseline

```python
from collections import defaultdict
import json

# Aggregate events into a behavioral baseline
baseline = defaultdict(lambda: defaultdict(int))
ip_per_user: dict[str, set] = defaultdict(set)
event_first_seen: dict[tuple, str] = {}

for event in events:
    user = event.get("Username") or "unknown"
    event_name = event.get("EventName", "")
    event_source = event.get("EventSource", "")
    source_ip = event.get("CloudTrailEvent") and json.loads(
        event["CloudTrailEvent"]
    ).get("sourceIPAddress", "unknown")

    baseline[user][event_name] += 1
    if source_ip:
        ip_per_user[user].add(source_ip)

    # Track first-seen event types per user
    key = (user, event_name)
    if key not in event_first_seen:
        event_first_seen[key] = event["EventTime"].isoformat()

print(f"Baseline built: {len(baseline)} distinct users, {len(event_first_seen)} unique (user, event) pairs")
```

### Step 3: Detect Anomalies

```python
SENSITIVE_APIS = {
    # Privilege escalation
    "AttachUserPolicy", "AttachRolePolicy", "CreateAccessKey", "CreateLoginProfile",
    "AddUserToGroup", "PutUserPolicy", "PutRolePolicy",
    # Credential / secret access
    "GetSecretValue", "GetParameter", "Decrypt",
    # Data exfil risk
    "GetObject", "CopyObject", "CreateBucket",
    # Infrastructure takeover
    "CreateVpc", "AuthorizeSecurityGroupIngress", "ModifyInstanceAttribute",
    # Log tampering
    "StopLogging", "DeleteTrail", "PutEventSelectors",
}

HIGH_FREQ_THRESHOLD = 50  # calls per 24h from a single user

anomalies = []

for user, event_counts in baseline.items():
    # Anomaly 1: high-frequency API calls (potential automation or credential stuffing)
    for event_name, count in event_counts.items():
        if count > HIGH_FREQ_THRESHOLD:
            anomalies.append({
                "type": "HIGH_FREQUENCY",
                "user": user,
                "event": event_name,
                "count": count,
                "severity": "MEDIUM",
            })

    # Anomaly 2: sensitive API calls
    for event_name in event_counts:
        if event_name in SENSITIVE_APIS:
            anomalies.append({
                "type": "SENSITIVE_API",
                "user": user,
                "event": event_name,
                "count": event_counts[event_name],
                "severity": "HIGH",
            })

    # Anomaly 3: multiple source IPs (potential credential sharing or compromise)
    unique_ips = ip_per_user[user]
    if len(unique_ips) > 3:
        anomalies.append({
            "type": "MULTIPLE_SOURCE_IPS",
            "user": user,
            "ip_count": len(unique_ips),
            "ips": list(unique_ips),
            "severity": "MEDIUM",
        })

print(f"Detected {len(anomalies)} anomalies")
```

### Step 4: Score and Rank Suspicious Users

```python
from collections import Counter

# Score each user by anomaly severity
severity_weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
user_scores: Counter = Counter()

for anomaly in anomalies:
    user_scores[anomaly["user"]] += severity_weights.get(anomaly["severity"], 1)

top_users = user_scores.most_common(10)
print("\nTop suspicious users:")
for user, score in top_users:
    print(f"  {user}: risk score {score}")
```

### Step 5: Generate Detection Report

```python
import json
from datetime import datetime, timezone

report = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "period_hours": 24,
    "total_events": len(events),
    "unique_users": len(baseline),
    "anomaly_count": len(anomalies),
    "top_suspicious_users": [
        {"user": u, "risk_score": s} for u, s in top_users
    ],
    "anomalies": sorted(anomalies, key=lambda a: severity_weights.get(a["severity"], 0), reverse=True),
}

with open("cloudtrail_anomaly_report.json", "w") as f:
    json.dump(report, f, indent=2)

print(json.dumps(report, indent=2))
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **CloudTrail management events** | API calls that create, modify, or delete AWS resources (write operations); control-plane activity tracked by default |
| **CloudTrail data events** | High-volume object-level operations (S3 GetObject, Lambda invocations); not enabled by default due to cost |
| **LookupEvents API** | CloudTrail API for querying recent management events; supports attribute filters but limited to 90-day retention |
| **Event source** | AWS service that recorded the event (e.g., `iam.amazonaws.com`, `s3.amazonaws.com`) |
| **sourceIPAddress** | IP address of the API caller; `AWS Internal` indicates service-to-service calls |
| **Privilege escalation path** | Sequence of IAM API calls that results in gaining elevated permissions (e.g., `CreateAccessKey` → `AttachUserPolicy`) |
| **Impossible travel** | Authentication from two geographically distant IPs within a time window too short for physical travel |

## Tools & Systems

- **boto3**: AWS SDK for Python; `cloudtrail` client provides `lookup_events` and paginator support
- **Amazon Detective**: Managed AWS service for CloudTrail behavioral analysis with built-in ML baselining
- **AWS Security Hub**: Aggregates CloudTrail-derived findings from GuardDuty, Inspector, and Macie
- **Athena + S3**: For querying full CloudTrail history beyond 90 days when logs are shipped to S3

## Common Scenarios

### Scenario: Investigating a Compromised IAM Access Key

**Context**: GuardDuty triggered an alert for `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`. The access key belongs to an EC2 instance role, but API calls are originating from an external IP.

**Approach**:
1. Run `get_cloudtrail_events` filtered by the access key ID (`LookupAttributeKey: AccessKeyId`)
2. Extract `sourceIPAddress` values and group by time window to build an activity timeline
3. Flag any `AttachUserPolicy`, `CreateAccessKey`, or `GetSecretValue` calls — these indicate post-compromise escalation
4. Check for `StopLogging` or `DeleteTrail` calls — common attacker anti-forensics step
5. Cross-reference source IPs against threat intelligence feeds
6. Revoke the access key immediately and capture the full event list before evidence window closes

**Pitfalls**:
- CloudTrail `lookup_events` only returns 90 days of history and is eventually consistent; for incidents older than 24h, query S3-backed logs directly with Athena
- Role-assumed sessions appear under the assumed role ARN, not the original principal; trace `AssumeRole` calls backward to find the original identity

### Scenario: Baselining Before Enabling GuardDuty Alerts

**Context**: The team is enabling GuardDuty in a new AWS account and needs to understand what "normal" looks like before alert thresholds are set — to avoid alert fatigue from CI/CD pipeline activity.

**Approach**:
1. Run the baseline builder over 7 days of CloudTrail history
2. Identify users/roles with consistently high API call volumes (CI/CD service accounts)
3. Document which sensitive APIs are legitimately called by automation (e.g., `GetSecretValue` by app deploy role)
4. Export the baseline as suppression rules for GuardDuty finding filters

**Pitfalls**:
- Don't baseline during an incident — compromised credential activity will inflate "normal" thresholds
- Service-linked roles generate many API calls that appear anomalous but are expected; filter by `userAgent` to identify AWS-internal callers

## Output Format

```
CLOUDTRAIL ANOMALY DETECTION REPORT
=====================================
Generated:      2025-10-15T09:00:00Z
Period:         24 hours
Total Events:   1,842
Unique Users:   23
Anomalies:      7

TOP SUSPICIOUS USERS
User                    Risk Score  Anomaly Types
alice@example.com       17          SENSITIVE_API (x3), HIGH_FREQUENCY
svc-deploy              4           SENSITIVE_API (x2)
bob@example.com         2           MULTIPLE_SOURCE_IPS

ANOMALIES (sorted by severity)
Severity  Type                 User                  Detail
HIGH      SENSITIVE_API        alice@example.com     CreateAccessKey (2 calls)
HIGH      SENSITIVE_API        alice@example.com     AttachUserPolicy (1 call)
HIGH      SENSITIVE_API        alice@example.com     GetSecretValue (8 calls)
HIGH      SENSITIVE_API        svc-deploy            Decrypt (15 calls)
HIGH      SENSITIVE_API        svc-deploy            GetParameter (42 calls)
MEDIUM    HIGH_FREQUENCY       alice@example.com     DescribeInstances (87 calls)
MEDIUM    MULTIPLE_SOURCE_IPS  bob@example.com       4 IPs: [203.0.113.5, 198.51.100.7, ...]

Report saved to: cloudtrail_anomaly_report.json
```
