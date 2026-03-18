---
name: detecting-compromised-cloud-credentials
description: >
  Detecting compromised cloud credentials across AWS, Azure, and GCP by analyzing
  anomalous API activity, impossible travel patterns, unauthorized resource provisioning,
  and credential abuse indicators using GuardDuty, Defender for Identity, and SCC
  Event Threat Detection.
domain: cybersecurity
subdomain: cloud-security
tags: [cloud-security, credential-compromise, threat-detection, guardduty, incident-response, anomaly-detection]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting Compromised Cloud Credentials

## When to Use

- When investigating alerts about unusual cloud API activity from unfamiliar locations
- When building detection rules for credential theft and abuse across cloud environments
- When responding to notifications from cloud providers about exposed credentials
- When monitoring for credential stuffing or brute force attacks against cloud identities
- When assessing the scope of a credential compromise after initial detection

**Do not use** for preventing credential compromise (use MFA, credential rotation, and secrets management), for detecting application-level credential theft (use application security monitoring), or for endpoint credential harvesting detection (use EDR tools).

## Prerequisites

- AWS GuardDuty enabled across all accounts and regions
- Azure Defender for Identity and Entra ID Protection configured
- GCP Security Command Center with Event Threat Detection enabled
- CloudTrail, Azure Activity Log, and GCP Audit Log centralized for analysis
- SIEM integration for cross-cloud correlation of credential abuse indicators
- Threat intelligence feeds for known malicious IP ranges

## Workflow

### Step 1: Detect Credential Compromise Indicators in AWS

Monitor GuardDuty findings and CloudTrail anomalies that indicate credential abuse.

```bash
# List GuardDuty credential-related findings
aws guardduty list-findings \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --finding-criteria '{
    "Criterion": {
      "type": {
        "Eq": [
          "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
          "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
          "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
          "UnauthorizedAccess:IAMUser/TorIPCaller",
          "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
          "Recon:IAMUser/MaliciousIPCaller",
          "Recon:IAMUser/MaliciousIPCaller.Custom",
          "InitialAccess:IAMUser/AnomalousBehavior",
          "CredentialAccess:IAMUser/AnomalousBehavior",
          "Persistence:IAMUser/AnomalousBehavior"
        ]
      },
      "service.archived": {"Eq": ["false"]}
    }
  }' --output json

# Check for console logins from new locations
aws logs start-query \
  --log-group-name cloudtrail-logs \
  --start-time $(date -d "7 days ago" +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields @timestamp, userIdentity.userName, sourceIPAddress, responseElements.ConsoleLogin
    | filter eventName = "ConsoleLogin"
    | filter responseElements.ConsoleLogin = "Success"
    | stats count() by userIdentity.userName, sourceIPAddress
    | sort count desc
  '

# Detect impossible travel (same user from geographically distant IPs within short time)
aws logs start-query \
  --log-group-name cloudtrail-logs \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields @timestamp, userIdentity.arn, sourceIPAddress, eventName
    | filter userIdentity.type = "IAMUser"
    | stats earliest(@timestamp) as first_seen, latest(@timestamp) as last_seen,
            count_distinct(sourceIPAddress) as unique_ips by userIdentity.arn
    | filter unique_ips > 3
  '
```

### Step 2: Detect Credential Abuse in Azure

Monitor Entra ID sign-in logs and Defender for Identity alerts for compromised credentials.

```bash
# Check for risky sign-ins
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=riskLevelDuringSignIn ne 'none' and createdDateTime ge 2026-02-16T00:00:00Z&\$top=50" \
  --query "value[*].{User:userPrincipalName,Risk:riskLevelDuringSignIn,IP:ipAddress,Location:location.city,App:appDisplayName,Status:status.errorCode}" \
  -o table

# Check for sign-ins from anonymous or Tor IPs
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=riskEventTypes_v2/any(r:r eq 'anonymizedIPAddress') and createdDateTime ge 2026-02-22T00:00:00Z" \
  --query "value[*].{User:userPrincipalName,IP:ipAddress,Location:location.city}" \
  -o table

# List users flagged as compromised by Identity Protection
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?\$filter=riskLevel eq 'high'" \
  --query "value[*].{User:userPrincipalName,RiskLevel:riskLevel,RiskState:riskState,LastDetected:riskLastUpdatedDateTime}" \
  -o table

# Check for suspicious application consent grants
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?\$filter=activityDisplayName eq 'Consent to application' and activityDateTime ge 2026-02-16T00:00:00Z" \
  --query "value[*].{Activity:activityDisplayName,User:initiatedBy.user.userPrincipalName,App:targetResources[0].displayName}" \
  -o table
```

### Step 3: Detect Credential Abuse in GCP

Query GCP audit logs and SCC findings for credential compromise indicators.

```bash
# Check SCC Event Threat Detection findings
gcloud scc findings list ORG_ID \
  --filter="state=\"ACTIVE\" AND (category=\"ANOMALOUS_CALLER_LOCATION\" OR category=\"SUSPICIOUS_LOGIN\" OR category=\"CREDENTIAL_ACCESS\")" \
  --format="table(finding.category, finding.severity, finding.resourceName, finding.eventTime)"

# Query audit logs for service account key usage from unusual IPs
gcloud logging read '
  protoPayload.authenticationInfo.principalEmail:*@*.iam.gserviceaccount.com
  AND protoPayload.requestMetadata.callerIp!=("10." OR "172." OR "192.168.")
  AND timestamp>="2026-02-22T00:00:00Z"
' --limit=100 --format="table(timestamp, protoPayload.authenticationInfo.principalEmail, protoPayload.requestMetadata.callerIp, protoPayload.methodName)"

# Detect API calls from Tor exit nodes
gcloud logging read '
  protoPayload.requestMetadata.callerIp:("185." OR "198." OR "45.")
  AND protoPayload.authenticationInfo.principalEmail:*@company.com
  AND timestamp>="2026-02-22T00:00:00Z"
' --limit=50 --format=json

# Check for new service account keys created (persistence indicator)
gcloud logging read '
  protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"
  AND timestamp>="2026-02-16T00:00:00Z"
' --format="table(timestamp, protoPayload.authenticationInfo.principalEmail, protoPayload.request.name)"
```

### Step 4: Build Cross-Cloud Correlation Rules

Create SIEM rules that correlate credential abuse indicators across cloud providers.

```python
# siem_correlation.py - Cross-cloud credential abuse detection
import json
from datetime import datetime, timedelta

def detect_impossible_travel(events):
    """Detect same identity used from distant locations in short timeframe."""
    user_events = {}
    for event in events:
        user = event.get('principal', '')
        ip = event.get('source_ip', '')
        ts = event.get('timestamp', '')
        cloud = event.get('cloud_provider', '')

        key = f"{user}_{cloud}"
        if key not in user_events:
            user_events[key] = []
        user_events[key].append({'ip': ip, 'timestamp': ts, 'cloud': cloud})

    alerts = []
    for user_key, accesses in user_events.items():
        accesses.sort(key=lambda x: x['timestamp'])
        for i in range(1, len(accesses)):
            time_diff = (datetime.fromisoformat(accesses[i]['timestamp']) -
                        datetime.fromisoformat(accesses[i-1]['timestamp']))
            if time_diff < timedelta(hours=1) and accesses[i]['ip'] != accesses[i-1]['ip']:
                alerts.append({
                    'type': 'IMPOSSIBLE_TRAVEL',
                    'user': user_key,
                    'ip_1': accesses[i-1]['ip'],
                    'ip_2': accesses[i]['ip'],
                    'time_gap_minutes': time_diff.total_seconds() / 60,
                    'severity': 'HIGH'
                })
    return alerts

def detect_credential_stuffing(events, threshold=10):
    """Detect multiple failed logins followed by success."""
    user_attempts = {}
    for event in events:
        user = event.get('principal', '')
        success = event.get('success', False)
        key = user
        if key not in user_attempts:
            user_attempts[key] = {'failures': 0, 'success_after_failures': False}
        if not success:
            user_attempts[key]['failures'] += 1
        elif user_attempts[key]['failures'] >= threshold:
            user_attempts[key]['success_after_failures'] = True

    return [{'user': u, 'failures': d['failures'], 'severity': 'CRITICAL'}
            for u, d in user_attempts.items() if d['success_after_failures']]
```

### Step 5: Respond to Confirmed Credential Compromise

Execute containment actions when credential compromise is confirmed.

```bash
# AWS: Deactivate access key immediately
aws iam update-access-key --user-name COMPROMISED_USER \
  --access-key-id AKIA_COMPROMISED --status Inactive

# AWS: Invalidate temporary role credentials by updating role trust policy
aws iam update-assume-role-policy --role-name COMPROMISED_ROLE \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"}]}'

# AWS: Revoke all sessions for an IAM user
aws iam put-user-policy --user-name COMPROMISED_USER \
  --policy-name RevokeOldSessions \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Deny",
      "Action":"*",
      "Resource":"*",
      "Condition":{"DateLessThan":{"aws:TokenIssueTime":"2026-02-23T10:00:00Z"}}
    }]
  }'

# Azure: Revoke all sign-in sessions
az rest --method POST \
  --url "https://graph.microsoft.com/v1.0/users/COMPROMISED_USER_ID/revokeSignInSessions"

# Azure: Force password reset
az ad user update --id COMPROMISED_USER_ID --force-change-password-next-sign-in true

# GCP: Disable service account
gcloud iam service-accounts disable COMPROMISED_SA_EMAIL

# GCP: Delete service account keys
gcloud iam service-accounts keys delete KEY_ID --iam-account=COMPROMISED_SA_EMAIL
```

## Key Concepts

| Term | Definition |
|------|------------|
| Impossible Travel | Detection of the same credential being used from geographically distant locations within a time period that makes physical travel impossible |
| Credential Stuffing | Attack using stolen username/password combinations from data breaches to attempt login across multiple cloud services |
| Instance Credential Exfiltration | GuardDuty finding indicating EC2 instance role credentials are being used from outside the expected AWS network |
| Anomalous Behavior | Machine learning-based detection of API call patterns that deviate significantly from the established baseline for a principal |
| Session Revocation | Invalidating all active authentication sessions for a compromised principal to force re-authentication with new credentials |
| Persistence Indicator | Attacker actions designed to maintain access after initial compromise, such as creating new access keys or service account keys |

## Tools & Systems

- **AWS GuardDuty**: ML-based threat detection with specific finding types for credential compromise and unauthorized access
- **Microsoft Entra ID Protection**: Identity risk detection for sign-in anomalies, compromised credentials, and risky user behavior
- **GCP Event Threat Detection**: SCC component detecting anomalous API usage and credential abuse in GCP environments
- **CloudTrail / Activity Log / Audit Log**: API audit logs providing the raw data for credential compromise investigation
- **SIEM (Splunk, Elastic, Sentinel)**: Centralized platform for cross-cloud correlation of credential abuse indicators

## Common Scenarios

### Scenario: Detecting an Access Key Compromised via Phishing

**Context**: A developer receives a phishing email that harvests their AWS console credentials. The attacker logs in from a foreign IP, creates a new access key, and begins enumerating the account.

**Approach**:
1. GuardDuty triggers `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` for login from unusual country
2. SOC reviews the finding and correlates with phishing reports from the email security team
3. Query CloudTrail for all actions by the compromised user from the attacker's IP
4. Discover the attacker created new access keys and ran IAM enumeration commands
5. Immediately deactivate all access keys for the user and revoke active sessions
6. Force password reset and re-enroll MFA
7. Check for persistence: new IAM users, roles, Lambda functions, or EC2 instances created
8. Remove any persistence artifacts and document the incident timeline

**Pitfalls**: Simply changing the password does not invalidate existing access keys or active sessions. All access keys must be rotated and temporary credentials revoked by adding a deny-all policy for tokens issued before the compromise was detected. Attackers may create new IAM users or roles for persistence before the initial credential is revoked.

## Output Format

```
Cloud Credential Compromise Detection Report
===============================================
Detection Date: 2026-02-23
Scope: Multi-cloud (AWS, Azure, GCP)
Period: 2026-02-16 to 2026-02-23

ACTIVE COMPROMISE INDICATORS:
[CRED-001] AWS Console Login from Unusual Location
  User: developer@company.com
  Source IP: 185.x.x.x (Russia)
  Normal Location: US-East
  GuardDuty Finding: UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B
  Severity: HIGH
  Status: Credential deactivated

[CRED-002] Azure Impossible Travel Detection
  User: admin@company.onmicrosoft.com
  Location 1: New York, US (09:00 UTC)
  Location 2: Beijing, CN (09:15 UTC)
  Risk Level: HIGH
  Status: Sessions revoked, under investigation

DETECTION METRICS (Last 7 Days):
  Impossible travel detections:        5
  Anomalous API activity alerts:      12
  Failed login attempts > threshold:   3
  New credentials from unusual IPs:    2
  Total compromises confirmed:         2

CONTAINMENT ACTIONS TAKEN:
  AWS access keys deactivated:    3
  Azure sessions revoked:         2
  GCP service accounts disabled:  1
  Passwords force-reset:          4
  MFA re-enrolled:                4
```
