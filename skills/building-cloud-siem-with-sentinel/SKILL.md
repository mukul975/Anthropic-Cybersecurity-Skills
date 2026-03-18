---
name: building-cloud-siem-with-sentinel
description: >
  This skill covers deploying Microsoft Sentinel as a cloud-native SIEM and SOAR
  platform for centralized security operations. It details configuring data connectors
  for multi-cloud log ingestion, writing KQL detection queries, building automated
  response playbooks with Logic Apps, and leveraging the Sentinel data lake for
  petabyte-scale threat hunting across AWS, Azure, and GCP security telemetry.
domain: cybersecurity
subdomain: cloud-security
tags: [microsoft-sentinel, cloud-siem, kql-queries, soar-automation, threat-detection]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Building Cloud SIEM with Sentinel

## When to Use

- When establishing a centralized security operations center for multi-cloud environments
- When migrating from legacy SIEM platforms (Splunk, QRadar) to cloud-native architecture
- When building automated incident response workflows for cloud-specific threats
- When performing large-scale threat hunting across petabytes of security telemetry
- When integrating threat intelligence feeds with cloud security log analysis

**Do not use** for AWS-only environments where Security Hub and GuardDuty suffice, for endpoint detection requiring EDR capabilities (use Defender for Endpoint), or for compliance posture monitoring (see building-cloud-security-posture-management).

## Prerequisites

- Azure subscription with Microsoft Sentinel enabled on a Log Analytics workspace
- Data connector permissions for target log sources (AWS CloudTrail, Azure Activity, GCP)
- Logic Apps or Azure Functions for automated response playbooks
- KQL (Kusto Query Language) proficiency for writing detection rules and hunting queries

## Workflow

### Step 1: Provision Sentinel Workspace and Data Connectors

Create a Log Analytics workspace optimized for security data and enable data connectors for multi-cloud ingestion.

```powershell
# Create Log Analytics workspace
az monitor log-analytics workspace create \
  --resource-group security-rg \
  --workspace-name sentinel-workspace \
  --location eastus \
  --retention-time 365 \
  --sku PerGB2018

# Enable Microsoft Sentinel on the workspace
az sentinel onboarding-state create \
  --resource-group security-rg \
  --workspace-name sentinel-workspace

# Enable AWS CloudTrail connector
az sentinel data-connector create \
  --resource-group security-rg \
  --workspace-name sentinel-workspace \
  --data-connector-id aws-cloudtrail \
  --kind AmazonWebServicesCloudTrail \
  --aws-cloud-trail-data-connector '{
    "awsRoleArn": "arn:aws:iam::123456789012:role/SentinelCloudTrailRole",
    "dataTypes": {"logs": {"state": "Enabled"}}
  }'

# Enable Azure AD sign-in and audit logs
az sentinel data-connector create \
  --resource-group security-rg \
  --workspace-name sentinel-workspace \
  --data-connector-id azure-ad \
  --kind AzureActiveDirectory \
  --azure-active-directory '{
    "dataTypes": {
      "alerts": {"state": "Enabled"},
      "signinLogs": {"state": "Enabled"},
      "auditLogs": {"state": "Enabled"}
    }
  }'
```

### Step 2: Write KQL Detection Rules

Create analytics rules using Kusto Query Language to detect cloud-specific threats. Map each rule to MITRE ATT&CK techniques.

```kql
// Detect impossible travel - sign-ins from geographically distant locations
let timeframe = 1h;
let distance_threshold = 500; // km
SigninLogs
| where TimeGenerated > ago(timeframe)
| where ResultType == 0 // Successful sign-ins only
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          Latitude = toreal(LocationDetails.geoCoordinates.latitude),
          Longitude = toreal(LocationDetails.geoCoordinates.longitude)
| sort by UserPrincipalName asc, TimeGenerated asc
| extend PrevLatitude = prev(Latitude, 1), PrevLongitude = prev(Longitude, 1),
         PrevTime = prev(TimeGenerated, 1), PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser
| extend TimeDiff = datetime_diff('minute', TimeGenerated, PrevTime)
| where TimeDiff < 60
| extend Distance = geo_distance_2points(Longitude, Latitude, PrevLongitude, PrevLatitude) / 1000
| where Distance > distance_threshold
| project TimeGenerated, UserPrincipalName, IPAddress, Location, Distance, TimeDiff
```

```kql
// Detect AWS IAM credential abuse from CloudTrail
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where EventName in ("ConsoleLogin", "AssumeRole", "GetSessionToken")
| where ErrorCode == ""
| summarize LoginCount = count(), DistinctIPs = dcount(SourceIpAddress),
            IPList = make_set(SourceIpAddress, 10)
            by UserIdentityArn, bin(TimeGenerated, 1h)
| where DistinctIPs > 3
| project TimeGenerated, UserIdentityArn, LoginCount, DistinctIPs, IPList
```

```kql
// Detect mass S3 object deletion (potential ransomware)
AWSCloudTrail
| where TimeGenerated > ago(1h)
| where EventName == "DeleteObject" or EventName == "DeleteObjects"
| summarize DeleteCount = count(), BucketsAffected = dcount(RequestParameters_bucketName)
            by UserIdentityArn, bin(TimeGenerated, 10m)
| where DeleteCount > 100
| project TimeGenerated, UserIdentityArn, DeleteCount, BucketsAffected
```

### Step 3: Build SOAR Playbooks with Logic Apps

Create automated response playbooks that execute when analytics rules trigger incidents. Common actions include blocking users, isolating resources, and enriching alerts with threat intelligence.

```json
{
  "definition": {
    "triggers": {
      "Microsoft_Sentinel_incident": {
        "type": "ApiConnectionWebhook",
        "inputs": {
          "body": {"incidentArmId": "subscriptions/@{triggerBody()?['workspaceInfo']?['SubscriptionId']}/resourceGroups/@{triggerBody()?['workspaceInfo']?['ResourceGroupName']}/providers/Microsoft.OperationalInsights/workspaces/@{triggerBody()?['workspaceInfo']?['WorkspaceName']}/providers/Microsoft.SecurityInsights/Incidents/@{triggerBody()?['object']?['properties']?['incidentNumber']}"},
          "host": {"connection": {"name": "@parameters('$connections')['microsoftsentinel']['connectionId']"}}
        }
      }
    },
    "actions": {
      "Get_incident_entities": {
        "type": "ApiConnection",
        "inputs": {"method": "post", "path": "/Incidents/entities"}
      },
      "For_each_account_entity": {
        "type": "Foreach",
        "foreach": "@body('Get_incident_entities')?['Accounts']",
        "actions": {
          "Disable_Azure_AD_user": {
            "type": "ApiConnection",
            "inputs": {
              "method": "PATCH",
              "path": "/v1.0/users/@{items('For_each_account_entity')?['AadUserId']}",
              "body": {"accountEnabled": false}
            }
          },
          "Add_comment_to_incident": {
            "type": "ApiConnection",
            "inputs": {
              "body": {"message": "User @{items('For_each_account_entity')?['Name']} disabled by automated playbook"}
            }
          }
        }
      }
    }
  }
}
```

### Step 4: Configure Sentinel Data Lake for Long-Term Hunting

Enable the Sentinel data lake for petabyte-scale log retention and advanced threat hunting using both KQL and SQL endpoints.

```kql
// Threat hunting query: detect lateral movement across AWS accounts
let suspicious_roles = AWSCloudTrail
| where TimeGenerated > ago(7d)
| where EventName == "AssumeRole"
| extend AssumedRoleArn = tostring(parse_json(RequestParameters).roleArn)
| where AssumedRoleArn contains "cross-account" or AssumedRoleArn contains "admin"
| summarize AssumeCount = count(), UniqueSourceAccounts = dcount(RecipientAccountId)
            by UserIdentityArn, AssumedRoleArn
| where AssumeCount > 10 and UniqueSourceAccounts > 2;
suspicious_roles
| join kind=inner (
    AWSCloudTrail
    | where TimeGenerated > ago(7d)
    | where EventName in ("RunInstances", "CreateFunction", "PutBucketPolicy")
) on UserIdentityArn
| project TimeGenerated, UserIdentityArn, AssumedRoleArn, EventName, SourceIpAddress
```

### Step 5: Integrate Threat Intelligence

Connect threat intelligence providers and create indicator-based matching rules to detect communication with known malicious infrastructure.

```powershell
# Enable Microsoft Threat Intelligence connector
az sentinel data-connector create \
  --resource-group security-rg \
  --workspace-name sentinel-workspace \
  --data-connector-id microsoft-ti \
  --kind MicrosoftThreatIntelligence \
  --microsoft-threat-intelligence '{
    "dataTypes": {"microsoftEmergingThreatFeed": {"lookbackPeriod": "2025-01-01T00:00:00Z", "state": "Enabled"}}
  }'
```

```kql
// Match network indicators against cloud flow logs
let TI_IPs = ThreatIntelligenceIndicator
| where TimeGenerated > ago(30d)
| where isnotempty(NetworkIP)
| distinct NetworkIP;
AzureNetworkAnalytics_CL
| where TimeGenerated > ago(24h)
| where DestIP_s in (TI_IPs)
| project TimeGenerated, SrcIP_s, DestIP_s, DestPort_d, FlowType_s
```

## Key Concepts

| Term | Definition |
|------|------------|
| KQL | Kusto Query Language, the primary query language for Microsoft Sentinel used to search, analyze, and visualize security data |
| Analytics Rule | Detection logic in Sentinel that evaluates log data on a schedule and creates incidents when conditions match |
| SOAR Playbook | Automated workflow triggered by incidents that performs response actions such as blocking accounts, enriching alerts, or notifying teams |
| Data Connector | Integration module that ingests security logs from cloud services, identity providers, and third-party tools into Sentinel |
| Sentinel Data Lake | Petabyte-scale storage layer providing long-term log retention with KQL and SQL query interfaces for advanced hunting |
| Workbook | Interactive dashboard in Sentinel displaying visualizations of security data, trends, and operational metrics |
| Watchlist | Reference data tables in Sentinel used to enrich alerts with context such as VIP user lists or approved IP ranges |
| Fusion Detection | Machine learning-powered correlation engine that automatically detects multi-stage attacks across data sources |

## Tools & Systems

- **Microsoft Sentinel**: Cloud-native SIEM/SOAR platform built on Azure Log Analytics with AI-powered threat detection
- **Azure Logic Apps**: Low-code automation platform for building SOAR playbooks triggered by Sentinel incidents
- **Microsoft Threat Intelligence**: Integrated threat feeds providing IP, domain, and URL indicators for matching against security logs
- **Azure Data Explorer**: High-performance analytics engine underlying Sentinel KQL queries for large-scale data exploration
- **MITRE ATT&CK Navigator**: Framework for mapping Sentinel detection rules to adversary tactics and techniques

## Common Scenarios

### Scenario: Detecting Cross-Cloud Credential Theft Campaign

**Context**: An attacker compromises an Azure AD account through phishing, then uses the account to access AWS resources via federated identity. Sentinel needs to correlate the Azure sign-in anomaly with unusual AWS API activity.

**Approach**:
1. Create an analytics rule detecting Azure AD impossible travel or anomalous sign-in risk
2. Write a KQL query correlating the compromised Azure AD identity with AWS CloudTrail AssumeRoleWithSAML events
3. Build a Fusion detection rule that links Azure AD risk events with subsequent AWS privilege escalation activity
4. Deploy a SOAR playbook that automatically disables the Azure AD account and revokes AWS STS sessions
5. Create a workbook showing the timeline from initial compromise through lateral movement to AWS
6. Run a hunting query across the data lake to check for similar patterns affecting other accounts

**Pitfalls**: Not correlating identity across cloud providers misses the full attack chain. Setting analytics rule frequency too low (e.g., 24 hours) allows attackers hours of undetected access.

## Output Format

```
Microsoft Sentinel SOC Operations Report
==========================================
Workspace: sentinel-workspace
Data Sources: 14 connectors active
Report Period: 2025-02-01 to 2025-02-23

DATA INGESTION:
  Azure AD Sign-in Logs:     2.3 TB (23 days)
  AWS CloudTrail:            1.8 TB (23 days)
  Azure Activity:            0.9 TB (23 days)
  Defender for Cloud Alerts: 45 GB (23 days)
  Total Ingestion:           5.1 TB

DETECTION SUMMARY:
  Active Analytics Rules: 87
  Incidents Created: 234
    Critical: 8 | High: 34 | Medium: 89 | Low: 103
  Mean Time to Detect (MTTD): 4.2 minutes
  Mean Time to Respond (MTTR): 18 minutes

TOP INCIDENT TYPES:
  Impossible Travel Detected:          42 incidents
  AWS Unauthorized API Call Pattern:   28 incidents
  Mass File Deletion in S3:            3 incidents
  Suspicious Azure AD App Registration: 12 incidents

AUTOMATION:
  Playbooks Executed: 156
  Accounts Auto-Disabled: 23
  Incidents Auto-Enriched: 198
  False Positive Rate: 12%
```
