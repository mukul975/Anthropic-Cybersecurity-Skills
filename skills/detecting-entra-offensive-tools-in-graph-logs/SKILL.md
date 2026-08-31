---
name: detecting-entra-offensive-tools-in-graph-logs
description: Hunt AADGraphActivityLogs and MicrosoftGraphActivityLogs in Microsoft Sentinel/Log Analytics using KQL to fingerprint offensive Entra ID enumeration tools such as ROADtools, AADInternals, and AzureHound, including User-Agent signatures, roadrecon endpoint sweeps, and sign-in correlation. Use when investigating suspicious Microsoft Graph API activity, Entra ID reconnaissance, or building Sentinel analytics rules to detect these tools.
domain: cybersecurity
subdomain: soc-operations
tags:
- threat-hunting
- entra-id
- microsoft-graph
- kql
- sentinel
- roadtools
- aadinternals
- detection-engineering
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-09
mitre_attack:
- T1078.004
---
# Detecting Entra Offensive Tools in Graph Logs

## Overview

For nearly a decade the legacy **Azure AD Graph API** (`graph.windows.net`) was a defender blind spot: requests to it produced no first-class activity log, so tools like ROADtools (`roadrecon`) and AADInternals — which lean heavily on AAD Graph — could enumerate an entire tenant with little trace. That changed when Microsoft shipped **AADGraphActivityLogs** (general availability in 2026), the counterpart to the already-available **MicrosoftGraphActivityLogs** (`graph.microsoft.com`). Together these two tables give SOCs request-level visibility into directory API traffic: the caller identity, app, source IP, HTTP method, request URI, and crucially the **User-Agent**.

This skill is the defensive complement to offensive Entra tooling. It hunts the two Graph activity tables for the behavioral and string fingerprints those tools leave behind. Many operators forget to spoof the User-Agent, so ROADtools (built on Python's `aiohttp`) emits a User-Agent like `Python/3.12 aiohttp/3.10.4`, and AADInternals frequently leaves `AADInternals` or library strings in the agent. Even when the agent is spoofed, the tools betray themselves through a characteristic **endpoint-sweep pattern**: `roadrecon gather` pulls `users`, `groups`, `applications`, `serviceprincipals`, `devices`, `directoryroles`, `roledefinitions`, `oauth2permissiongrants`, and more within a tight time window — a signature that survives header spoofing.

The activity being detected maps to MITRE ATT&CK **T1078.004 – Valid Accounts: Cloud Accounts**: an adversary using legitimate (often phished or token-stolen) cloud credentials to enumerate and operate against the tenant via the Graph APIs. These detections both surface live intrusions and validate that the offensive techniques in the companion red-team skills are observable.

## When to Use

- Building or tuning detections for Microsoft Sentinel / Log Analytics covering Entra ID
- Threat hunting after suspected credential theft, device-code phishing, or OAuth consent abuse
- Purple-team exercises validating that ROADtools/AADInternals/AzureHound activity is detectable
- Investigating an alert and needing to correlate Graph API calls back to a sign-in/session
- Closing the legacy Azure AD Graph visibility gap after enabling AADGraphActivityLogs

## Prerequisites

- A Microsoft Sentinel workspace (or Log Analytics) ingesting:
  - **MicrosoftGraphActivityLogs** (diagnostic setting on Microsoft Entra ID -> graph.microsoft.com)
  - **AADGraphActivityLogs** (diagnostic setting on Microsoft Entra ID -> legacy Azure AD Graph)
- `SigninLogs` and `AADNonInteractiveUserSignInLogs` for correlation
- Microsoft Sentinel Reader/Responder (or Log Analytics Reader) RBAC to run KQL
- Familiarity with Kusto Query Language (KQL)
- Enable the diagnostic settings (Azure Portal -> Microsoft Entra ID -> Diagnostic settings -> send `MicrosoftGraphActivityLogs` and `AADGraphActivityLogs` to your workspace), or via CLI:
  ```bash
  az monitor diagnostic-settings create \
    --name "entra-graph-logs" \
    --resource "/providers/microsoft.aadiam/diagnosticSettings" \
    --logs '[{"category":"MicrosoftGraphActivityLogs","enabled":true},{"category":"AADGraphActivityLogs","enabled":true}]' \
    --workspace "<log-analytics-workspace-id>"
  ```

## Objectives

- Confirm both Graph activity tables are flowing into the workspace
- Detect User-Agent string fingerprints of ROADtools, AADInternals, and AzureHound
- Detect the endpoint-sweep behavioral fingerprint that survives User-Agent spoofing
- Correlate suspicious Graph activity back to a sign-in/session and source identity
- Operationalize the best queries as scheduled analytics rules

## MITRE ATT&CK Mapping

| ID | Technique | Application in this skill |
|----|-----------|---------------------------|
| T1078.004 | Valid Accounts: Cloud Accounts | Detecting adversaries using valid cloud credentials/tokens to enumerate the tenant via the Microsoft Graph and legacy Azure AD Graph APIs |

Related techniques surfaced by these hunts: **T1087.004** Account Discovery: Cloud Account, **T1069.003** Permission Groups Discovery: Cloud Groups, **T1526** Cloud Service Discovery.

## Workflow

### Step 1: Confirm both tables are ingesting
Before hunting, verify the data exists and inspect the schema fields you will pivot on.

```kusto
union withsource=Tbl MicrosoftGraphActivityLogs, AADGraphActivityLogs
| where TimeGenerated > ago(1d)
| summarize Records=count(), LastSeen=max(TimeGenerated) by Tbl
```

### Step 2: Hunt User-Agent fingerprints (ROADtools / aiohttp)
ROADtools uses `aiohttp`; an un-spoofed run shows `python` + `aiohttp` in the User-Agent.

```kusto
AADGraphActivityLogs
| where TimeGenerated > ago(7d)
| where RequestMethod == "GET"
| where UserAgent contains "python" and UserAgent contains "aiohttp"
| summarize RequestCount = count() by CallerIpAddress, AppId, UserAgent, UserId
| sort by RequestCount desc
```

### Step 3: Hunt AADInternals and AzureHound agents
AADInternals leaves toolkit/library strings; AzureHound's Go HTTP client and BloodHound tooling have distinctive agents.

```kusto
union MicrosoftGraphActivityLogs, AADGraphActivityLogs
| where TimeGenerated > ago(7d)
| where UserAgent has_any ("AADInternals", "aad-internals", "azurehound",
                           "BloodHound", "python-requests", "Go-http-client")
| project TimeGenerated, UserAgent, CallerIpAddress, AppId, UserId, RequestUri
| sort by TimeGenerated desc
```

### Step 4: Behavioral hunt — the roadrecon endpoint sweep (spoof-resistant)
Even with a spoofed agent, `roadrecon gather` touches a recognizable set of directory resources in a short window. Bucket by user and 5 minutes; alert when one identity hits the full sweep.

```kusto
AADGraphActivityLogs
| where TimeGenerated > ago(1d)
| where RequestMethod == "GET"
| extend TopLevelResource = tolower(tostring(split(split(RequestUri, "?")[0], "/")[3]))
| summarize
    TopLevelResources = make_set(TopLevelResource),
    AppIds = make_set(AppId),
    CallerIPs = make_set(CallerIpAddress),
    UserAgents = make_set(UserAgent),
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated)
    by UserId, bin(TimeGenerated, 5m)
| where TopLevelResources has_all ("users", "tenantdetails", "groups", "applications",
    "serviceprincipals", "devices", "directoryroles", "roledefinitions", "contacts",
    "oauth2permissiongrants", "authorizationpolicy")
| project StartTime, EndTime, UserId, AppIds, CallerIPs, UserAgents
```

### Step 5: High-volume enumeration outliers
Catch tooling that simply makes far more directory reads than a human in a short window.

```kusto
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1d)
| where RequestMethod == "GET"
| where RequestUri has_any ("/users", "/groups", "/servicePrincipals", "/applications",
                            "/directoryRoles", "/roleManagement")
| summarize Reads=count(), Resources=dcount(RequestUri) by UserId, AppId, CallerIpAddress, bin(TimeGenerated, 10m)
| where Reads > 200
| sort by Reads desc
```

### Step 6: Correlate Graph activity to the originating sign-in
Pivot a suspicious Graph caller back to the sign-in to recover device, location, MFA, and conditional-access result. Note the `SignInActivityId` in AADGraphActivityLogs may carry `==` padding versus `SigninLogs.UniqueTokenIdentifier`.

```kusto
AADGraphActivityLogs
| where TimeGenerated > ago(1d)
| where UserAgent contains "aiohttp"
| extend TokenId = trim_end("=", tostring(SignInActivityId))
| join kind=leftouter (
    SigninLogs
    | extend TokenId = tostring(UniqueTokenIdentifier)
    | project TokenId, UserPrincipalName, IPAddress, AppDisplayName, ConditionalAccessStatus, DeviceDetail
) on TokenId
| project TimeGenerated, UserId, UserPrincipalName, CallerIpAddress, IPAddress,
          AppDisplayName, ConditionalAccessStatus, UserAgent
```

### Step 7: Operationalize as analytics rules
Promote the highest-fidelity queries (Steps 2-4) to scheduled analytics rules. Set a query period/frequency (e.g., run every 1h over 1d), map the rule to T1078.004, and configure entity mappings (Account = UserId, IP = CallerIpAddress, Host/App = AppId) so incidents enrich automatically. Tune out known automation/service-principal App IDs and approved scanner IPs via a watchlist before enabling.

## Tools and Resources

| Resource | Purpose | Source |
|----------|---------|--------|
| AADGraphActivityLogs reference | Schema and field meaning | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadgraphactivitylogs |
| MicrosoftGraphActivityLogs | Graph API activity schema | https://learn.microsoft.com/graph/microsoft-graph-activity-logs-overview |
| Invictus-IR writeup | AADGraphActivityLogs hunting queries | https://www.invictus-ir.com/news/the-missing-link-aadgraphactivitylogs-finally-arrives |
| Cloudbrothers analysis | Behavioral fingerprinting of ROADtools | https://cloudbrothers.info/en/aadgraphactivitylogs/ |
| ROADtools | The offensive tool being detected | https://github.com/dirkjanm/ROADtools |
| MITRE T1078.004 | Valid Accounts: Cloud Accounts | https://attack.mitre.org/techniques/T1078/004/ |

## Detection Fingerprint Reference

| Tool | Primary fingerprint | Table |
|------|---------------------|-------|
| ROADtools (roadrecon) | `python` + `aiohttp` UA; full directory endpoint sweep in 5 min | AADGraphActivityLogs |
| AADInternals | `AADInternals` / toolkit strings in UA; AAD Graph reads | AADGraphActivityLogs |
| AzureHound | Go HTTP client UA; broad MS Graph enumeration | MicrosoftGraphActivityLogs |
| Generic recon | High GET volume across users/groups/apps/SPs in short window | both |

## Validation Criteria

- [ ] Both MicrosoftGraphActivityLogs and AADGraphActivityLogs confirmed ingesting
- [ ] User-Agent fingerprint hunt for ROADtools/aiohttp executed
- [ ] AADInternals/AzureHound agent hunt executed
- [ ] Behavioral endpoint-sweep hunt executed and tuned for false positives
- [ ] High-volume enumeration outlier query executed
- [ ] At least one finding correlated back to a sign-in/session and source identity
- [ ] Best queries promoted to scheduled analytics rules with T1078.004 mapping and entity mappings
- [ ] Known-good service principals/IPs excluded via watchlist to control false positives
