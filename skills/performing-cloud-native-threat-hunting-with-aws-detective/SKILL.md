---
name: performing-cloud-native-threat-hunting-with-aws-detective
description: >-
  Hunt for threats in AWS environments using Detective behavior graphs, entity
  investigation timelines, GuardDuty finding correlation, and automated entity
  profiling across IAM users, EC2 instances, and IP addresses. Use when the user
  asks about investigating suspicious AWS activity, correlating GuardDuty alerts,
  analyzing Detective findings, or hunting threats across AWS accounts.
domain: cybersecurity
subdomain: cloud-security
tags: [aws-detective, threat-hunting, cloud-security, guardduty, behavior-graph, aws, iam, ec2, incident-investigation]
version: "1.0"
author: juliosuas
license: Apache-2.0
---

# Performing Cloud-Native Threat Hunting with AWS Detective

## Prerequisites

- AWS account with Detective enabled (requires GuardDuty active for 48+ hours)
- AWS CLI v2 with IAM permissions: `detective:ListGraphs`, `detective:ListInvestigations`, `detective:GetInvestigation`, `detective:ListIndicators`, `guardduty:List*`
- Python 3.9+ with boto3

## Steps

### Step 1: List Available Behavior Graphs

```bash
aws detective list-graphs --output table
```

If no graphs are returned, Detective is not enabled. Enable it via the Console or `aws detective create-graph`. Graphs need 48+ hours of data before investigations produce meaningful results.

**Checkpoint:** Confirm at least one graph ARN is returned before proceeding.

### Step 2: Investigate a Suspicious IAM User

```bash
# Get entity profile for an IAM user
aws detective get-investigation \
  --graph-arn arn:aws:detective:us-east-1:123456789012:graph:a1b2c3d4 \
  --investigation-id 000000000000000000001
```

### Step 3: Search Entities Programmatically

```python
#!/usr/bin/env python3
"""Search AWS Detective for suspicious entities."""
import boto3
import json
from datetime import datetime, timedelta

detective = boto3.client('detective')

def list_behavior_graphs():
    """List all Detective behavior graphs."""
    response = detective.list_graphs()
    return response.get('GraphList', [])

def get_investigation_indicators(graph_arn, investigation_id, max_results=50):
    """Get indicators for a specific investigation."""
    response = detective.list_indicators(
        GraphArn=graph_arn,
        InvestigationId=investigation_id,
        MaxResults=max_results
    )
    return response.get('Indicators', [])

def investigate_guardduty_findings(graph_arn):
    """List high-severity investigations correlated by Detective."""
    response = detective.list_investigations(
        GraphArn=graph_arn,
        FilterCriteria={
            'Severity': {'Value': 'CRITICAL'},
            'Status': {'Value': 'RUNNING'}
        },
        MaxResults=20
    )

    for investigation in response.get('InvestigationDetails', []):
        print(f"Investigation: {investigation['InvestigationId']}")
        print(f"  Entity: {investigation['EntityArn']}")
        print(f"  Status: {investigation['Status']}")
        print(f"  Severity: {investigation['Severity']}")
        print(f"  Created: {investigation['CreatedTime']}")
        print()

if __name__ == "__main__":
    graphs = list_behavior_graphs()
    for graph in graphs:
        print(f"Graph: {graph['Arn']}")
        investigate_guardduty_findings(graph['Arn'])
```

**Checkpoint:** Verify the script returns investigations with valid `EntityArn` and `Severity` fields before proceeding to triage.

### Step 4: Analyze Finding Groups for Attack Campaigns

```bash
# List investigations with high severity
aws detective list-investigations \
  --graph-arn arn:aws:detective:us-east-1:123456789012:graph:a1b2c3d4 \
  --filter-criteria '{"Severity":{"Value":"HIGH"}}' \
  --max-results 10
```

### Step 5: Check Entity Indicators

```bash
# Get indicators for a specific investigation
aws detective list-indicators \
  --graph-arn arn:aws:detective:us-east-1:123456789012:graph:a1b2c3d4 \
  --investigation-id 000000000000000000001 \
  --max-results 50
```

### Step 6: Interpret Indicators and Decide Next Actions

Triage based on indicator type returned by `list-indicators`:

| Indicator Type | Meaning | Next Action |
|---------------|---------|-------------|
| `TTP_OBSERVED` | Known MITRE ATT&CK technique detected | Map to ATT&CK matrix, check for lateral movement |
| `IMPOSSIBLE_TRAVEL` | Entity authenticated from geographically distant locations | Verify with user, likely credential compromise |
| `FLAGGED_IP_ADDRESS` | Communication with known-malicious IP | Block IP in security groups/NACLs, check other entities contacting same IP |
| `NEW_GEOLOCATION` / `NEW_ASO` | Activity from unusual location or network | Compare against baseline, escalate if unexpected |
| `NEW_USER_AGENT` | Unfamiliar tooling used by entity | Check if legitimate tooling change or adversary tool |
| `RELATED_FINDING` | Linked GuardDuty finding | Pull full finding via `aws guardduty get-findings` for detail |
| `RELATED_FINDING_GROUP` | Part of correlated attack campaign | Investigate all entities in the group as a single incident |

## Verification

1. `aws detective list-graphs` returns at least one graph with an active ARN
2. Investigation queries return results with valid `EntityArn` and `Severity` fields
3. Indicator types match expected categories from the triage table above
4. For `RELATED_FINDING` indicators, cross-reference the linked GuardDuty finding ID via `aws guardduty get-findings` to confirm accuracy
5. For `IMPOSSIBLE_TRAVEL`, verify the geographic distance is genuine (not VPN/proxy) before escalating