---
name: performing-cloud-native-threat-hunting-with-aws-detective
description: Hunt for threats in AWS environments using Detective behavior graphs, entity investigation timelines, GuardDuty finding correlation, and automated entity profiling across IAM users, EC2 instances, and IP addresses.
domain: cybersecurity
subdomain: cloud-security
tags: [aws-detective, threat-hunting, cloud-security, guardduty, behavior-graph, aws, iam, ec2, incident-investigation]
version: "1.0"
author: juliosuas
license: Apache-2.0
---

# Performing Cloud-Native Threat Hunting with AWS Detective

## Overview

AWS Detective automatically collects and analyzes log data from AWS CloudTrail, VPC Flow Logs, GuardDuty findings, and EKS audit logs to build interactive behavior graphs. These graphs enable security analysts to investigate entities (IAM users, roles, IP addresses, EC2 instances) across time, identify anomalous API calls, detect lateral movement between accounts, and correlate GuardDuty findings into coherent attack narratives — all without manual log parsing.

## Prerequisites

- AWS account with Detective enabled (requires GuardDuty active for 48+ hours)
- AWS CLI v2 configured with appropriate IAM permissions (`detective:*`, `guardduty:List*`)
- Python 3.9+ with boto3
- IAM policy: `AmazonDetectiveFullAccess` or custom policy with `detective:SearchGraph`, `detective:GetInvestigation`, `detective:ListIndicators`

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Behavior Graph** | Data structure linking CloudTrail, VPC Flow, GuardDuty, and EKS logs for an account/region |
| **Entity** | Investigable object: IAM user, IAM role, EC2 instance, IP address, S3 bucket, EKS cluster |
| **Finding Group** | Correlated set of GuardDuty findings linked to the same attack campaign |
| **Entity Profile** | Timeline of API calls, network connections, and resource access for a specific entity |
| **Scope Time** | Investigation window (default 24h, max 1 year) for behavioral analysis |

## Steps

### Step 1: List Available Behavior Graphs

```bash
aws detective list-graphs --output table
```

### Step 2: Investigate a Suspicious IAM User

```bash
# Get entity profile for an IAM user
aws detective get-investigation \
  --graph-arn arn:aws:detective:us-east-1:123456789012:graph:a1b2c3d4 \
  --investigation-id inv-1234567890
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

def get_entity_history(graph_arn, entity_arn, hours=24):
    """Get API call history for an entity."""
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)
    
    response = detective.list_indicators(
        GraphArn=graph_arn,
        InvestigationId=entity_arn,
        MaxResults=50
    )
    return response.get('Indicators', [])

def investigate_guardduty_findings(graph_arn):
    """List finding groups correlated by Detective."""
    response = detective.list_investigations(
        GraphArn=graph_arn,
        FilterCriteria={
            'Statuses': ['RUNNING', 'FAILED'],
            'Severities': ['HIGH', 'CRITICAL']
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

### Step 4: Analyze Finding Groups for Attack Campaigns

```bash
# List investigations with high severity
aws detective list-investigations \
  --graph-arn arn:aws:detective:us-east-1:123456789012:graph:a1b2c3d4 \
  --filter-criteria '{"Severities":["HIGH","CRITICAL"]}' \
  --max-results 10
```

### Step 5: Check Entity Indicators

```bash
# Get indicators for a specific investigation
aws detective list-indicators \
  --graph-arn arn:aws:detective:us-east-1:123456789012:graph:a1b2c3d4 \
  --investigation-id inv-1234567890 \
  --max-results 50
```

## Expected Output

```json
{
  "InvestigationDetails": [
    {
      "InvestigationId": "inv-0a1b2c3d4e5f",
      "Severity": "CRITICAL",
      "Status": "RUNNING",
      "EntityArn": "arn:aws:iam::123456789012:user/suspicious-user",
      "EntityType": "IAM_USER",
      "CreatedTime": "2026-03-15T14:30:00Z",
      "Indicators": {
        "ImpossibleTravel": true,
        "NewGeoLocation": "ru-central-1",
        "UnusualApiCalls": ["CreateAccessKey", "AttachUserPolicy", "PutBucketPolicy"],
        "RelatedFindings": 7
      }
    }
  ]
}
```

## Verification

1. Confirm behavior graph has data: `aws detective list-graphs` returns non-empty list
2. Validate investigation results contain entity timelines with API call sequences
3. Cross-reference Detective findings with raw CloudTrail logs for accuracy
4. Verify finding group correlations match manual investigation conclusions
5. Confirm automated alerts trigger for HIGH/CRITICAL severity investigations
