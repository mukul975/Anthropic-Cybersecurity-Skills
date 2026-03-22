---
name: analyzing-cloud-storage-access-patterns
description: >-
  Detect abnormal access patterns in AWS S3, Google Cloud Storage, and Azure Blob Storage by analyzing CloudTrail data events, GCS audit logs, and Azure Storage Analytics. Identifies bulk download anomalies, access from unusual IPs, GetObject spikes, and potential data exfiltration using statistical baselines.
domain: cybersecurity
subdomain: cloud-security
tags: [analyzing, cloud, storage, access]
version: "1.0"
author: mahipal
license: Apache-2.0
---

## Instructions

1. Install dependencies: `pip install boto3 requests`
2. Query CloudTrail for S3 Data Events using AWS CLI or boto3.
3. Build access baselines: hourly request volume, per-user object counts, source IP history.
4. Detect anomalies:
   - After-hours access (outside 8am-6pm local time)
   - Bulk downloads: >100 GetObject calls from single principal in 1 hour
   - New source IPs not seen in the prior 30 days
   - ListBucket enumeration spikes (reconnaissance indicator)
5. Generate prioritized findings report.

```bash
python scripts/agent.py --bucket my-sensitive-data --hours-back 24 --output s3_access_report.json
```

## Examples

### CloudTrail S3 Data Event
```json
{"eventName": "GetObject", "requestParameters": {"bucketName": "sensitive-data", "key": "financials/q4.xlsx"},
 "sourceIPAddress": "203.0.113.50", "userIdentity": {"arn": "arn:aws:iam::123456789012:user/analyst"}}
```
