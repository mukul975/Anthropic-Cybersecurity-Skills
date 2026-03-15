# API Reference: Detecting AWS CloudTrail Anomalies

## boto3 CloudTrail API

```python
import boto3

client = boto3.client("cloudtrail", region_name="us-east-1")

# Paginated event lookup
paginator = client.get_paginator("lookup_events")
pages = paginator.paginate(
    StartTime=datetime(2025, 1, 1),
    EndTime=datetime.utcnow(),
    LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}],
    PaginationConfig={"MaxItems": 500, "PageSize": 50},
)
for page in pages:
    for event in page["Events"]:
        ct = json.loads(event["CloudTrailEvent"])
        print(ct["sourceIPAddress"], event["EventName"])
```

## CloudTrail Event Fields

| Field | Location | Description |
|-------|----------|-------------|
| EventName | Event | API action name |
| EventSource | Event | AWS service (e.g. iam.amazonaws.com) |
| Username | Event | IAM user or assumed role |
| sourceIPAddress | CloudTrailEvent JSON | Caller IP address |
| errorCode | CloudTrailEvent JSON | Error type if failed |
| userAgent | CloudTrailEvent JSON | Client SDK/browser |
| awsRegion | CloudTrailEvent JSON | Region of API call |

## Sensitive API Calls to Monitor

| Event Name | Risk | Reason |
|------------|------|--------|
| StopLogging | Critical | Disabling CloudTrail |
| DeleteTrail | Critical | Removing audit trail |
| CreateAccessKey | High | New credentials for user |
| AttachUserPolicy | High | Privilege escalation |
| PutBucketPolicy | High | S3 access change |
| ConsoleLogin | Medium | Interactive access |
| RunInstances | Medium | Resource creation |
| AssumeRole | Medium | Role switching |

## Rate Limits

- lookup_events: 2 requests/second per account per region
- Maximum lookback: 90 days
- Max results per page: 50 events

## References

- boto3 CloudTrail: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail.html
- CloudTrail Insights: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-insights-events-with-cloudtrail.html
- LookupEvents API: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html
