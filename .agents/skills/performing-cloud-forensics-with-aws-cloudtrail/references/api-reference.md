# AWS CloudTrail Forensics API Reference

## boto3 CloudTrail Client

```python
import boto3
client = boto3.client("cloudtrail", region_name="us-east-1")
```

## lookup_events

```python
response = client.lookup_events(
    LookupAttributes=[
        {"AttributeKey": "Username", "AttributeValue": "compromised-user"},
    ],
    StartTime=datetime(2025, 1, 1),
    EndTime=datetime(2025, 1, 2),
    MaxResults=50,
)
```

### LookupAttributes Keys

| AttributeKey | Description |
|-------------|-------------|
| EventId | Unique event identifier |
| EventName | AWS API action (e.g., CreateUser, GetObject) |
| ReadOnly | true/false for read-only API calls |
| Username | IAM user or role session name |
| ResourceType | AWS resource type (e.g., AWS::S3::Object) |
| ResourceName | Name or ARN of the resource accessed |
| EventSource | AWS service (e.g., iam.amazonaws.com) |
| AccessKeyId | IAM access key used for the API call |

### Response Structure

```json
{
    "Events": [
        {
            "EventId": "abc123",
            "EventName": "CreateUser",
            "EventTime": "2025-01-01T12:00:00Z",
            "Username": "attacker",
            "CloudTrailEvent": "{\"sourceIPAddress\":\"1.2.3.4\",\"userAgent\":\"aws-cli/2.0\",...}"
        }
    ],
    "NextToken": "..."
}
```

## Paginator Usage

```python
paginator = client.get_paginator("lookup_events")
for page in paginator.paginate(
    LookupAttributes=[{"AttributeKey": "AccessKeyId", "AttributeValue": "AKIA..."}],
    StartTime=start, EndTime=end
):
    for event in page["Events"]:
        ct = json.loads(event["CloudTrailEvent"])
        print(ct["sourceIPAddress"], ct["eventName"])
```

## AWS CLI Equivalents

```bash
# Lookup events by username
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=compromised-user \
  --start-time 2025-01-01T00:00:00Z \
  --output json

# Search by access key
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAEXAMPLE \
  --max-results 50
```

## Athena Query for S3 CloudTrail Logs

```sql
SELECT eventtime, eventname, useridentity.arn, sourceipaddress, useragent,
       requestparameters, responseelements, errorcode
FROM cloudtrail_logs
WHERE eventtime BETWEEN '2025-01-01' AND '2025-01-02'
  AND useridentity.accesskeyid = 'AKIAEXAMPLE'
ORDER BY eventtime;
```

## Key Forensic Event Names

| Event Name | Service | Forensic Significance |
|-----------|---------|----------------------|
| CreateUser | IAM | Persistence - new user account |
| CreateAccessKey | IAM | Persistence - new credential |
| AssumeRole | STS | Lateral movement / privilege escalation |
| GetObject | S3 | Data exfiltration |
| StopLogging | CloudTrail | Anti-forensics |
| PutBucketPolicy | S3 | Permission modification |
| RunInstances | EC2 | Cryptomining / C2 infrastructure |
| GetSecretValue | SecretsManager | Credential theft |

## Suspicious User Agents

| User Agent Pattern | Tool |
|-------------------|------|
| `Pacu/...` | AWS exploitation framework |
| `python-requests` | Custom Python scripts |
| `aws-cli/2.x` from unusual IP | CLI from attacker machine |
| `Scout Suite` | Cloud security assessment |
| `Prowler` | AWS security scanner |
