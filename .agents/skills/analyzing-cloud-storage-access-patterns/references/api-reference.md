# API Reference: Cloud Storage Access Pattern Analysis

## AWS CLI - CloudTrail Lookup
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::S3::Object \
  --start-time 2024-01-15T00:00:00Z \
  --output json
```

## CloudTrail S3 Data Event Structure
```json
{
  "EventTime": "2024-01-15T10:30:00Z",
  "EventName": "GetObject",
  "Username": "analyst",
  "CloudTrailEvent": "{\"sourceIPAddress\":\"10.0.0.1\",\"userAgent\":\"aws-cli\",\"requestParameters\":{\"bucketName\":\"data\",\"key\":\"file.csv\"},\"userIdentity\":{\"arn\":\"arn:aws:iam::123:user/analyst\"}}"
}
```

## Key S3 Event Names
| Event | Meaning |
|-------|---------|
| GetObject | Object download |
| PutObject | Object upload |
| DeleteObject | Object deletion |
| ListBucket / ListObjectsV2 | Bucket enumeration |
| GetBucketPolicy | Policy read |
| PutBucketPolicy | Policy modification |

## Detection Thresholds
| Anomaly | Threshold | Severity |
|---------|-----------|----------|
| Bulk download | >100 GetObject/hr per user | Critical |
| After-hours | Access outside 08:00-18:00 UTC | Medium |
| New source IP | IP not in 30-day baseline | High |
| Enumeration | >20 ListBucket per user | High |

## boto3 CloudTrail Client (alternative)
```python
import boto3
client = boto3.client("cloudtrail")
response = client.lookup_events(
    LookupAttributes=[{"AttributeKey":"ResourceType","AttributeValue":"AWS::S3::Object"}],
    StartTime=datetime(2024,1,15),
    MaxResults=50
)
events = response["Events"]
```
