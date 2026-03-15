# S3 Data Exfiltration Detection API Reference

## GuardDuty S3 Finding Types

| Finding Type | Description |
|-------------|-------------|
| `Exfiltration:S3/MaliciousIPCaller` | S3 accessed from known malicious IP |
| `Exfiltration:S3/AnomalousBehavior` | Unusual S3 access pattern |
| `UnauthorizedAccess:S3/TorIPCaller` | S3 accessed from Tor exit node |
| `Discovery:S3/AnomalousBehavior` | Unusual ListObjects/HeadBucket |
| `Impact:S3/AnomalousBehavior.Delete` | Anomalous object deletion |

## CloudTrail S3 Data Events

```bash
# Enable S3 data events on trail
aws cloudtrail put-event-selectors --trail-name mgmt-trail \
  --event-selectors '[{"ReadWriteType":"All","DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3:::sensitive-bucket/"]}]}]'

# Query GetObject events via Athena
SELECT eventtime, useridentity.arn, requestparameters,
       sourceipaddress, useragent
FROM cloudtrail_logs
WHERE eventname = 'GetObject'
  AND requestparameters LIKE '%sensitive-bucket%'
ORDER BY eventtime DESC
```

## S3 Access Monitoring

```bash
# Check bucket policy
aws s3api get-bucket-policy --bucket mybucket

# Check public access block
aws s3api get-public-access-block --bucket mybucket

# Enable server access logging
aws s3api put-bucket-logging --bucket mybucket \
  --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"log-bucket","TargetPrefix":"s3-logs/"}}'

# List bucket ACL
aws s3api get-bucket-acl --bucket mybucket
```

## S3 Data Event Log Fields

| Field | Description |
|-------|-------------|
| `eventName` | GetObject, PutObject, DeleteObject, CopyObject |
| `requestParameters.bucketName` | Target bucket |
| `requestParameters.key` | Object key accessed |
| `sourceIPAddress` | Caller IP |
| `userIdentity.arn` | Caller identity |
| `additionalEventData.bytesTransferredOut` | Data volume |

## Athena Query - Detect Bulk Downloads

```sql
SELECT useridentity.arn, sourceipaddress,
       COUNT(*) as object_count,
       SUM(CAST(json_extract_scalar(additionaleventdata, '$.bytesTransferredOut') AS bigint)) as bytes_out
FROM cloudtrail_logs
WHERE eventname = 'GetObject'
  AND eventtime > '2024-01-01'
GROUP BY useridentity.arn, sourceipaddress
HAVING COUNT(*) > 100
ORDER BY object_count DESC
```

## Bucket Policy - Restrict to VPC Endpoint

```json
{
  "Statement": [{
    "Sid": "DenyNonVPC",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::bucket/*",
    "Condition": {"StringNotEquals": {"aws:sourceVpce": "vpce-xxxxx"}}
  }]
}
```
