# API Reference: Performing Cloud Forensics Investigation

## AWS CloudTrail API (boto3)

| Method | Description |
|--------|-------------|
| `cloudtrail.lookup_events(StartTime, EndTime)` | Query management events by time window |
| `cloudtrail.get_trail_status(Name)` | Check if trail is actively logging |
| `cloudtrail.describe_trails()` | List configured CloudTrail trails |

## AWS EC2 API (Forensic Snapshots)

| Method | Description |
|--------|-------------|
| `ec2.describe_instances(InstanceIds)` | Get instance details and EBS mappings |
| `ec2.create_snapshot(VolumeId, Description)` | Create forensic snapshot of EBS volume |
| `ec2.copy_snapshot(SourceSnapshotId, SourceRegion)` | Copy snapshot cross-region for preservation |
| `ec2.describe_snapshots(SnapshotIds)` | Check snapshot completion status |

## AWS IAM API

| Method | Description |
|--------|-------------|
| `iam.list_access_keys(UserName)` | List access keys for investigation target |
| `iam.get_access_key_last_used(AccessKeyId)` | Determine last key usage |
| `iam.list_attached_user_policies(UserName)` | List policies attached to user |

## AWS S3 API (Log Collection)

| Method | Description |
|--------|-------------|
| `s3.list_objects_v2(Bucket, Prefix)` | List CloudTrail log files in S3 |
| `s3.get_object(Bucket, Key)` | Download specific log file |

## Key Libraries

- **boto3** (`pip install boto3`): AWS SDK for CloudTrail, EC2, IAM, and S3 APIs
- **botocore**: Exception handling for AWS API errors
- **json** (stdlib): Parse CloudTrail event JSON payloads

## Configuration

| Variable | Description |
|----------|-------------|
| `AWS_PROFILE` | AWS CLI profile with forensic investigation permissions |
| `AWS_DEFAULT_REGION` | Default region for API calls |
| CloudTrail S3 Bucket | Bucket containing CloudTrail log archives |

## Required IAM Permissions

| Permission | Purpose |
|------------|---------|
| `cloudtrail:LookupEvents` | Query CloudTrail events |
| `ec2:DescribeInstances` | Identify volumes for snapshots |
| `ec2:CreateSnapshot` | Create forensic disk snapshots |
| `iam:List*` | Enumerate IAM configuration |
| `s3:GetObject` | Download archived CloudTrail logs |

## References

- [AWS CloudTrail API](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/)
- [AWS Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/)
- [SANS Cloud Forensics](https://www.sans.org/white-papers/cloud-forensics/)
