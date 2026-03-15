# API Reference: Implementing CloudTrail Log Analysis

## Libraries

### boto3 -- AWS CloudTrail
- **Install**: `pip install boto3`
- **Docs**: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail.html

### Key Methods

| Method | Description |
|--------|-------------|
| `lookup_events()` | Search recent CloudTrail events with filters |
| `describe_trails()` | List configured trails |
| `get_trail_status()` | Check if trail is actively logging |
| `create_trail()` | Create a new CloudTrail trail |
| `start_logging()` / `stop_logging()` | Control trail recording |
| `get_event_selectors()` | View event type configuration |
| `put_event_selectors()` | Configure management/data event capture |

## Lookup Attributes

| AttributeKey | Description |
|-------------|-------------|
| `EventName` | API action name (e.g., `RunInstances`) |
| `Username` | IAM user or role name |
| `ResourceType` | AWS resource type |
| `ResourceName` | Specific resource identifier |
| `EventSource` | AWS service (e.g., `ec2.amazonaws.com`) |
| `ReadOnly` | Filter read vs write events |

## Suspicious Event Names

| Event | Threat Category |
|-------|----------------|
| `StopLogging` / `DeleteTrail` | Anti-forensics |
| `CreateUser` / `CreateAccessKey` | Persistence |
| `AttachUserPolicy` / `PutUserPolicy` | Privilege escalation |
| `ConsoleLogin` (failed) | Brute force |
| `RunInstances` | Resource abuse / cryptomining |
| `AuthorizeSecurityGroupIngress` | Lateral movement |
| `DisableKey` | Ransomware indicator |

## Athena Query Integration
- Create Athena table from CloudTrail S3 logs
- SQL queries for historical analysis beyond 90-day API limit
- Partition by region, year, month for performance

## CloudWatch Logs Insights
- `filter eventName = "ConsoleLogin"` -- Login analysis
- `stats count(*) by eventName` -- API call frequency
- `filter errorCode = "AccessDenied"` -- Permission issues

## External References
- CloudTrail User Guide: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/
- CloudTrail Log Events: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html
- Athena + CloudTrail: https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html
