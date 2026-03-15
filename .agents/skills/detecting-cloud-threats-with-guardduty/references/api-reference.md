# Amazon GuardDuty API Reference

## GuardDuty CLI - Core Operations

```bash
# Enable GuardDuty
aws guardduty create-detector --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES \
  --data-sources '{"S3Logs":{"Enable":true},"Kubernetes":{"AuditLogs":{"Enable":true}}}'

# Get detector ID
aws guardduty list-detectors --query 'DetectorIds[0]' --output text

# Get detector status
aws guardduty get-detector --detector-id $DETECTOR_ID

# Enable Runtime Monitoring
aws guardduty update-detector --detector-id $DETECTOR_ID \
  --features '[{"Name":"RUNTIME_MONITORING","Status":"ENABLED","AdditionalConfiguration":[{"Name":"ECS_FARGATE_AGENT_MANAGEMENT","Status":"ENABLED"}]}]'
```

## Finding Management

```bash
# List findings by severity
aws guardduty list-findings --detector-id $DET \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}' \
  --sort-criteria '{"AttributeName":"severity","OrderBy":"DESC"}'

# Get finding details
aws guardduty get-findings --detector-id $DET --finding-ids id1 id2

# Archive findings
aws guardduty archive-findings --detector-id $DET --finding-ids id1

# Create suppression filter
aws guardduty create-filter --detector-id $DET \
  --name "SuppressDevVPC" --action ARCHIVE \
  --finding-criteria '{"Criterion":{"resource.instanceDetails.networkInterfaces.subnetId":{"Eq":["subnet-dev"]}}}'
```

## GuardDuty Finding Severity Levels

| Range | Level | Action |
|-------|-------|--------|
| 7.0 - 8.9 | HIGH | Immediate investigation |
| 4.0 - 6.9 | MEDIUM | Investigation within 24h |
| 1.0 - 3.9 | LOW | Review during business hours |

## Key Finding Type Prefixes

| Prefix | Source |
|--------|--------|
| `Recon:` | Reconnaissance activity |
| `UnauthorizedAccess:` | Credential or access abuse |
| `CryptoCurrency:` | Mining activity |
| `Trojan:` | Malware communication |
| `Impact:` | Resource abuse |
| `Exfiltration:` | Data theft |
| `Persistence:` | Backdoor/persistence |

## EventBridge Rule for GuardDuty

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "severity": [{"numeric": [">=", 7]}]
  }
}
```

## Threat Intel Set

```bash
aws guardduty create-threat-intel-set --detector-id $DET \
  --name "CustomBadIPs" --format TXT \
  --location s3://bucket/threat-ips.txt --activate
```
