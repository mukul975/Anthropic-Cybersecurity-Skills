# GuardDuty Findings Automation Template

## Configuration
| Setting | Value |
|---------|-------|
| Detector ID | |
| Publishing Frequency | 15min / 1hr / 6hr |
| Multi-Account | Yes / No |
| Security Hub Integration | Enabled / Disabled |

## EventBridge Rules
| Rule Name | Severity Threshold | Target | Status |
|-----------|-------------------|--------|--------|
| guardduty-critical | >= 8.0 | Lambda + PagerDuty | |
| guardduty-high | >= 7.0 | Lambda + SNS | |
| guardduty-medium | >= 4.0 | SNS | |

## Auto-Response Actions
| Finding Type | Action | Lambda Function | Tested |
|-------------|--------|----------------|--------|
| EC2 Compromise | Quarantine + Snapshot | [ ] | |
| IAM Credential | Deactivate + Deny | [ ] | |
| S3 Exfiltration | Block Public Access | [ ] | |
