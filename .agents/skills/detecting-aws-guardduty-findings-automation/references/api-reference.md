# AWS GuardDuty Findings Automation — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| boto3 | `pip install boto3` | AWS SDK for GuardDuty API |

## Key boto3 GuardDuty Methods

| Method | Description |
|--------|-------------|
| `list_detectors()` | List GuardDuty detector IDs |
| `get_detector(DetectorId=)` | Get detector configuration |
| `list_findings(DetectorId=, FindingCriteria=)` | Query finding IDs |
| `get_findings(DetectorId=, FindingIds=[])` | Get finding details |
| `get_findings_statistics(DetectorId=)` | Finding counts by severity |
| `archive_findings(DetectorId=, FindingIds=[])` | Archive processed findings |
| `list_members(DetectorId=)` | List member accounts (multi-account) |
| `create_sample_findings(DetectorId=)` | Generate sample findings for testing |

## Finding Severity Levels

| Range | Level | Description |
|-------|-------|-------------|
| 7.0-8.9 | High | Compromised resource, active threat |
| 4.0-6.9 | Medium | Suspicious activity, potential threat |
| 1.0-3.9 | Low | Attempted suspicious activity |

## GuardDuty Finding Types

| Type Prefix | Category |
|-------------|----------|
| `Recon:` | Reconnaissance activity |
| `UnauthorizedAccess:` | Unauthorized access attempt |
| `CryptoCurrency:` | Crypto mining activity |
| `Trojan:` | Malware communication |
| `Stealth:` | Logging/monitoring evasion |
| `Policy:` | Policy violation |
| `Persistence:` | Persistence mechanism |

## GuardDuty Protection Features

| Feature | Description |
|---------|-------------|
| S3_DATA_EVENTS | S3 data plane monitoring |
| EKS_AUDIT_LOGS | EKS control plane monitoring |
| EBS_MALWARE_PROTECTION | EBS volume malware scanning |
| RDS_LOGIN_EVENTS | RDS login activity monitoring |
| LAMBDA_NETWORK_LOGS | Lambda function network monitoring |
| RUNTIME_MONITORING | EC2/ECS/EKS runtime threat detection |

## FindingCriteria Filter

```python
criteria = {
    "Criterion": {
        "severity": {"Gte": 7.0},
        "service.archived": {"Eq": ["false"]},
        "type": {"Eq": ["UnauthorizedAccess:EC2/SSHBruteForce"]},
    }
}
```

## External References

- [GuardDuty API Reference](https://docs.aws.amazon.com/guardduty/latest/APIReference/)
- [GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [GuardDuty Multi-Account](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_accounts.html)
