# API Reference: Implementing Security Chaos Engineering

## Experiment Pattern

```python
def run_experiment(setup_fn, verify_fn, rollback_fn, timeout=300):
    try:
        setup_fn()       # Introduce failure
        result = verify_fn(timeout)  # Check detection
    finally:
        rollback_fn()    # Always restore
    return result
```

## AWS boto3 (Chaos Actions)

```python
import boto3

# Open security group
ec2 = boto3.client("ec2")
ec2.authorize_security_group_ingress(GroupId="sg-xxx",
    IpProtocol="tcp", FromPort=22, ToPort=22, CidrIp="0.0.0.0/0")
# Rollback
ec2.revoke_security_group_ingress(...)

# Stop CloudTrail
ct = boto3.client("cloudtrail")
ct.stop_logging(Name="main-trail")
ct.start_logging(Name="main-trail")  # rollback

# Check Config compliance
config = boto3.client("config")
config.get_compliance_details_by_config_rule(
    ConfigRuleName="restricted-ssh",
    ComplianceTypes=["NON_COMPLIANT"])
```

## Experiment Catalog

| Experiment | Detection Target | SLA |
|-----------|-----------------|-----|
| Open SG 0.0.0.0/0 | AWS Config Rule | < 5 min |
| Create admin user | GuardDuty | < 15 min |
| Stop CloudTrail | CloudWatch alarm | < 5 min |
| Public S3 bucket | Config / Macie | < 10 min |

### References

- AWS Config Rules: https://docs.aws.amazon.com/config/latest/developerguide/
- GuardDuty: https://docs.aws.amazon.com/guardduty/
- Security Chaos Engineering book: https://www.oreilly.com/library/view/security-chaos-engineering/
