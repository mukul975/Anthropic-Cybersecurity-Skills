# API Reference: Auditing Cloud with CIS Benchmarks

## boto3 - AWS CIS Checks

### IAM Account Summary (Root Keys, MFA)

```python
import boto3
iam = boto3.client("iam")
summary = iam.get_account_summary()["SummaryMap"]
print("Root access keys:", summary["AccountAccessKeysPresent"])
print("Root MFA:", summary["AccountMFAEnabled"])
```

### Password Policy

```python
policy = iam.get_account_password_policy()["PasswordPolicy"]
print("Min length:", policy["MinimumPasswordLength"])
print("Require symbols:", policy["RequireSymbols"])
```

### CloudTrail Multi-Region

```python
ct = boto3.client("cloudtrail")
trails = ct.describe_trails()["trailList"]
for t in trails:
    print(t["Name"], "Multi-region:", t["IsMultiRegionTrail"])
```

### VPC Flow Logs

```python
ec2 = boto3.client("ec2")
vpcs = ec2.describe_vpcs()["Vpcs"]
flow_logs = ec2.describe_flow_logs()["FlowLogs"]
logged = {fl["ResourceId"] for fl in flow_logs}
for vpc in vpcs:
    print(vpc["VpcId"], "Logged:" if vpc["VpcId"] in logged else "MISSING")
```

## CIS Controls Quick Reference

| CIS Control | boto3 Method | Check |
|-------------|-------------|-------|
| 1.4 Root keys | `iam.get_account_summary()` | `AccountAccessKeysPresent == 0` |
| 1.5 Root MFA | `iam.get_account_summary()` | `AccountMFAEnabled == 1` |
| 2.1.1 S3 encryption | `s3.get_bucket_encryption()` | No ClientError |
| 3.1 CloudTrail | `ct.describe_trails()` | `IsMultiRegionTrail` |
| 5.1 VPC flow logs | `ec2.describe_flow_logs()` | All VPCs covered |
| 5.4 Default SG | `ec2.describe_security_groups()` | No 0.0.0.0/0 rules |

## Prowler CLI

```bash
prowler aws --compliance cis_5.0_aws --output-formats json,csv
prowler azure --compliance cis_4.0_azure
prowler gcp --compliance cis_4.0_gcp
```

### References

- boto3: https://boto3.amazonaws.com/v1/documentation/api/latest/
- CIS Benchmarks: https://www.cisecurity.org/benchmark/amazon_web_services
- Prowler: https://github.com/prowler-cloud/prowler
