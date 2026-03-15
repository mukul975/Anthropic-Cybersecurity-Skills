# API Reference: Building Cloud Security Posture Management

## boto3 - AWS CSPM Checks

### S3 Public Access

```python
s3 = boto3.client("s3")
pab = s3.get_public_access_block(Bucket="my-bucket")
config = pab["PublicAccessBlockConfiguration"]
```

### Unencrypted EBS Volumes

```python
ec2 = boto3.client("ec2")
for vol in ec2.describe_volumes()["Volumes"]:
    if not vol["Encrypted"]:
        print(f"Unencrypted: {vol['VolumeId']}")
```

### Open Security Groups

```python
for sg in ec2.describe_security_groups()["SecurityGroups"]:
    for rule in sg["IpPermissions"]:
        for ip in rule.get("IpRanges", []):
            if ip["CidrIp"] == "0.0.0.0/0":
                print(f"OPEN: {sg['GroupId']} port {rule['FromPort']}")
```

### IAM Users Without MFA

```python
iam = boto3.client("iam")
for user in iam.list_users()["Users"]:
    mfa = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
    if not mfa:
        print(f"No MFA: {user['UserName']}")
```

### Public RDS Instances

```python
rds = boto3.client("rds")
for db in rds.describe_db_instances()["DBInstances"]:
    if db["PubliclyAccessible"]:
        print(f"Public RDS: {db['DBInstanceIdentifier']}")
```

## Key CSPM Checks

| Check | Service | boto3 Method |
|-------|---------|-------------|
| Public S3 | S3 | `get_public_access_block()` |
| Unencrypted EBS | EC2 | `describe_volumes()` |
| Open SGs | EC2 | `describe_security_groups()` |
| No MFA | IAM | `list_mfa_devices()` |
| Public RDS | RDS | `describe_db_instances()` |
| CloudTrail | CloudTrail | `describe_trails()` |

## Steampipe (SQL-Based CSPM)

```sql
select name, region, server_side_encryption_configuration
from aws_s3_bucket
where server_side_encryption_configuration is null;
```

### References

- boto3: https://boto3.amazonaws.com/v1/documentation/api/latest/
- Prowler: https://github.com/prowler-cloud/prowler
- Steampipe: https://steampipe.io/
