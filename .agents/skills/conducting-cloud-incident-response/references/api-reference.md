# API Reference: Cloud Incident Response Agent

## Overview

Automates AWS cloud incident response: disables compromised access keys, attaches deny-all policies, isolates EC2 instances, captures EBS snapshots for forensics, and queries CloudTrail for attacker activity timeline.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | HTTP API calls |
| AWS CLI | >=2.0 | AWS service interaction (subprocess) |

## CLI Usage

```bash
python agent.py --incident-id INC-2025-001 --username compromised-user \
  --access-key-id AKIA... --instance-id i-0abc123 --output report.json
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--incident-id` | Yes | Incident ticket identifier |
| `--username` | Yes | Compromised IAM username |
| `--access-key-id` | No | Access key ID to disable |
| `--instance-id` | No | EC2 instance ID to isolate |
| `--forensic-sg` | No | Forensic isolation security group ID |
| `--output` | No | Output report file path |

## Key Functions

### `aws_disable_access_key(username, access_key_id)`
Disables a compromised IAM access key by setting status to Inactive via `aws iam update-access-key`.

### `aws_attach_deny_all(username)`
Attaches the `AWSDenyAll` managed policy to block all API calls from the compromised user.

### `aws_isolate_ec2(instance_id, forensic_sg)`
Changes an EC2 instance's security groups to a forensic isolation group that denies all traffic.

### `aws_snapshot_ebs(instance_id)`
Creates forensic snapshots of all EBS volumes attached to the compromised instance.

### `aws_query_cloudtrail(username, hours_back)`
Queries CloudTrail for all API events made by the compromised identity, parsing source IP, user agent, and resources.

### `aws_list_attacker_resources(username, events)`
Filters CloudTrail events for resource creation actions (Create*, Run*, Put*, Attach*).

### `aws_check_all_regions_instances()`
Scans all AWS regions for running EC2 instances to detect crypto-mining deployments.

## AWS CLI Commands Used

| Command | Purpose |
|---------|---------|
| `aws iam update-access-key` | Disable access key |
| `aws iam attach-user-policy` | Attach deny-all policy |
| `aws ec2 modify-instance-attribute` | Change security groups |
| `aws ec2 create-snapshot` | Capture EBS volume snapshot |
| `aws cloudtrail lookup-events` | Query API audit trail |
| `aws ec2 describe-regions` | List all regions |
