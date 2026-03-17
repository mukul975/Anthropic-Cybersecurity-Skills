---
name: detecting-aws-guardduty-findings-automation
description: Automate AWS GuardDuty threat detection findings processing using EventBridge and Lambda to enable real-time incident response, automatic quarantine of compromised resources, and security notification workflows.
domain: cybersecurity
subdomain: cloud-security
tags: [aws, guardduty, eventbridge, lambda, threat-detection, automation, incident-response, siem]
mitre_attack: ["T1078", "T1537", "T1580"]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting AWS GuardDuty Findings Automation

## Overview

Amazon GuardDuty is a threat detection service that continuously monitors AWS accounts for malicious activity and unauthorized behavior. By integrating GuardDuty with Amazon EventBridge and AWS Lambda, security teams achieve automated, real-time responses to threats, reducing mean time to response (MTTR) from hours to seconds. GuardDuty analyzes VPC Flow Logs, CloudTrail management and data events, DNS logs, EKS audit logs, and S3 data events.


## When to Use

- When investigating security incidents that require detecting aws guardduty findings automation
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- AWS account with GuardDuty enabled
- IAM roles for Lambda execution
- EventBridge configured for GuardDuty events
- SNS topic for security notifications
- Security Hub integration (recommended)

## Enable GuardDuty

```bash
# Enable GuardDuty
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES

# Enable additional data sources
aws guardduty update-detector \
  --detector-id DETECTOR_ID \
  --data-sources '{
    "S3Logs": {"Enable": true},
    "Kubernetes": {"AuditLogs": {"Enable": true}},
    "MalwareProtection": {"ScanEc2InstanceWithFindings": {"EbsVolumes": true}},
    "RuntimeMonitoring": {"Enable": true}
  }'
```

## EventBridge Rule Configuration

### Rule for high-severity findings

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "severity": [{"numeric": [">=", 7.0]}]
  }
}
```

### Create EventBridge rule via CLI

```bash
aws events put-rule \
  --name "guardduty-high-severity" \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "severity": [{"numeric": [">=", 7.0]}]
    }
  }'

aws events put-targets \
  --rule "guardduty-high-severity" \
  --targets "Id"="lambda-handler","Arn"="arn:aws:lambda:us-east-1:123456789012:function:guardduty-response"
```

## Lambda Automated Response Functions

### EC2 Instance Isolation

```python
import boto3
import json
import os

ec2 = boto3.client('ec2')
sns = boto3.client('sns')

QUARANTINE_SG = os.environ.get('QUARANTINE_SECURITY_GROUP')
SNS_TOPIC = os.environ.get('SNS_TOPIC_ARN')

def lambda_handler(event, context):
    finding = event['detail']
    finding_type = finding['type']
    severity = finding['severity']
    account_id = finding['accountId']
    region = finding['region']

    # Extract resource information
    resource = finding.get('resource', {})
    resource_type = resource.get('resourceType', '')

    if resource_type == 'Instance':
        instance_id = resource['instanceDetails']['instanceId']
        instance_tags = {t['key']: t['value']
                        for t in resource['instanceDetails'].get('tags', [])}

        # Skip if already quarantined
        if instance_tags.get('SecurityStatus') == 'Quarantined':
            return {'statusCode': 200, 'body': 'Already quarantined'}

        # Get current security groups for forensics
        instance = ec2.describe_instances(InstanceIds=[instance_id])
        current_sgs = [sg['GroupId'] for sg in
                       instance['Reservations'][0]['Instances'][0]['SecurityGroups']]

        # Tag instance with finding info and original SGs
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {'Key': 'SecurityStatus', 'Value': 'Quarantined'},
                {'Key': 'GuardDutyFinding', 'Value': finding_type},
                {'Key': 'OriginalSecurityGroups', 'Value': ','.join(current_sgs)},
                {'Key': 'QuarantineTime', 'Value': finding['updatedAt']}
            ]
        )

        # Move to quarantine security group (blocks all traffic)
        if QUARANTINE_SG:
            ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[QUARANTINE_SG]
            )

        # Create EBS snapshots for forensics
        volumes = ec2.describe_volumes(
            Filters=[{'Name': 'attachment.instance-id', 'Values': [instance_id]}]
        )
        for vol in volumes['Volumes']:
            ec2.create_snapshot(
                VolumeId=vol['VolumeId'],
                Description=f'GuardDuty forensic snapshot - {finding_type}',
                TagSpecifications=[{
                    'ResourceType': 'snapshot',
                    'Tags': [
                        {'Key': 'Purpose', 'Value': 'ForensicCapture'},
                        {'Key': 'SourceInstance', 'Value': instance_id},
                        {'Key': 'FindingType', 'Value': finding_type}
                    ]
                }]
            )

        # Notify security team
        sns.publish(
            TopicArn=SNS_TOPIC,
            Subject=f'[GuardDuty] {finding_type} - Instance {instance_id} Quarantined',
            Message=json.dumps({
                'action': 'instance_quarantined',
                'instance_id': instance_id,
                'finding_type': finding_type,
                'severity': severity,
                'account': account_id,
                'region': region,
                'original_security_groups': current_sgs,
                'description': finding.get('description', '')
            }, indent=2)
        )

        return {
            'statusCode': 200,
            'body': f'Instance {instance_id} quarantined and snapshots created'
        }

    return {'statusCode': 200, 'body': 'Non-EC2 finding processed'}
```

### IAM Credential Compromise Response

```python
import boto3
import json
import os

iam = boto3.client('iam')
sns = boto3.client('sns')

SNS_TOPIC = os.environ.get('SNS_TOPIC_ARN')

def lambda_handler(event, context):
    finding = event['detail']
    finding_type = finding['type']

    if 'IAMUser' not in finding_type and 'UnauthorizedAccess' not in finding_type:
        return {'statusCode': 200, 'body': 'Not an IAM finding'}

    resource = finding.get('resource', {})
    access_key_details = resource.get('accessKeyDetails', {})
    user_name = access_key_details.get('userName', '')
    access_key_id = access_key_details.get('accessKeyId', '')

    if not user_name:
        return {'statusCode': 200, 'body': 'No user identified'}

    actions_taken = []

    # Deactivate the compromised access key
    if access_key_id and access_key_id != 'GeneratedFindingAccessKeyId':
        try:
            iam.update_access_key(
                UserName=user_name,
                AccessKeyId=access_key_id,
                Status='Inactive'
            )
            actions_taken.append(f'Deactivated access key {access_key_id}')
        except Exception as e:
            actions_taken.append(f'Failed to deactivate key: {str(e)}')

    # Attach deny-all policy to user
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*"
        }]
    }

    try:
        iam.put_user_policy(
            UserName=user_name,
            PolicyName='GuardDuty-DenyAll-Quarantine',
            PolicyDocument=json.dumps(deny_policy)
        )
        actions_taken.append(f'Applied deny-all policy to {user_name}')
    except Exception as e:
        actions_taken.append(f'Failed to apply deny policy: {str(e)}')

    # Notify
    sns.publish(
        TopicArn=SNS_TOPIC,
        Subject=f'[GuardDuty] IAM Compromise - {user_name}',
        Message=json.dumps({
            'finding_type': finding_type,
            'user': user_name,
            'access_key': access_key_id,
            'actions_taken': actions_taken,
            'severity': finding['severity']
        }, indent=2)
    )

    return {'statusCode': 200, 'body': json.dumps(actions_taken)}
```

## Terraform Deployment

```hcl
resource "aws_guardduty_detector" "main" {
  enable = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs { enable = true }
    kubernetes { audit_logs { enable = true } }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes { enable = true }
      }
    }
  }
}

resource "aws_cloudwatch_event_rule" "guardduty_high" {
  name        = "guardduty-high-severity"
  description = "GuardDuty high severity findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7.0] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.guardduty_high.name
  arn  = aws_lambda_function.guardduty_response.arn
}
```

## Finding Categories

| Category | Severity Range | Examples |
|----------|---------------|---------|
| Backdoor | 5.0 - 8.0 | Backdoor:EC2/C&CActivity |
| CryptoCurrency | 5.0 - 8.0 | CryptoCurrency:EC2/BitcoinTool |
| Trojan | 5.0 - 8.0 | Trojan:EC2/BlackholeTraffic |
| UnauthorizedAccess | 5.0 - 8.0 | UnauthorizedAccess:IAMUser/ConsoleLogin |
| Recon | 2.0 - 5.0 | Recon:EC2/PortProbeUnprotected |
| Persistence | 5.0 - 8.0 | Persistence:IAMUser/AnomalousBehavior |

## Multi-Account Setup

```bash
# Designate GuardDuty administrator
aws guardduty enable-organization-admin-account \
  --admin-account-id 111111111111

# Auto-enable for new accounts
aws guardduty update-organization-configuration \
  --detector-id DETECTOR_ID \
  --auto-enable
```

## References

- AWS GuardDuty Best Practices: https://aws.github.io/aws-security-services-best-practices/guides/guardduty/
- EventBridge Integration: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_eventbridge.html
- GuardDuty Finding Types Reference
