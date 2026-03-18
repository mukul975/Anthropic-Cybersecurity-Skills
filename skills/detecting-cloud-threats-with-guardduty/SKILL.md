---
name: detecting-cloud-threats-with-guardduty
description: >
  This skill teaches security teams how to deploy and operationalize Amazon GuardDuty
  for continuous threat detection across AWS accounts and workloads. It covers enabling
  protection plans for S3, EKS, EC2 runtime monitoring, and Lambda, interpreting finding
  severity levels, and building automated response workflows using EventBridge and Lambda.
domain: cybersecurity
subdomain: cloud-security
tags: [amazon-guardduty, threat-detection, aws-security, runtime-monitoring, cloud-soc]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Detecting Cloud Threats with GuardDuty

## When to Use

- When establishing continuous threat detection for new or existing AWS accounts
- When investigating GuardDuty findings related to compromised instances, credential abuse, or data exfiltration
- When building automated incident response playbooks triggered by GuardDuty findings
- When extending threat coverage to container workloads running on EKS, ECS, or Fargate
- When enabling malware scanning for EBS volumes attached to suspicious EC2 instances

**Do not use** for Azure or GCP threat detection (see securing-azure-with-microsoft-defender or auditing-gcp-security-posture), for static code analysis, or for compliance posture monitoring (see implementing-aws-security-hub).

## Prerequisites

- AWS account with GuardDuty administrative permissions (guardduty:*)
- AWS CloudTrail, VPC Flow Logs, and DNS query logs enabled (GuardDuty consumes these automatically)
- AWS Organizations configured if deploying GuardDuty across a multi-account estate
- EventBridge and Lambda configured for automated response workflows

## Workflow

### Step 1: Enable GuardDuty and Protection Plans

Activate GuardDuty at the organization level using a delegated administrator account. Enable all protection plans including S3 Protection, EKS Audit Log Monitoring, Runtime Monitoring, Malware Protection, RDS Login Activity, and Lambda Network Activity Monitoring.

```bash
# Enable GuardDuty as organization delegated administrator
aws guardduty create-detector \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES \
  --data-sources '{
    "S3Logs": {"Enable": true},
    "Kubernetes": {"AuditLogs": {"Enable": true}},
    "MalwareProtection": {"ScanEc2InstanceWithFindings": {"EbsVolumes": true}}
  }'

# Enable Runtime Monitoring for EC2 and ECS
aws guardduty update-detector \
  --detector-id <detector-id> \
  --features '[
    {"Name": "RUNTIME_MONITORING", "Status": "ENABLED",
     "AdditionalConfiguration": [
       {"Name": "ECS_FARGATE_AGENT_MANAGEMENT", "Status": "ENABLED"},
       {"Name": "EC2_AGENT_MANAGEMENT", "Status": "ENABLED"}
     ]}
  ]'

# Designate delegated admin for multi-account
aws guardduty enable-organization-admin-account \
  --admin-account-id 111122223333
```

### Step 2: Configure Multi-Account Aggregation

Automatically enroll all organization member accounts and configure finding export to a centralized S3 bucket for retention and SIEM ingestion.

```bash
# Auto-enable GuardDuty for all org members
aws guardduty update-organization-configuration \
  --detector-id <detector-id> \
  --auto-enable-organization-members ALL \
  --features '[
    {"Name": "S3_DATA_EVENTS", "AutoEnable": "ALL"},
    {"Name": "EKS_AUDIT_LOGS", "AutoEnable": "ALL"},
    {"Name": "RUNTIME_MONITORING", "AutoEnable": "ALL"}
  ]'

# Configure finding export to S3
aws guardduty create-publishing-destination \
  --detector-id <detector-id> \
  --destination-type S3 \
  --destination-properties '{
    "DestinationArn": "arn:aws:s3:::guardduty-findings-centralized",
    "KmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-id"
  }'
```

### Step 3: Interpret Finding Types and Severity Levels

GuardDuty classifies findings into four severity levels: Critical, High, Medium, and Low. Each finding type follows the format ThreatPurpose:ResourceType/ThreatName. Extended Threat Detection generates attack sequence findings that correlate multiple events across time.

Key finding categories:
- **Recon**: Port scanning, API enumeration (e.g., Recon:EC2/PortProbeUnprotectedPort)
- **UnauthorizedAccess**: Credential abuse, console logins from unusual locations
- **CryptoCurrency**: Mining activity detected on instances (e.g., CryptoCurrency:EC2/BitcoinTool.B)
- **Impact**: Resource hijacking, data destruction attempts
- **AttackSequence**: Multi-stage attacks correlating initial access through lateral movement to impact (Critical severity)

### Step 4: Build Automated Response with EventBridge

Create EventBridge rules that route GuardDuty findings to Lambda functions for automated containment actions such as isolating compromised EC2 instances, revoking IAM credentials, or blocking malicious IP addresses.

```bash
# EventBridge rule for high/critical GuardDuty findings
aws events put-rule \
  --name GuardDutyHighSeverity \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "severity": [{"numeric": [">=", 7]}]
    }
  }'

# Target Lambda function for auto-remediation
aws events put-targets \
  --rule GuardDutyHighSeverity \
  --targets '[{
    "Id": "AutoRemediateTarget",
    "Arn": "arn:aws:lambda:us-east-1:123456789012:function/guardduty-auto-remediate"
  }]'
```

Auto-remediation Lambda example for isolating a compromised EC2 instance:

```python
import boto3

def lambda_handler(event, context):
    finding = event['detail']
    finding_type = finding['type']
    severity = finding['severity']

    if finding_type.startswith('UnauthorizedAccess:EC2') and severity >= 7:
        instance_id = finding['resource']['instanceDetails']['instanceId']
        ec2 = boto3.client('ec2')

        # Create isolation security group (no inbound/outbound rules)
        vpc_id = finding['resource']['instanceDetails']['networkInterfaces'][0]['vpcId']
        isolation_sg = ec2.create_security_group(
            GroupName=f'isolation-{instance_id}',
            Description='GuardDuty auto-isolation',
            VpcId=vpc_id
        )

        # Replace all security groups with isolation group
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[isolation_sg['GroupId']]
        )

        # Tag instance for investigation
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[{'Key': 'SecurityStatus', 'Value': 'ISOLATED'},
                  {'Key': 'GuardDutyFinding', 'Value': finding_type}]
        )

        return {'status': 'isolated', 'instance': instance_id}
```

### Step 5: Investigate Extended Threat Detection Attack Sequences

Review Critical-severity attack sequence findings that correlate multiple signals across EC2, ECS, and EKS. These findings represent multi-stage attacks such as initial access through compromised credentials followed by persistence, lateral movement, and crypto mining.

```bash
# List critical attack sequence findings
aws guardduty list-findings \
  --detector-id <detector-id> \
  --finding-criteria '{
    "Criterion": {
      "severity": {"Gte": 9},
      "type": {"Eq": ["AttackSequence:EC2/CompromisedInstanceGroup",
                       "AttackSequence:ECS/CompromisedCluster",
                       "AttackSequence:EKS/CompromisedCluster"]}
    }
  }'

# Get full finding details with attack sequence timeline
aws guardduty get-findings \
  --detector-id <detector-id> \
  --finding-ids <finding-id>
```

### Step 6: Integrate with Security Hub and SIEM

Forward GuardDuty findings to AWS Security Hub for centralized aggregation and to external SIEM platforms via S3 export or Amazon Security Lake for long-term retention and cross-source correlation.

```bash
# Verify GuardDuty integration with Security Hub
aws securityhub get-enabled-standards

# Enable Amazon Security Lake with GuardDuty as a source
aws securitylake create-data-lake \
  --configurations '[{
    "region": "us-east-1",
    "lifecycleConfiguration": {
      "expiration": {"days": 365}
    }
  }]'
```

## Key Concepts

| Term | Definition |
|------|------------|
| Extended Threat Detection | GuardDuty capability that correlates multiple signals across time to detect multi-stage attacks, generating Critical-severity attack sequence findings |
| Runtime Monitoring | Protection plan that deploys a security agent to EC2 instances, ECS tasks, and EKS pods to detect runtime threats at the OS level |
| Finding Severity | Four-tier classification (Low, Medium, High, Critical) where Critical indicates confirmed multi-stage attacks requiring immediate response |
| Malware Protection | On-demand and automatic EBS volume scanning triggered by suspicious EC2 behavior to detect malware without agent installation |
| Delegated Administrator | Organization member account designated to manage GuardDuty across all accounts in an AWS Organization |
| Suppression Rule | Filter that automatically archives findings matching specific criteria to reduce noise from known benign activity |
| Threat Intelligence | IP reputation lists and domain threat feeds used by GuardDuty to identify communication with known malicious infrastructure |

## Tools & Systems

- **Amazon GuardDuty**: Core threat detection service analyzing CloudTrail, VPC Flow Logs, DNS logs, and runtime telemetry
- **Amazon EventBridge**: Serverless event bus for routing GuardDuty findings to automated response targets
- **AWS Security Hub**: Centralized security findings aggregation supporting automated remediation workflows
- **Amazon Security Lake**: OCSF-normalized data lake for long-term security log retention and cross-service correlation
- **Amazon Detective**: Graph-based investigation service that visualizes relationships between GuardDuty findings, resources, and API activity

## Common Scenarios

### Scenario: Cryptocurrency Mining Detected on ECS Cluster

**Context**: GuardDuty generates a CryptoCurrency:Runtime/BitcoinTool.B finding with High severity targeting an ECS Fargate task. Runtime Monitoring detected the execution of a mining binary within a container.

**Approach**:
1. Review the finding details to identify the ECS cluster, task definition, and container image
2. Stop the affected ECS task immediately and quarantine the container image in ECR
3. Check CloudTrail for the ecs:RegisterTaskDefinition and ecs:RunTask calls to identify who deployed the malicious image
4. Scan the Docker image with ECR enhanced scanning to identify the embedded mining binary
5. Review IAM credentials used to push the image and revoke compromised access
6. Update ECR image scanning policies to block images with known mining signatures

**Pitfalls**: Stopping the task without preserving the container image loses forensic evidence. Failing to trace back to the RegisterTaskDefinition API call misses the initial compromise vector.

## Output Format

```
GuardDuty Threat Detection Summary
====================================
Account: 123456789012 (production)
Region: us-east-1
Period: 2025-02-01 to 2025-02-23

CRITICAL FINDINGS (Immediate Action Required):
[CRIT-001] AttackSequence:EC2/CompromisedInstanceGroup
  - Instances: i-0abc123def, i-0def456abc
  - Attack Chain: Credential theft -> Persistence -> Crypto mining
  - First Signal: 2025-02-15T08:23:00Z
  - Duration: 4 hours across 3 stages
  - Status: Auto-isolated via Lambda

HIGH FINDINGS:
[HIGH-001] UnauthorizedAccess:IAMUser/MaliciousIPCaller
  - Principal: arn:aws:iam::123456789012:user/ci-deploy
  - Source IP: 198.51.100.42 (Tor exit node)
  - API Calls: 47 calls to ec2:RunInstances
  - Status: Access key deactivated

[HIGH-002] CryptoCurrency:Runtime/BitcoinTool.B
  - Resource: ECS Task arn:aws:ecs:us-east-1:123456789012:task/cluster/task-id
  - Image: 123456789012.dkr.ecr.us-east-1.amazonaws.com/app:v2.1
  - Process: /tmp/.hidden/xmrig --pool stratum+tcp://pool.example.com:3333
  - Status: Task stopped, image quarantined

STATISTICS:
  Total Findings: 23
  Critical: 1 | High: 3 | Medium: 8 | Low: 11
  Auto-Remediated: 4
  Pending Investigation: 2
```
