---
name: detecting-cryptomining-in-cloud
description: >
  This skill teaches security teams how to detect and respond to unauthorized cryptocurrency
  mining operations in cloud environments. It covers identifying cryptomining indicators
  through compute usage anomalies, network traffic patterns to mining pools, GuardDuty
  CryptoCurrency findings, and runtime process monitoring on EC2, ECS, EKS, and Azure
  Automation workloads.
domain: cybersecurity
subdomain: cloud-security
tags: [cryptomining-detection, cloud-abuse, resource-hijacking, guardduty-crypto, cost-anomaly]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Detecting Cryptomining in Cloud

## When to Use

- When cloud billing alerts indicate unexpected compute cost spikes
- When GuardDuty generates CryptoCurrency or Impact finding types
- When investigating compromised IAM credentials that may be used to launch mining instances
- When monitoring container workloads for unauthorized process execution
- When establishing proactive detection controls against resource hijacking attacks

**Do not use** for legitimate cryptocurrency mining operations, for non-cloud mining detection on physical hardware, or for general malware analysis unrelated to mining activity.

## Prerequisites

- Amazon GuardDuty enabled with Runtime Monitoring for EC2, ECS, and EKS
- CloudWatch or Azure Monitor configured for compute utilization alerting
- VPC Flow Logs enabled for network traffic analysis to mining pool IPs
- AWS Cost Anomaly Detection or Azure Cost Management alerts configured

## Workflow

### Step 1: Establish Detection Through Multiple Signals

Deploy detection across four signal categories: cost anomalies, compute utilization, network traffic, and runtime processes.

```bash
# AWS Cost Anomaly Detection
aws ce create-anomaly-monitor \
  --anomaly-monitor '{
    "MonitorName": "EC2CostSpike",
    "MonitorType": "DIMENSIONAL",
    "MonitorDimension": "SERVICE"
  }'

aws ce create-anomaly-subscription \
  --anomaly-subscription '{
    "SubscriptionName": "CryptoMiningAlert",
    "MonitorArnList": ["arn:aws:ce::123456789012:anomalymonitor/monitor-id"],
    "Subscribers": [{"Address": "security@company.com", "Type": "EMAIL"}],
    "Threshold": 50.0,
    "Frequency": "IMMEDIATE"
  }'

# CloudWatch alarm for CPU utilization spike
aws cloudwatch put-metric-alarm \
  --alarm-name HighCPUUtilization \
  --namespace AWS/EC2 \
  --metric-name CPUUtilization \
  --statistic Average \
  --period 300 \
  --threshold 90 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 3 \
  --alarm-actions "arn:aws:sns:us-east-1:123456789012:security-alerts"
```

### Step 2: Monitor GuardDuty CryptoCurrency Findings

Configure alerting for GuardDuty findings specific to cryptocurrency mining activity on EC2, ECS, and EKS workloads.

Key GuardDuty finding types for cryptomining:
- `CryptoCurrency:EC2/BitcoinTool.B` - Network connections to crypto-related domains
- `CryptoCurrency:Runtime/BitcoinTool.B` - Runtime detection of mining process execution
- `Impact:EC2/BitcoinTool.B` - EC2 instance communicating with known Bitcoin mining pools
- `Impact:Runtime/CryptoMinerExecuted` - Crypto mining binary execution detected by runtime agent

```bash
# EventBridge rule for cryptocurrency findings
aws events put-rule \
  --name CryptoMiningDetection \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "type": [
        {"prefix": "CryptoCurrency:"},
        {"prefix": "Impact:EC2/BitcoinTool"},
        {"prefix": "Impact:Runtime/CryptoMiner"}
      ]
    }
  }'

# Auto-remediation Lambda for crypto findings
aws events put-targets \
  --rule CryptoMiningDetection \
  --targets '[{
    "Id": "CryptoAutoRemediate",
    "Arn": "arn:aws:lambda:us-east-1:123456789012:function/crypto-remediate"
  }]'
```

### Step 3: Analyze Network Traffic for Mining Pool Connections

Monitor VPC Flow Logs and DNS queries for connections to known cryptocurrency mining pools operating on common ports (3333, 4444, 5555, 8333, 9999, 14444).

```kql
// Sentinel KQL query for mining pool connections
AzureNetworkAnalytics_CL
| where TimeGenerated > ago(24h)
| where DestPort_d in (3333, 4444, 5555, 8333, 9999, 14444, 14433, 45700)
| summarize ConnectionCount = count(), BytesSent = sum(BytesSent_d)
            by SrcIP_s, DestIP_s, DestPort_d, bin(TimeGenerated, 1h)
| where ConnectionCount > 10
| project TimeGenerated, SrcIP_s, DestIP_s, DestPort_d, ConnectionCount, BytesSent
```

```bash
# AWS Athena query for VPC Flow Logs mining pool detection
cat << 'EOF' > mining-detection.sql
SELECT srcaddr, dstaddr, dstport, protocol,
       COUNT(*) as connection_count,
       SUM(bytes) as total_bytes
FROM vpc_flow_logs
WHERE dstport IN (3333, 4444, 5555, 8333, 9999, 14444)
  AND action = 'ACCEPT'
  AND start >= date_add('hour', -24, now())
GROUP BY srcaddr, dstaddr, dstport, protocol
HAVING COUNT(*) > 10
ORDER BY connection_count DESC
EOF
```

### Step 4: Detect Mining in Container Environments

Monitor ECS task definitions and EKS pod deployments for known mining container images and suspicious process execution.

```bash
# Check for recently registered ECS task definitions with suspicious images
aws ecs list-task-definitions --sort DESC --max-items 50 | \
  jq -r '.taskDefinitionArns[]' | while read arn; do
    aws ecs describe-task-definition --task-definition "$arn" \
      --query 'taskDefinition.containerDefinitions[*].[name,image]' --output text
  done

# Known malicious mining images to watch for:
# - Images with high pull counts from unknown registries
# - Images containing xmrig, cpuminer, minergate, or ccminer binaries
# - Images with entrypoint pointing to /tmp/.hidden or /dev/shm paths

# Monitor CloudTrail for suspicious ECS/EKS activity
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RegisterTaskDefinition \
  --start-time $(date -d '-24 hours' +%Y-%m-%dT%H:%M:%S) \
  --query 'Events[*].[EventName,Username,EventTime]'
```

### Step 5: Respond and Contain Mining Activity

Execute immediate containment actions when mining is confirmed, preserving forensic evidence before terminating the malicious workloads.

```python
# Auto-remediation Lambda for cryptomining incidents
import boto3
import json

def lambda_handler(event, context):
    finding = event['detail']
    resource_type = finding['resource']['resourceType']

    if resource_type == 'Instance':
        instance_id = finding['resource']['instanceDetails']['instanceId']
        ec2 = boto3.client('ec2')

        # Snapshot EBS volumes for forensics before isolation
        volumes = ec2.describe_instances(InstanceIds=[instance_id])
        for reservation in volumes['Reservations']:
            for instance in reservation['Instances']:
                for vol in instance['BlockDeviceMappings']:
                    volume_id = vol['Ebs']['VolumeId']
                    ec2.create_snapshot(
                        VolumeId=volume_id,
                        Description=f'Forensic snapshot - crypto mining - {instance_id}',
                        TagSpecifications=[{
                            'ResourceType': 'snapshot',
                            'Tags': [{'Key': 'Incident', 'Value': 'CryptoMining'},
                                     {'Key': 'SourceInstance', 'Value': instance_id}]
                        }]
                    )

        # Disable API termination protection if set by attacker
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            DisableApiTermination={'Value': False}
        )

        # Isolate instance with empty security group
        vpc_id = finding['resource']['instanceDetails']['networkInterfaces'][0]['vpcId']
        isolation_sg = ec2.create_security_group(
            GroupName=f'crypto-isolation-{instance_id}',
            Description='Cryptomining isolation - no traffic allowed',
            VpcId=vpc_id
        )
        # Revoke default egress rule
        ec2.revoke_security_group_egress(
            GroupId=isolation_sg['GroupId'],
            IpPermissions=[{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
        )
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[isolation_sg['GroupId']]
        )

        return {'status': 'contained', 'instance': instance_id}
```

### Step 6: Trace Initial Access Vector

Investigate CloudTrail logs to determine how the attacker gained access to deploy mining workloads. Common vectors include compromised IAM credentials, exposed access keys, and supply chain attacks through container images.

```bash
# Trace the initial access for the compromised identity
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=compromised-user \
  --start-time 2025-02-01T00:00:00Z \
  --query 'Events[?EventName==`ConsoleLogin` || EventName==`GetSessionToken`].[EventTime,SourceIPAddress,EventName]' \
  --output table

# Check for RunInstances calls in unusual regions
for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  count=$(aws cloudtrail lookup-events \
    --region $region \
    --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
    --start-time $(date -d '-7 days' +%Y-%m-%dT%H:%M:%S) \
    --query 'Events | length(@)')
  if [ "$count" -gt 0 ]; then
    echo "Region: $region - RunInstances calls: $count"
  fi
done
```

## Key Concepts

| Term | Definition |
|------|------------|
| Cryptojacking | Unauthorized use of cloud compute resources to mine cryptocurrency, typically Monero (XMR) due to its CPU-friendly algorithm |
| Stratum Protocol | Mining pool communication protocol operating on TCP ports 3333, 4444, or custom ports, identifiable in network flow logs |
| XMRig | Open-source Monero mining software commonly found in cryptojacking attacks, often deployed as a hidden binary in containers |
| API Termination Protection | EC2 attribute that attackers enable to prevent security teams from quickly terminating compromised mining instances |
| Cost Anomaly Detection | AWS service that uses machine learning to identify unusual spending patterns that may indicate unauthorized resource usage |
| Runtime Monitoring | GuardDuty capability that deploys agents to detect process-level activity including crypto mining binary execution |
| Attack Sequence | GuardDuty Extended Threat Detection finding correlating credential theft, infrastructure deployment, and mining execution into a single Critical event |

## Tools & Systems

- **Amazon GuardDuty**: Detects cryptocurrency mining through network traffic analysis, DNS queries, and runtime process monitoring
- **AWS Cost Anomaly Detection**: Machine learning-based service identifying unexpected cost increases from mining instance deployment
- **VPC Flow Logs**: Network traffic metadata showing connections to mining pool IP addresses and ports
- **Falco**: Open-source runtime security tool for detecting crypto mining process execution in containers
- **Amazon Detective**: Graph-based investigation tool for tracing the attack path from initial access to mining deployment

## Common Scenarios

### Scenario: Compromised IAM Credentials Used for Large-Scale EC2 Mining

**Context**: Exposed IAM credentials from a public GitHub repository are used to launch 200 GPU instances across 8 AWS regions within 10 minutes. The attacker enables API termination protection and disables CloudTrail in each region.

**Approach**:
1. AWS Cost Anomaly Detection triggers an immediate alert for $15,000+ hourly EC2 spend
2. GuardDuty generates Stealth:IAMUser/CloudTrailLoggingDisabled and CryptoCurrency:EC2/BitcoinTool.B findings
3. Immediately deactivate the compromised IAM access key
4. Re-enable CloudTrail in all affected regions to restore visibility
5. Disable API termination protection on all 200 instances and terminate them
6. Create forensic snapshots of representative instances before termination
7. Review the GitHub commit history to identify and remove the exposed credentials
8. Deploy AWS Config rules preventing CloudTrail disabling and enforcing IMDSv2

**Pitfalls**: Failing to check all AWS regions for mining instances leaves active miners running in overlooked regions. Not disabling API termination protection before attempting to stop instances wastes response time.

## Output Format

```
Cryptomining Incident Response Report
=======================================
Incident ID: INC-2025-0223-CRYPTO
Detection Time: 2025-02-23T14:23:00Z
Containment Time: 2025-02-23T14:41:00Z (18 minutes)

INITIAL ACCESS:
  Vector: Exposed IAM access key in public GitHub repository
  Credential: AKIAIOSFODNN7EXAMPLE (user: ci-deploy)
  First Malicious Activity: 2025-02-23T14:12:00Z

IMPACT:
  Instances Launched: 200 (p3.2xlarge GPU instances)
  Regions Affected: 8 (us-east-1, us-west-2, eu-west-1, eu-central-1, ...)
  Estimated Cost: $4,200 (18 minutes at $15,400/hour)
  Mining Pool: stratum+tcp://pool.supportxmr.com:3333
  Cryptocurrency: Monero (XMR)

DETECTION SIGNALS:
  [14:15] GuardDuty: Stealth:IAMUser/CloudTrailLoggingDisabled (HIGH)
  [14:18] Cost Anomaly: EC2 spend 4,200% above baseline
  [14:23] GuardDuty: CryptoCurrency:EC2/BitcoinTool.B (HIGH) x 200

CONTAINMENT ACTIONS:
  [14:25] IAM access key AKIAIOSFODNN7EXAMPLE deactivated
  [14:30] CloudTrail re-enabled in all 8 regions
  [14:35] API termination protection disabled on 200 instances
  [14:41] All 200 instances terminated

REMEDIATION:
  - Compromised access key deleted
  - GitHub repository secret scanning enabled
  - AWS Config rule deployed: cloudtrail-enabled (auto-remediate)
  - SCP deployed: deny ec2:RunInstances for GPU instance types without approval
```
