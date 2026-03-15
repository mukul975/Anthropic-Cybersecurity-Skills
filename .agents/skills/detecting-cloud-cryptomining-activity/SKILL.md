---
name: detecting-cloud-cryptomining-activity
description: >
  Detecting unauthorized cryptocurrency mining activity in cloud environments by analyzing
  compute usage anomalies, network traffic to mining pools, GuardDuty findings, and
  container workload behavior using AWS, Azure, and GCP native security services.
domain: cybersecurity
subdomain: cloud-security
tags: [cloud-security, cryptomining, threat-detection, guardduty, cost-anomaly, incident-response]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting Cloud Cryptomining Activity

## When to Use

- When investigating unexpected spikes in cloud compute costs or CPU utilization
- When GuardDuty, Defender for Cloud, or SCC reports cryptocurrency-related findings
- When monitoring for compromised credentials being used to launch mining instances
- When building detection rules for unauthorized workload deployment in cloud environments
- When responding to alerts about network connections to known mining pool infrastructure

**Do not use** for detecting cryptomining on endpoints or on-premises servers (use EDR tools), for investigating the financial impact of mining (use cloud cost management tools), or for blocking mining at the network level (use DNS filtering and firewall rules).

## Prerequisites

- AWS GuardDuty enabled across all accounts and regions
- Azure Defender for Cloud with server and container plans enabled
- GCP Security Command Center with Event Threat Detection enabled
- CloudTrail, Azure Activity Log, and GCP Audit Log enabled for API monitoring
- Cloud cost monitoring and alerting configured (AWS Cost Anomaly Detection, Azure Cost Management)
- Network flow logs enabled (VPC Flow Logs, NSG Flow Logs, VPC Flow Logs)

## Workflow

### Step 1: Identify GuardDuty Cryptocurrency Findings (AWS)

Query GuardDuty for cryptocurrency-specific finding types that indicate mining activity.

```bash
# List active cryptocurrency-related findings
aws guardduty list-findings \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --finding-criteria '{
    "Criterion": {
      "type": {
        "Eq": [
          "CryptoCurrency:EC2/BitcoinTool.B!DNS",
          "CryptoCurrency:EC2/BitcoinTool.B",
          "CryptoCurrency:Runtime/BitcoinTool.B!DNS",
          "CryptoCurrency:Runtime/BitcoinTool.B",
          "CryptoCurrency:Lambda/BitcoinTool.B"
        ]
      },
      "service.archived": {"Eq": ["false"]}
    }
  }' --output json

# Get detailed findings
FINDING_IDS=$(aws guardduty list-findings \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --finding-criteria '{"Criterion":{"type":{"Eq":["CryptoCurrency:EC2/BitcoinTool.B!DNS"]}}}' \
  --query 'FindingIds' --output json)

aws guardduty get-findings \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --finding-ids $FINDING_IDS \
  --query 'Findings[*].{Type:Type,Severity:Severity,Resource:Resource.InstanceDetails.InstanceId,RemoteIP:Service.Action.NetworkConnectionAction.RemoteIpDetails.IpAddressV4,Domain:Service.Action.DnsRequestAction.Domain}' \
  --output table
```

### Step 2: Detect Compute Usage Anomalies

Monitor for unexpected compute resource provisioning and CPU utilization spikes that indicate mining.

```bash
# AWS: Find recently launched large instances (mining often uses c5/p3/g4 instances)
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,LaunchTime,Tags[?Key==`Name`].Value|[0]]' \
  --output table | grep -E "c5\.|c6\.|p3\.|p4\.|g4\.|g5\."

# AWS: Check for high CPU utilization
aws cloudwatch get-metric-statistics \
  --namespace AWS/EC2 \
  --metric-name CPUUtilization \
  --dimensions Name=InstanceId,Value=i-SUSPECT_INSTANCE \
  --start-time 2026-02-22T00:00:00Z \
  --end-time 2026-02-23T00:00:00Z \
  --period 3600 \
  --statistics Average \
  --query 'Datapoints[*].[Timestamp,Average]' --output table

# AWS: Check Cost Anomaly Detection
aws ce get-anomalies \
  --date-interval '{"StartDate":"2026-02-16","EndDate":"2026-02-23"}' \
  --query 'Anomalies[*].[AnomalyId,AnomalyScore.MaxScore,Impact.TotalImpact,RootCauses[0].Service]' \
  --output table

# Azure: Find VMs with unusual CPU patterns
az monitor metrics list \
  --resource /subscriptions/SUB_ID/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/VM_NAME \
  --metric "Percentage CPU" \
  --interval PT1H \
  --start-time 2026-02-22T00:00:00Z \
  --end-time 2026-02-23T00:00:00Z
```

### Step 3: Analyze Network Traffic for Mining Pool Connections

Identify network connections to known cryptocurrency mining pools and Stratum protocol traffic.

```bash
# Query VPC Flow Logs for connections to known mining pool ports (3333, 4444, 8333, 14444)
# AWS: Using CloudWatch Logs Insights
aws logs start-query \
  --log-group-name vpc-flow-logs \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields @timestamp, srcAddr, dstAddr, dstPort, bytes
    | filter dstPort in [3333, 4444, 8333, 14444, 14433, 45700]
    | sort bytes desc
    | limit 100
  '

# Check DNS queries for mining pool domains
aws logs start-query \
  --log-group-name route53-resolver-logs \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields @timestamp, query_name, srcids.instance
    | filter query_name like /pool|mining|xmr|monero|nicehash|ethermine|f2pool|nanopool/
    | limit 100
  '

# GCP: Query VPC Flow Logs for mining connections
gcloud logging read '
  resource.type="gce_subnetwork"
  AND jsonPayload.connection.dest_port=(3333 OR 4444 OR 8333 OR 14444)
  AND timestamp>="2026-02-22T00:00:00Z"
' --limit=50 --format=json
```

### Step 4: Investigate Container and Serverless Mining

Check for cryptomining within container workloads and serverless functions.

```bash
# EKS/Kubernetes: Find pods with high CPU usage
kubectl top pods --all-namespaces --sort-by=cpu | head -20

# Find suspicious container images
kubectl get pods --all-namespaces -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
suspicious = ['xmrig', 'monero', 'miner', 'crypto', 'pool', 'hashrate']
for pod in data['items']:
    ns = pod['metadata']['namespace']
    name = pod['metadata']['name']
    for container in pod['spec'].get('containers', []):
        image = container.get('image', '').lower()
        if any(s in image for s in suspicious):
            print(f'SUSPICIOUS: {ns}/{name} -> image: {container[\"image\"]}')
"

# Check Lambda function for mining (unusual duration and memory)
aws lambda list-functions --query 'Functions[*].[FunctionName,MemorySize,Timeout]' --output table
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Duration \
  --dimensions Name=FunctionName,Value=SUSPECT_FUNCTION \
  --start-time 2026-02-22T00:00:00Z \
  --end-time 2026-02-23T00:00:00Z \
  --period 3600 \
  --statistics Average Maximum
```

### Step 5: Trace the Attack Vector

Investigate how the mining infrastructure was deployed by analyzing API logs and credential usage.

```bash
# AWS: Find who launched suspect instances
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::EC2::Instance \
  --start-time 2026-02-20T00:00:00Z \
  --query 'Events[?contains(Resources[0].ResourceName, `i-SUSPECT`)].[EventTime,EventName,Username,SourceIPAddress]' \
  --output table

# Check for leaked credentials being used
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA_SUSPECT_KEY \
  --query 'Events[*].[EventTime,EventName,SourceIPAddress,EventSource]' \
  --output table

# Check for unusual API calls (RunInstances from new IPs)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
  --start-time 2026-02-20T00:00:00Z \
  --query 'Events[*].[EventTime,Username,SourceIPAddress]' \
  --output table
```

### Step 6: Contain and Remediate

Isolate mining resources, revoke compromised credentials, and implement preventive controls.

```bash
# Terminate mining instances
aws ec2 terminate-instances --instance-ids i-MINING_INSTANCE_1 i-MINING_INSTANCE_2

# Deactivate compromised credentials
aws iam update-access-key --user-name compromised-user \
  --access-key-id AKIA_COMPROMISED --status Inactive

# Add SCP to prevent large instance types in non-production accounts
cat > mining-prevention-scp.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "ec2:RunInstances",
    "Resource": "arn:aws:ec2:*:*:instance/*",
    "Condition": {
      "ForAnyValue:StringLike": {
        "ec2:InstanceType": ["p3.*", "p4.*", "g4.*", "g5.*"]
      }
    }
  }]
}
EOF

# Set up billing alarm for early detection
aws cloudwatch put-metric-alarm \
  --alarm-name high-ec2-spend \
  --metric-name EstimatedCharges \
  --namespace AWS/Billing \
  --statistic Maximum \
  --period 21600 \
  --threshold 500 \
  --comparison-operator GreaterThanThreshold \
  --alarm-actions arn:aws:sns:us-east-1:ACCOUNT:billing-alerts
```

## Key Concepts

| Term | Definition |
|------|------------|
| Cryptomining | Unauthorized use of cloud compute resources to mine cryptocurrency, typically Monero (XMR) due to its CPU-mining efficiency and privacy features |
| Stratum Protocol | Mining pool communication protocol typically running on ports 3333, 4444, or 14444 used to coordinate mining work between miners and pools |
| GuardDuty CryptoCurrency Finding | AWS threat detection finding that identifies EC2, EKS, or Lambda resources communicating with known cryptocurrency mining infrastructure |
| Cost Anomaly Detection | AWS service that uses machine learning to detect unusual spending patterns that may indicate unauthorized resource provisioning |
| Compute Abuse | Unauthorized use of cloud compute resources, commonly via compromised credentials or exploited applications, for cryptomining or other purposes |
| Service Control Policy | AWS Organizations policy that can restrict instance types or regions to prevent attackers from launching GPU/compute-optimized mining instances |

## Tools & Systems

- **AWS GuardDuty**: Threat detection service with specific finding types for cryptocurrency mining activity on EC2, EKS, and Lambda
- **Azure Defender for Cloud**: Detects cryptomining through behavioral analysis and network threat intelligence
- **GCP Event Threat Detection**: SCC component that identifies cryptocurrency mining via network analysis and process monitoring
- **CloudTrail / Activity Log / Audit Log**: API audit logs for tracing how mining resources were provisioned
- **VPC Flow Logs**: Network flow data for identifying connections to mining pool infrastructure

## Common Scenarios

### Scenario: Compromised AWS Access Key Used to Launch GPU Mining Fleet

**Context**: A billing alarm triggers after a weekend spike from $200/day to $15,000/day. Investigation reveals 50 p3.8xlarge instances running across four regions, all launched by an access key belonging to a developer.

**Approach**:
1. Query GuardDuty for CryptoCurrency findings to confirm mining activity
2. Terminate all mining instances across all regions immediately
3. Deactivate the compromised access key and check CloudTrail for the source IP
4. Discover the key was exposed in a public GitHub repository via TruffleHog scan
5. Rotate all credentials for the compromised user
6. Implement SCP to deny GPU instance types in non-production accounts
7. Enable AWS Cost Anomaly Detection with automated alerts
8. Set up git-secrets pre-commit hooks across the development team

**Pitfalls**: Cryptominers often launch instances in regions where the account has no monitoring. Enable GuardDuty in ALL regions. Mining instances may use spot requests that persist after instance termination, so also cancel any active spot fleet requests and auto-scaling groups created by the attacker.

## Output Format

```
Cloud Cryptomining Incident Report
=====================================
Account: 123456789012 (Production)
Detection Date: 2026-02-23
Alert Source: AWS Cost Anomaly Detection + GuardDuty

INCIDENT SUMMARY:
  Mining instances launched: 50 (p3.8xlarge)
  Regions affected: us-east-1, us-west-2, eu-west-1, ap-southeast-1
  Duration: ~48 hours (Feb 21 14:00 UTC to Feb 23 10:00 UTC)
  Estimated cost impact: $28,400
  Cryptocurrency mined: Monero (XMR)

ATTACK VECTOR:
  Compromised credential: AKIA...WXYZ (developer-user)
  Exposure method: Hardcoded in public GitHub repository
  First unauthorized API call: Feb 21 13:47 UTC from IP 185.x.x.x

GUARDDUTY FINDINGS:
  CryptoCurrency:EC2/BitcoinTool.B!DNS: 50 findings
  UnauthorizedAccess:EC2/TorIPCaller: 3 findings

CONTAINMENT ACTIONS:
  [x] All mining instances terminated
  [x] Compromised access key deactivated
  [x] New access key issued via Secrets Manager
  [x] SCP applied to deny GPU instance types
  [x] Cost anomaly alerting configured
  [x] GuardDuty enabled in all regions
```
