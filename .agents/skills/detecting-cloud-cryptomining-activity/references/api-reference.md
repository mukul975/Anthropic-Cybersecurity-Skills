# Cloud Cryptomining Detection API Reference

## GuardDuty - Cryptocurrency Finding Types

| Finding Type | Signal |
|-------------|--------|
| `CryptoCurrency:EC2/BitcoinTool.B!DNS` | EC2 querying crypto domains |
| `CryptoCurrency:EC2/BitcoinTool.B` | EC2 communicating with mining pools |
| `CryptoCurrency:Runtime/BitcoinTool.B!DNS` | Container DNS to mining domain |
| `CryptoCurrency:Runtime/BitcoinTool.B` | Container network to mining pool |
| `Impact:EC2/BitcoinDomainRequest.Reputation` | Known mining domain access |

## GuardDuty CLI

```bash
# Get detector ID
aws guardduty list-detectors --query 'DetectorIds[0]' --output text

# List crypto findings
aws guardduty list-findings --detector-id $DET \
  --finding-criteria '{"Criterion":{"type":{"Eq":["CryptoCurrency:EC2/BitcoinTool.B!DNS"]}}}'

# Get finding details
aws guardduty get-findings --detector-id $DET --finding-ids id1 id2
```

## AWS Cost Anomaly Detection

```bash
# Create cost anomaly monitor
aws ce create-anomaly-monitor --anomaly-monitor '{
  "MonitorName": "EC2CostSpike",
  "MonitorType": "DIMENSIONAL",
  "MonitorDimension": "SERVICE"
}'

# Create alert subscription
aws ce create-anomaly-subscription --anomaly-subscription '{
  "SubscriptionName": "CryptoAlert",
  "MonitorArnList": ["arn:aws:ce::123456789012:anomalymonitor/monitor-id"],
  "Subscribers": [{"Address": "soc@company.com", "Type": "EMAIL"}],
  "Threshold": 100.0,
  "Frequency": "IMMEDIATE"
}'
```

## Known Mining Pool Ports

```
3333   - Stratum protocol (common)
4444   - Mining proxy
5555   - Monero (XMR)
7777   - Alt-coin mining
8888   - Multi-pool
9999   - Mining proxy
14444  - XMRig default
45700  - MoneroOcean
```

## VPC Flow Logs Query (CloudWatch Insights)

```
fields @timestamp, srcaddr, dstaddr, dstport, action
| filter dstport in [3333, 4444, 5555, 7777, 14444, 45700]
| sort @timestamp desc
| limit 50
```

## EC2 Instance Remediation

```bash
# Terminate mining instance
aws ec2 terminate-instances --instance-ids i-0123456789abcdef0

# Revoke security group ingress on mining ports
aws ec2 revoke-security-group-ingress --group-id sg-xxx \
  --protocol tcp --port 3333 --cidr 0.0.0.0/0
```
