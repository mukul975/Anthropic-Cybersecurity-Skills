# Detecting Cryptomining in Cloud API Reference

## Detection Signal Categories

| Signal | Source | Indicator |
|--------|--------|-----------|
| Cost spike | AWS Cost Explorer | Sudden EC2/GPU cost increase |
| High CPU | CloudWatch | Sustained >95% CPU utilization |
| Mining ports | VPC Flow Logs | Traffic on 3333, 4444, 14444 |
| DNS queries | GuardDuty / Route53 | Queries to pool domains |
| Process | Runtime Monitoring | xmrig, ccminer, ethminer |

## GuardDuty Crypto Findings

```bash
# List crypto findings
aws guardduty list-findings --detector-id $DET \
  --finding-criteria '{"Criterion":{"type":{"Eq":["CryptoCurrency:EC2/BitcoinTool.B!DNS","CryptoCurrency:Runtime/BitcoinTool.B"]}}}'
```

## CloudWatch CPU Alarm

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "HighCPU-Mining" \
  --metric-name CPUUtilization \
  --namespace AWS/EC2 \
  --statistic Average \
  --period 300 --threshold 95 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 6 \
  --alarm-actions arn:aws:sns:us-east-1:123456:SOCAlerts
```

## AWS Cost Anomaly Detection

```bash
# Create monitor
aws ce create-anomaly-monitor --anomaly-monitor '{
  "MonitorName": "EC2CostSpike", "MonitorType": "DIMENSIONAL",
  "MonitorDimension": "SERVICE"
}'

# Get anomalies
aws ce get-anomalies --date-interval '{"StartDate":"2024-01-01","EndDate":"2024-01-31"}'
```

## VPC Flow Logs Mining Port Query

```
fields @timestamp, srcaddr, dstaddr, dstport, bytes
| filter dstport in [3333, 4444, 5555, 14444, 45700]
| stats sum(bytes) as total_bytes by srcaddr, dstaddr, dstport
| sort total_bytes desc
```

## Known Mining Pool Domains

```
pool.minexmr.com, xmr.pool.minergate.com, monerohash.com,
xmrpool.eu, supportxmr.com, pool.hashvault.pro,
gulf.moneroocean.stream, rx.unmineable.com
```

## Instance Remediation

```bash
# Terminate mining instance
aws ec2 terminate-instances --instance-ids i-0123456789abcdef0

# Isolate via security group
aws ec2 modify-instance-attribute --instance-id i-xxx --groups sg-isolation

# Snapshot for forensics before termination
aws ec2 create-snapshot --volume-id vol-xxx --description "Mining forensics"
```
