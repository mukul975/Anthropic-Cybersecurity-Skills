# API Reference: Implementing Cloud Workload Protection

## AWS SSM Run Command (boto3)

```python
import boto3
ssm = boto3.client("ssm")

# Execute command on instances
resp = ssm.send_command(
    InstanceIds=["i-abc123"],
    DocumentName="AWS-RunShellScript",
    Parameters={"commands": ["ps aux"]},
    TimeoutSeconds=60,
)
command_id = resp["Command"]["CommandId"]

# Get output
output = ssm.get_command_invocation(
    CommandId=command_id, InstanceId="i-abc123"
)
print(output["StandardOutputContent"])
```

## CloudWatch CPU Monitoring

```python
cw = boto3.client("cloudwatch")
resp = cw.get_metric_statistics(
    Namespace="AWS/EC2", MetricName="CPUUtilization",
    Dimensions=[{"Name": "InstanceId", "Value": "i-abc123"}],
    StartTime=start, EndTime=end, Period=300,
    Statistics=["Average"],
)
```

## Key Detection Commands

| Threat | Command |
|--------|---------|
| Cryptominer | `ps aux \| grep -iE 'xmrig\|minerd'` |
| Reverse shell | `ss -tlnp \| grep ESTAB` |
| File integrity | `rpm -Va \| grep '^..5'` |
| Unauthorized binaries | `find /tmp -executable -type f` |
| Cron persistence | `crontab -l; ls /etc/cron.d/` |

## GuardDuty Integration

```python
gd = boto3.client("guardduty")
findings = gd.list_findings(DetectorId="detector-id")
for fid in findings["FindingIds"]:
    detail = gd.get_findings(DetectorId="detector-id", FindingIds=[fid])
    print(detail["Findings"][0]["Type"])
```

### References

- SSM Run Command: https://docs.aws.amazon.com/systems-manager/latest/userguide/run-command.html
- CloudWatch: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudwatch.html
- GuardDuty: https://docs.aws.amazon.com/guardduty/latest/ug/
