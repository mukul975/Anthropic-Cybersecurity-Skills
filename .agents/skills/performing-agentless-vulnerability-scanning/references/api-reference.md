# Agentless Vulnerability Scanning - API Reference

## AWS Inspector2 (boto3)

### Enable Inspector
```python
client = boto3.client("inspector2")
client.enable(resourceTypes=["EC2", "ECR", "LAMBDA"],
              accountIds=["123456789012"])
```

### Check Account Status
```python
client.batch_get_account_status(accountIds=["123456789012"])
```

### List Coverage
```python
paginator = client.get_paginator("list_coverage")
for page in paginator.paginate(
    filterCriteria={"resourceType": [{"comparison": "EQUALS", "value": "AWS_EC2_INSTANCE"}]}
):
    for resource in page["coveredResources"]:
        print(resource["resourceId"], resource["scanStatus"]["statusCode"])
```

### List Findings
```python
paginator = client.get_paginator("list_findings")
for page in paginator.paginate(
    filterCriteria={"severity": [{"comparison": "EQUALS", "value": "CRITICAL"}]}
):
    for finding in page["findings"]:
        print(finding["title"], finding["severity"])
```

### Finding Fields

| Field | Type | Description |
|-------|------|-------------|
| `findingArn` | string | Unique finding ARN |
| `title` | string | Vulnerability title |
| `severity` | string | CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL |
| `status` | string | ACTIVE, SUPPRESSED, CLOSED |
| `type` | string | NETWORK_REACHABILITY or PACKAGE_VULNERABILITY |
| `resources` | array | Affected AWS resources |
| `packageVulnerabilityDetails.vulnerabilityId` | string | CVE ID |
| `packageVulnerabilityDetails.cvss` | array | CVSS scores |
| `packageVulnerabilityDetails.fixedInVersion` | string | Patched version |

## Agentless Scanning via EBS Snapshots

Inspector2 supports agentless scanning by:
1. Creating EBS snapshots of instance volumes
2. Mounting snapshots in Inspector service account
3. Scanning file system for vulnerable packages
4. No agent installation required on target instances

### Create Snapshot (boto3 EC2)
```python
ec2 = boto3.client("ec2")
ec2.create_snapshot(
    VolumeId="vol-xxx",
    Description="Agentless scan",
    TagSpecifications=[{"ResourceType": "snapshot",
                        "Tags": [{"Key": "Purpose", "Value": "VulnScan"}]}]
)
```

## SSM Inventory (Alternative)

AWS Systems Manager Inventory collects software inventory without custom agents:
```python
ssm = boto3.client("ssm")
ssm.get_inventory(
    Filters=[{"Key": "AWS:Application.Name", "Values": ["openssl"]}]
)
```

## Scan Types

| Type | Method | Agent Required |
|------|--------|---------------|
| Inspector Classic | AWS agent | Yes |
| Inspector2 Agent | SSM agent | Yes (auto-installed) |
| Inspector2 Agentless | EBS snapshot | No |
| SSM Inventory | SSM agent | Yes |

## Output Schema

```json
{
  "report": "agentless_vulnerability_scanning",
  "inspector_status": {"enabled": true},
  "total_resources_scanned": 50,
  "uncovered_resources": 3,
  "total_findings": 125,
  "severity_summary": {"CRITICAL": 5, "HIGH": 30, "MEDIUM": 60, "LOW": 30}
}
```

## CLI Usage

```bash
python agent.py --region us-east-1 --severity CRITICAL HIGH --output report.json
```
