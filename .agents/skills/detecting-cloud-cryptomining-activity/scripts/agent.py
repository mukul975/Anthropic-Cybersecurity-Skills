#!/usr/bin/env python3
"""Cloud cryptomining detection agent using AWS GuardDuty and CloudWatch."""

import json
import subprocess
import sys
from datetime import datetime


CRYPTO_FINDING_TYPES = [
    "CryptoCurrency:EC2/BitcoinTool.B!DNS",
    "CryptoCurrency:EC2/BitcoinTool.B",
    "CryptoCurrency:Runtime/BitcoinTool.B!DNS",
    "CryptoCurrency:Runtime/BitcoinTool.B",
    "CryptoCurrency:Lambda/BitcoinTool.B",
    "Impact:EC2/BitcoinDomainRequest.Reputation",
    "Impact:Runtime/BitcoinDomainRequest.Reputation",
]

MINING_POOL_PORTS = [3333, 4444, 5555, 7777, 8888, 9999, 14444, 45700]


def aws_cli(args):
    """Execute an AWS CLI command and return parsed JSON."""
    cmd = ["aws"] + args + ["--output", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return json.loads(result.stdout) if result.stdout.strip() else {}
        return {"error": result.stderr.strip()}
    except Exception as e:
        return {"error": str(e)}


def get_guardduty_detector():
    """Get the GuardDuty detector ID."""
    result = aws_cli(["guardduty", "list-detectors"])
    detectors = result.get("DetectorIds", [])
    return detectors[0] if detectors else None


def list_crypto_findings(detector_id=None):
    """List GuardDuty findings related to cryptocurrency mining."""
    if not detector_id:
        detector_id = get_guardduty_detector()
    if not detector_id:
        return {"error": "No GuardDuty detector found"}

    criteria = {"Criterion": {"type": {"Eq": CRYPTO_FINDING_TYPES}, "service.archived": {"Eq": ["false"]}}}
    result = aws_cli([
        "guardduty", "list-findings",
        "--detector-id", detector_id,
        "--finding-criteria", json.dumps(criteria),
    ])
    finding_ids = result.get("FindingIds", [])
    if not finding_ids:
        return {"detector_id": detector_id, "findings": [], "count": 0}

    details = aws_cli([
        "guardduty", "get-findings",
        "--detector-id", detector_id,
        "--finding-ids"] + finding_ids[:25]
    )
    findings = []
    for f in details.get("Findings", []):
        resource = f.get("Resource", {})
        instance = resource.get("InstanceDetails", {})
        findings.append({
            "id": f.get("Id"),
            "type": f.get("Type"),
            "severity": f.get("Severity"),
            "title": f.get("Title"),
            "instance_id": instance.get("InstanceId"),
            "instance_type": instance.get("InstanceType"),
            "region": f.get("Region"),
            "updated_at": f.get("UpdatedAt"),
        })

    return {"detector_id": detector_id, "count": len(findings), "findings": findings}


def check_ec2_cpu_anomalies(threshold_percent=90):
    """Find EC2 instances with sustained high CPU (potential mining)."""
    result = aws_cli([
        "cloudwatch", "get-metric-data",
        "--metric-data-queries", json.dumps([{
            "Id": "cpu",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/EC2",
                    "MetricName": "CPUUtilization",
                },
                "Period": 3600,
                "Stat": "Average",
            },
        }]),
        "--start-time", (datetime.utcnow().replace(hour=0, minute=0, second=0)).isoformat() + "Z",
        "--end-time", datetime.utcnow().isoformat() + "Z",
    ])
    return result


def check_cost_anomalies():
    """Check for cost anomaly detections that may indicate mining."""
    result = aws_cli([
        "ce", "get-anomalies",
        "--date-interval", json.dumps({
            "StartDate": datetime.utcnow().strftime("%Y-%m-01"),
            "EndDate": datetime.utcnow().strftime("%Y-%m-%d"),
        }),
    ])
    return result


def check_vpc_flow_mining_ports(log_group="/aws/vpc/flowlogs"):
    """Query CloudWatch Logs for connections to known mining pool ports."""
    ports_filter = " || ".join([f"dstport = {p}" for p in MINING_POOL_PORTS])
    query = f'fields @timestamp, srcaddr, dstaddr, dstport, action | filter ({ports_filter}) | sort @timestamp desc | limit 50'
    result = aws_cli([
        "logs", "start-query",
        "--log-group-name", log_group,
        "--start-time", str(int((datetime.utcnow().replace(hour=0)).timestamp())),
        "--end-time", str(int(datetime.utcnow().timestamp())),
        "--query-string", query,
    ])
    return result


def terminate_mining_instance(instance_id):
    """Terminate a confirmed cryptomining EC2 instance."""
    result = aws_cli(["ec2", "terminate-instances", "--instance-ids", instance_id])
    return {
        "action": "terminate_instance",
        "instance_id": instance_id,
        "result": result,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


def generate_report():
    """Generate a comprehensive cryptomining detection report."""
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "guardduty_findings": list_crypto_findings(),
        "cost_anomalies": check_cost_anomalies(),
    }


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "report"
    if action == "report":
        print(json.dumps(generate_report(), indent=2, default=str))
    elif action == "findings":
        print(json.dumps(list_crypto_findings(), indent=2, default=str))
    elif action == "costs":
        print(json.dumps(check_cost_anomalies(), indent=2, default=str))
    elif action == "flow-logs":
        lg = sys.argv[2] if len(sys.argv) > 2 else "/aws/vpc/flowlogs"
        print(json.dumps(check_vpc_flow_mining_ports(lg), indent=2, default=str))
    elif action == "terminate" and len(sys.argv) > 2:
        print(json.dumps(terminate_mining_instance(sys.argv[2]), indent=2, default=str))
    else:
        print("Usage: agent.py [report|findings|costs|flow-logs [log-group]|terminate <instance-id>]")
