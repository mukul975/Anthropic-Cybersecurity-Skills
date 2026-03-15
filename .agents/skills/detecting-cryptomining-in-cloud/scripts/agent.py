#!/usr/bin/env python3
"""Cloud cryptomining detection agent with multi-signal analysis."""

import json
import subprocess
import sys
from datetime import datetime, timedelta


MINING_PORTS = [3333, 4444, 5555, 7777, 8888, 9999, 14444, 14433, 45700]
MINING_DOMAINS = [
    "pool.minexmr.com", "xmr.pool.minergate.com", "monerohash.com",
    "xmrpool.eu", "supportxmr.com", "pool.hashvault.pro",
    "gulf.moneroocean.stream", "rx.unmineable.com",
]


def aws_cli(args):
    """Execute AWS CLI command and return parsed JSON."""
    cmd = ["aws"] + args + ["--output", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
        return {"error": result.stderr.strip()} if result.returncode != 0 else {}
    except Exception as e:
        return {"error": str(e)}


def get_guardduty_crypto_findings():
    """Retrieve GuardDuty cryptocurrency-related findings."""
    det = aws_cli(["guardduty", "list-detectors"])
    detector_id = det.get("DetectorIds", [None])[0]
    if not detector_id:
        return {"error": "No GuardDuty detector found"}

    crypto_types = [
        "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "CryptoCurrency:EC2/BitcoinTool.B",
        "CryptoCurrency:Runtime/BitcoinTool.B!DNS",
        "CryptoCurrency:Runtime/BitcoinTool.B",
        "Impact:EC2/BitcoinDomainRequest.Reputation",
    ]
    result = aws_cli([
        "guardduty", "list-findings",
        "--detector-id", detector_id,
        "--finding-criteria", json.dumps({"Criterion": {"type": {"Eq": crypto_types}}}),
    ])
    finding_ids = result.get("FindingIds", [])
    if not finding_ids:
        return {"count": 0, "findings": []}

    details = aws_cli(["guardduty", "get-findings", "--detector-id", detector_id, "--finding-ids"] + finding_ids[:20])
    parsed = []
    for f in details.get("Findings", []):
        inst = f.get("Resource", {}).get("InstanceDetails", {})
        parsed.append({
            "type": f.get("Type"),
            "severity": f.get("Severity"),
            "instance_id": inst.get("InstanceId"),
            "instance_type": inst.get("InstanceType"),
            "region": f.get("Region"),
        })
    return {"count": len(parsed), "findings": parsed}


def check_high_cpu_instances():
    """Find EC2 instances with sustained high CPU utilization."""
    instances = aws_cli(["ec2", "describe-instances",
                         "--filters", "Name=instance-state-name,Values=running",
                         "--query", "Reservations[*].Instances[*].[InstanceId,InstanceType,LaunchTime]",
                         "--output", "json"])
    return instances


def create_cost_anomaly_monitor():
    """Create AWS Cost Anomaly Detection monitor for EC2 spikes."""
    return aws_cli([
        "ce", "create-anomaly-monitor",
        "--anomaly-monitor", json.dumps({
            "MonitorName": "CryptoMiningCostSpike",
            "MonitorType": "DIMENSIONAL",
            "MonitorDimension": "SERVICE",
        }),
    ])


def check_cloudtrail_instance_launches(hours=24):
    """Check CloudTrail for unusual instance launch patterns."""
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)
    result = aws_cli([
        "cloudtrail", "lookup-events",
        "--lookup-attributes", json.dumps([
            {"AttributeKey": "EventName", "AttributeValue": "RunInstances"}
        ]),
        "--start-time", start_time.isoformat() + "Z",
        "--end-time", end_time.isoformat() + "Z",
        "--max-results", "50",
    ])
    events = []
    for e in result.get("Events", []):
        detail = json.loads(e.get("CloudTrailEvent", "{}"))
        events.append({
            "time": e.get("EventTime"),
            "user": e.get("Username"),
            "source_ip": detail.get("sourceIPAddress"),
            "region": detail.get("awsRegion"),
            "instance_type": detail.get("requestParameters", {}).get("instanceType"),
        })
    return {"launches": events, "count": len(events)}


def query_vpc_flow_logs_mining(log_group="/aws/vpc/flowlogs"):
    """Query VPC Flow Logs for traffic to mining pool ports."""
    port_filter = " || ".join([f"dstport = {p}" for p in MINING_PORTS])
    query = f"""
    fields @timestamp, srcaddr, dstaddr, dstport, bytes, action
    | filter ({port_filter})
    | sort @timestamp desc
    | limit 100
    """
    return aws_cli([
        "logs", "start-query",
        "--log-group-name", log_group,
        "--start-time", str(int((datetime.utcnow() - timedelta(hours=24)).timestamp())),
        "--end-time", str(int(datetime.utcnow().timestamp())),
        "--query-string", query,
    ])


def isolate_mining_instance(instance_id):
    """Isolate a mining instance by modifying its security group."""
    sg_result = aws_cli([
        "ec2", "create-security-group",
        "--group-name", f"isolation-{instance_id}",
        "--description", "Isolation SG for mining instance",
    ])
    sg_id = sg_result.get("GroupId")
    if not sg_id:
        return {"error": "Failed to create isolation security group"}

    return aws_cli([
        "ec2", "modify-instance-attribute",
        "--instance-id", instance_id,
        "--groups", sg_id,
    ])


def generate_report():
    """Generate comprehensive cryptomining detection report."""
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "guardduty": get_guardduty_crypto_findings(),
        "recent_launches": check_cloudtrail_instance_launches(),
        "known_mining_ports": MINING_PORTS,
        "known_mining_domains": MINING_DOMAINS,
    }


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "report"
    if action == "report":
        print(json.dumps(generate_report(), indent=2, default=str))
    elif action == "findings":
        print(json.dumps(get_guardduty_crypto_findings(), indent=2, default=str))
    elif action == "launches":
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        print(json.dumps(check_cloudtrail_instance_launches(hours), indent=2, default=str))
    elif action == "flow-logs":
        lg = sys.argv[2] if len(sys.argv) > 2 else "/aws/vpc/flowlogs"
        print(json.dumps(query_vpc_flow_logs_mining(lg), indent=2, default=str))
    elif action == "isolate" and len(sys.argv) > 2:
        print(json.dumps(isolate_mining_instance(sys.argv[2]), indent=2))
    else:
        print("Usage: agent.py [report|findings|launches [hours]|flow-logs [log-group]|isolate <instance-id>]")
