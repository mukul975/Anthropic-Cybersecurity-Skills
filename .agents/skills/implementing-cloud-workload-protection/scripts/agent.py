#!/usr/bin/env python3
"""Agent for cloud workload protection on AWS EC2 instances."""

import os
import json
import time
import argparse
from datetime import datetime

import boto3
from botocore.exceptions import ClientError


def get_running_instances(session, filters=None):
    """List all running EC2 instances."""
    ec2 = session.client("ec2")
    params = {"Filters": [{"Name": "instance-state-name", "Values": ["running"]}]}
    if filters:
        params["Filters"].extend(filters)
    instances = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(**params):
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                instances.append({
                    "instance_id": inst["InstanceId"],
                    "type": inst["InstanceType"],
                    "ip": inst.get("PrivateIpAddress", ""),
                    "launch_time": str(inst["LaunchTime"]),
                })
    return instances


def run_ssm_command(session, instance_ids, commands):
    """Execute commands on instances via SSM Run Command."""
    ssm = session.client("ssm")
    resp = ssm.send_command(
        InstanceIds=instance_ids,
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands},
        TimeoutSeconds=60,
    )
    command_id = resp["Command"]["CommandId"]
    time.sleep(5)
    results = {}
    for iid in instance_ids:
        try:
            output = ssm.get_command_invocation(CommandId=command_id, InstanceId=iid)
            results[iid] = {
                "status": output["Status"],
                "stdout": output.get("StandardOutputContent", ""),
                "stderr": output.get("StandardErrorContent", ""),
            }
        except ClientError as e:
            results[iid] = {"status": "Error", "error": str(e)}
    return results


def scan_for_cryptominers(session, instance_ids):
    """Detect cryptomining processes on instances."""
    commands = [
        "ps aux | grep -iE 'xmrig|minerd|cryptonight|stratum|nicehash' | grep -v grep",
        "find /tmp /var/tmp /dev/shm -name '*.sh' -o -name 'config.json' 2>/dev/null | head -20",
    ]
    results = run_ssm_command(session, instance_ids, commands)
    findings = []
    for iid, result in results.items():
        if result.get("stdout", "").strip():
            findings.append({
                "instance_id": iid,
                "type": "cryptominer",
                "severity": "CRITICAL",
                "output": result["stdout"].strip(),
            })
    return findings


def scan_for_reverse_shells(session, instance_ids):
    """Detect potential reverse shell connections."""
    commands = [
        "ss -tlnp 2>/dev/null | grep ESTAB | grep -vE ':443|:80|:22|:8089'",
        "ls -la /dev/tcp 2>/dev/null; ls -la /proc/*/fd 2>/dev/null | grep socket | head -20",
    ]
    results = run_ssm_command(session, instance_ids, commands)
    findings = []
    for iid, result in results.items():
        if result.get("stdout", "").strip():
            findings.append({
                "instance_id": iid,
                "type": "suspicious_connections",
                "severity": "HIGH",
                "output": result["stdout"].strip(),
            })
    return findings


def check_file_integrity(session, instance_ids):
    """Check integrity of critical system files."""
    commands = [
        "rpm -Va 2>/dev/null | grep -E '^..5' | head -20 || "
        "debsums -c 2>/dev/null | head -20",
        "find /usr/bin /usr/sbin -newer /var/log/lastlog -type f 2>/dev/null | head -20",
    ]
    results = run_ssm_command(session, instance_ids, commands)
    findings = []
    for iid, result in results.items():
        if result.get("stdout", "").strip():
            findings.append({
                "instance_id": iid,
                "type": "file_integrity",
                "severity": "MEDIUM",
                "modified_files": result["stdout"].strip().splitlines(),
            })
    return findings


def check_cpu_anomaly(session, instance_ids):
    """Detect CPU usage anomalies via CloudWatch."""
    cw = session.client("cloudwatch")
    anomalies = []
    for iid in instance_ids:
        resp = cw.get_metric_statistics(
            Namespace="AWS/EC2",
            MetricName="CPUUtilization",
            Dimensions=[{"Name": "InstanceId", "Value": iid}],
            StartTime=datetime.utcnow().replace(hour=0, minute=0),
            EndTime=datetime.utcnow(),
            Period=300,
            Statistics=["Average"],
        )
        for dp in resp.get("Datapoints", []):
            if dp["Average"] > 90:
                anomalies.append({
                    "instance_id": iid,
                    "cpu_avg": round(dp["Average"], 1),
                    "timestamp": str(dp["Timestamp"]),
                    "severity": "HIGH",
                })
    return anomalies


def main():
    parser = argparse.ArgumentParser(description="Cloud Workload Protection Agent")
    parser.add_argument("--profile", default=os.getenv("AWS_PROFILE"))
    parser.add_argument("--region", default=os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
    parser.add_argument("--output", default="cwp_report.json")
    parser.add_argument("--action", choices=[
        "list", "cryptominer", "reverse_shell", "integrity", "cpu", "full_scan"
    ], default="full_scan")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    instances = get_running_instances(session)
    instance_ids = [i["instance_id"] for i in instances]
    report["instances"] = instances
    print(f"[+] Running instances: {len(instances)}")

    if args.action in ("cryptominer", "full_scan") and instance_ids:
        findings = scan_for_cryptominers(session, instance_ids)
        report["findings"]["cryptominers"] = findings
        print(f"[+] Cryptominer detections: {len(findings)}")

    if args.action in ("reverse_shell", "full_scan") and instance_ids:
        findings = scan_for_reverse_shells(session, instance_ids)
        report["findings"]["reverse_shells"] = findings
        print(f"[+] Suspicious connections: {len(findings)}")

    if args.action in ("integrity", "full_scan") and instance_ids:
        findings = check_file_integrity(session, instance_ids)
        report["findings"]["file_integrity"] = findings
        print(f"[+] File integrity issues: {len(findings)}")

    if args.action in ("cpu", "full_scan") and instance_ids:
        anomalies = check_cpu_anomaly(session, instance_ids)
        report["findings"]["cpu_anomalies"] = anomalies
        print(f"[+] CPU anomalies: {len(anomalies)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
