#!/usr/bin/env python3
"""Cloud Incident Response Agent - Automates AWS/Azure cloud IR containment and evidence collection."""

import json
import logging
import argparse
import subprocess
from datetime import datetime, timedelta

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def aws_disable_access_key(username, access_key_id):
    """Disable a compromised IAM access key via AWS CLI."""
    cmd = [
        "aws", "iam", "update-access-key",
        "--user-name", username,
        "--access-key-id", access_key_id,
        "--status", "Inactive",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        logger.info("Disabled access key %s for user %s", access_key_id, username)
    else:
        logger.error("Failed to disable key: %s", result.stderr)
    return result.returncode == 0


def aws_attach_deny_all(username):
    """Attach AWSDenyAll policy to a compromised IAM user."""
    cmd = [
        "aws", "iam", "attach-user-policy",
        "--user-name", username,
        "--policy-arn", "arn:aws:iam::aws:policy/AWSDenyAll",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        logger.info("Attached AWSDenyAll to user %s", username)
    return result.returncode == 0


def aws_isolate_ec2(instance_id, forensic_sg):
    """Isolate an EC2 instance by changing its security group to forensic isolation SG."""
    cmd = [
        "aws", "ec2", "modify-instance-attribute",
        "--instance-id", instance_id,
        "--groups", forensic_sg,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        logger.info("Isolated EC2 %s with security group %s", instance_id, forensic_sg)
    return result.returncode == 0


def aws_snapshot_ebs(instance_id):
    """Create EBS snapshots of all volumes attached to an EC2 instance."""
    cmd = [
        "aws", "ec2", "describe-volumes",
        "--filters", f"Name=attachment.instance-id,Values={instance_id}",
        "--query", "Volumes[*].VolumeId",
        "--output", "text",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    volume_ids = result.stdout.strip().split()
    snapshots = []
    for vol_id in volume_ids:
        snap_cmd = [
            "aws", "ec2", "create-snapshot",
            "--volume-id", vol_id,
            "--description", f"IR evidence - {instance_id} - {datetime.utcnow().isoformat()}",
        ]
        snap_result = subprocess.run(snap_cmd, capture_output=True, text=True)
        if snap_result.returncode == 0:
            snap_data = json.loads(snap_result.stdout)
            snapshots.append(snap_data.get("SnapshotId"))
            logger.info("Created snapshot %s for volume %s", snap_data.get("SnapshotId"), vol_id)
    return snapshots


def aws_query_cloudtrail(username, hours_back=24):
    """Query CloudTrail for API calls made by a specific IAM user."""
    start_time = (datetime.utcnow() - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cmd = [
        "aws", "cloudtrail", "lookup-events",
        "--lookup-attributes", f"AttributeKey=Username,AttributeValue={username}",
        "--start-time", start_time,
        "--output", "json",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        events = json.loads(result.stdout).get("Events", [])
        logger.info("CloudTrail: %d events for user %s in last %d hours", len(events), username, hours_back)
        parsed = []
        for event in events:
            ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
            parsed.append({
                "time": event.get("EventTime", ""),
                "event_name": event.get("EventName", ""),
                "source_ip": ct_event.get("sourceIPAddress", ""),
                "user_agent": ct_event.get("userAgent", ""),
                "resources": event.get("Resources", []),
            })
        return parsed
    return []


def aws_list_attacker_resources(username, events):
    """Identify resources created by the attacker from CloudTrail events."""
    create_events = [
        e for e in events
        if e["event_name"].startswith(("Create", "Run", "Put", "Attach"))
    ]
    logger.info("Identified %d resource creation events", len(create_events))
    return create_events


def aws_check_all_regions_instances():
    """Check all AWS regions for unauthorized EC2 instances."""
    cmd = ["aws", "ec2", "describe-regions", "--query", "Regions[*].RegionName", "--output", "text"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    regions = result.stdout.strip().split()
    all_instances = {}
    for region in regions:
        cmd = [
            "aws", "ec2", "describe-instances",
            "--region", region,
            "--query", "Reservations[*].Instances[*].[InstanceId,InstanceType,State.Name]",
            "--output", "json",
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 0:
            instances = json.loads(r.stdout)
            running = [i for reservation in instances for i in reservation if i[2] == "running"]
            if running:
                all_instances[region] = running
    logger.info("Found instances in %d regions", len(all_instances))
    return all_instances


def generate_ir_report(incident_id, username, events, snapshots, containment_actions):
    """Generate a cloud incident response report."""
    report = {
        "incident_id": incident_id,
        "timestamp": datetime.utcnow().isoformat(),
        "compromised_identity": username,
        "cloudtrail_events": len(events),
        "evidence_snapshots": snapshots,
        "containment_actions": containment_actions,
        "attacker_activity": events[:20],
    }
    print(json.dumps(report, indent=2))
    return report


def main():
    parser = argparse.ArgumentParser(description="Cloud Incident Response Agent")
    parser.add_argument("--incident-id", required=True, help="Incident ID")
    parser.add_argument("--username", required=True, help="Compromised IAM username")
    parser.add_argument("--access-key-id", help="Compromised access key to disable")
    parser.add_argument("--instance-id", help="EC2 instance to isolate")
    parser.add_argument("--forensic-sg", default="sg-forensic-isolate", help="Forensic SG ID")
    parser.add_argument("--output", default="cloud_ir_report.json")
    args = parser.parse_args()

    containment = []

    if args.access_key_id:
        aws_disable_access_key(args.username, args.access_key_id)
        containment.append(f"Disabled access key {args.access_key_id}")

    aws_attach_deny_all(args.username)
    containment.append(f"Attached AWSDenyAll to {args.username}")

    snapshots = []
    if args.instance_id:
        aws_isolate_ec2(args.instance_id, args.forensic_sg)
        containment.append(f"Isolated EC2 {args.instance_id}")
        snapshots = aws_snapshot_ebs(args.instance_id)

    events = aws_query_cloudtrail(args.username, hours_back=72)
    attacker_actions = aws_list_attacker_resources(args.username, events)

    report = generate_ir_report(args.incident_id, args.username, events, snapshots, containment)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("IR report saved to %s", args.output)


if __name__ == "__main__":
    main()
