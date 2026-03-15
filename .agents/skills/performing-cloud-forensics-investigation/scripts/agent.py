#!/usr/bin/env python3
"""
Cloud Forensics Investigation Agent
Collects and analyzes forensic evidence from AWS cloud environments including
CloudTrail logs, EC2 snapshots, and IAM activity for incident response.
"""

import json
import sys
from datetime import datetime, timezone, timedelta

import boto3
from botocore.exceptions import ClientError


def collect_cloudtrail_events(
    start_time: datetime, end_time: datetime, region: str = "us-east-1"
) -> list[dict]:
    """Collect CloudTrail management events for the investigation window."""
    ct = boto3.client("cloudtrail", region_name=region)
    events = []

    paginator = ct.get_paginator("lookup_events")
    for page in paginator.paginate(
        StartTime=start_time,
        EndTime=end_time,
        MaxResults=50,
    ):
        for event in page.get("Events", []):
            cloud_event = json.loads(event.get("CloudTrailEvent", "{}"))
            events.append({
                "timestamp": str(event.get("EventTime", "")),
                "event_name": event.get("EventName", ""),
                "event_source": event.get("EventSource", ""),
                "username": event.get("Username", ""),
                "source_ip": cloud_event.get("sourceIPAddress", ""),
                "user_agent": cloud_event.get("userAgent", ""),
                "region": cloud_event.get("awsRegion", ""),
                "error_code": cloud_event.get("errorCode", ""),
                "error_message": cloud_event.get("errorMessage", ""),
                "resources": event.get("Resources", []),
            })

    return events


def identify_suspicious_activity(events: list[dict]) -> list[dict]:
    """Identify suspicious CloudTrail events indicating compromise."""
    suspicious_patterns = {
        "ConsoleLogin": "Console login detected",
        "CreateAccessKey": "New access key created",
        "CreateUser": "New IAM user created",
        "AttachUserPolicy": "Policy attached to user",
        "PutBucketPolicy": "S3 bucket policy modified",
        "AuthorizeSecurityGroupIngress": "Security group opened",
        "RunInstances": "EC2 instance launched",
        "CreateKeyPair": "SSH key pair created",
        "StopLogging": "CloudTrail logging stopped",
        "DeleteTrail": "CloudTrail trail deleted",
        "ModifySnapshotAttribute": "Snapshot shared externally",
        "CreateLoginProfile": "Console password set for user",
    }

    suspicious = []
    for event in events:
        event_name = event["event_name"]
        if event_name in suspicious_patterns:
            suspicious.append({
                **event,
                "reason": suspicious_patterns[event_name],
                "severity": "HIGH" if event_name in (
                    "StopLogging", "DeleteTrail", "CreateAccessKey", "AttachUserPolicy"
                ) else "MEDIUM",
            })

        if event.get("error_code") == "AccessDenied":
            suspicious.append({
                **event,
                "reason": "Access denied - possible reconnaissance",
                "severity": "LOW",
            })

    return suspicious


def snapshot_ec2_instance(instance_id: str, region: str = "us-east-1") -> list[dict]:
    """Create forensic snapshots of all EBS volumes attached to an instance."""
    ec2 = boto3.client("ec2", region_name=region)
    snapshots = []

    try:
        instance = ec2.describe_instances(InstanceIds=[instance_id])
        reservations = instance["Reservations"]
        if not reservations:
            return [{"error": f"Instance {instance_id} not found"}]

        volumes = []
        for reservation in reservations:
            for inst in reservation["Instances"]:
                for mapping in inst.get("BlockDeviceMappings", []):
                    vol_id = mapping.get("Ebs", {}).get("VolumeId")
                    if vol_id:
                        volumes.append({"volume_id": vol_id, "device": mapping["DeviceName"]})

        for vol in volumes:
            snap = ec2.create_snapshot(
                VolumeId=vol["volume_id"],
                Description=f"Forensic snapshot - {instance_id} - {vol['device']} - "
                            f"{datetime.now(timezone.utc).strftime('%Y%m%d')}",
                TagSpecifications=[{
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "Purpose", "Value": "forensics"},
                        {"Key": "SourceInstance", "Value": instance_id},
                        {"Key": "SourceVolume", "Value": vol["volume_id"]},
                    ],
                }],
            )
            snapshots.append({
                "snapshot_id": snap["SnapshotId"],
                "volume_id": vol["volume_id"],
                "device": vol["device"],
                "state": snap["State"],
            })

    except ClientError as e:
        snapshots.append({"error": str(e)})

    return snapshots


def collect_iam_activity(username: str) -> dict:
    """Collect IAM activity for a specific user."""
    iam = boto3.client("iam")
    result = {"user": username, "access_keys": [], "policies": [], "groups": []}

    try:
        keys = iam.list_access_keys(UserName=username)
        for key in keys.get("AccessKeyMetadata", []):
            last_used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
            result["access_keys"].append({
                "key_id": key["AccessKeyId"],
                "status": key["Status"],
                "created": str(key["CreateDate"]),
                "last_used": str(last_used.get("AccessKeyLastUsed", {}).get("LastUsedDate", "Never")),
                "last_service": last_used.get("AccessKeyLastUsed", {}).get("ServiceName", "N/A"),
            })

        policies = iam.list_attached_user_policies(UserName=username)
        result["policies"] = [p["PolicyArn"] for p in policies["AttachedPolicies"]]

        groups = iam.list_groups_for_user(UserName=username)
        result["groups"] = [g["GroupName"] for g in groups["Groups"]]

    except ClientError as e:
        result["error"] = str(e)

    return result


def generate_report(events: list, suspicious: list, snapshots: list, iam: dict) -> str:
    """Generate cloud forensics investigation report."""
    lines = [
        "CLOUD FORENSICS INVESTIGATION REPORT",
        "=" * 50,
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"CloudTrail Events Collected: {len(events)}",
        f"Suspicious Events: {len(suspicious)}",
        f"Forensic Snapshots Created: {len(snapshots)}",
        "",
        "SUSPICIOUS ACTIVITY:",
        "-" * 40,
    ]

    for s in suspicious[:15]:
        lines.append(f"  [{s['severity']}] {s['timestamp']} - {s['event_name']}")
        lines.append(f"    User: {s['username']} | IP: {s['source_ip']} | {s['reason']}")

    if snapshots:
        lines.extend(["", "FORENSIC SNAPSHOTS:"])
        for snap in snapshots:
            if "error" not in snap:
                lines.append(f"  {snap['snapshot_id']} (vol: {snap['volume_id']}, device: {snap['device']})")

    if iam.get("access_keys"):
        lines.extend(["", f"IAM ACTIVITY ({iam['user']}):"])
        for key in iam["access_keys"]:
            lines.append(f"  Key: {key['key_id']} | Status: {key['status']} | Last Used: {key['last_used']}")

    return "\n".join(lines)


if __name__ == "__main__":
    hours_back = int(sys.argv[1]) if len(sys.argv) > 1 else 24
    instance_id = sys.argv[2] if len(sys.argv) > 2 else None
    username = sys.argv[3] if len(sys.argv) > 3 else None

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours_back)

    print(f"[*] Collecting CloudTrail events ({hours_back}h window)...")
    events = collect_cloudtrail_events(start_time, end_time)
    suspicious = identify_suspicious_activity(events)
    print(f"[*] Found {len(suspicious)} suspicious events")

    snapshots = []
    if instance_id:
        print(f"[*] Creating forensic snapshots for {instance_id}...")
        snapshots = snapshot_ec2_instance(instance_id)

    iam_data = {}
    if username:
        print(f"[*] Collecting IAM activity for {username}...")
        iam_data = collect_iam_activity(username)

    report = generate_report(events, suspicious, snapshots, iam_data)
    print(report)

    output = f"cloud_forensics_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    with open(output, "w") as f:
        json.dump({"events": events, "suspicious": suspicious, "snapshots": snapshots, "iam": iam_data}, f, indent=2)
    print(f"\n[*] Results saved to {output}")
