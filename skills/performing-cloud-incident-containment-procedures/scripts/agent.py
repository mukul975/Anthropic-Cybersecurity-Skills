#!/usr/bin/env python3
"""AWS cloud incident containment agent.

Automates incident containment procedures in AWS environments including
EC2 instance isolation, IAM credential revocation, security group lockdown,
S3 bucket access restriction, and forensic snapshot creation using boto3.
"""
import argparse
import json
import sys
from datetime import datetime, timezone

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("[!] 'boto3' library required: pip install boto3", file=sys.stderr)
    sys.exit(1)


def get_session(profile=None, region=None):
    """Create a boto3 session."""
    kwargs = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return boto3.Session(**kwargs)


def isolate_ec2_instance(session, instance_id, vpc_id=None):
    """Isolate an EC2 instance by replacing security groups with a deny-all SG."""
    ec2 = session.client("ec2")
    findings = []
    print(f"[*] Isolating EC2 instance: {instance_id}")

    # Get current instance details
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        instance = resp["Reservations"][0]["Instances"][0]
        current_sgs = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
        instance_vpc = instance.get("VpcId", vpc_id)
        findings.append({"action": "describe_instance", "status": "OK",
                         "detail": f"Current SGs: {current_sgs}"})
    except ClientError as e:
        findings.append({"action": "describe_instance", "status": "FAIL",
                         "severity": "CRITICAL", "detail": str(e)})
        return findings

    # Create or find isolation security group
    isolation_sg_name = f"incident-isolation-{instance_id[:8]}"
    isolation_sg_id = None
    try:
        existing = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": [isolation_sg_name]},
                     {"Name": "vpc-id", "Values": [instance_vpc]}]
        )
        if existing["SecurityGroups"]:
            isolation_sg_id = existing["SecurityGroups"][0]["GroupId"]
        else:
            resp = ec2.create_security_group(
                GroupName=isolation_sg_name,
                Description=f"Incident isolation SG for {instance_id}",
                VpcId=instance_vpc,
            )
            isolation_sg_id = resp["GroupId"]
            # Revoke default egress rule
            ec2.revoke_security_group_egress(
                GroupId=isolation_sg_id,
                IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
            )
        findings.append({"action": "create_isolation_sg", "status": "OK",
                         "detail": f"SG: {isolation_sg_id} (no ingress, no egress)"})
    except ClientError as e:
        findings.append({"action": "create_isolation_sg", "status": "FAIL",
                         "severity": "HIGH", "detail": str(e)})
        return findings

    # Replace security groups with isolation SG
    try:
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[isolation_sg_id],
        )
        findings.append({"action": "apply_isolation_sg", "status": "OK",
                         "detail": f"Replaced {current_sgs} with [{isolation_sg_id}]"})
    except ClientError as e:
        findings.append({"action": "apply_isolation_sg", "status": "FAIL",
                         "severity": "CRITICAL", "detail": str(e)})

    # Tag instance as contained
    try:
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {"Key": "IncidentStatus", "Value": "CONTAINED"},
                {"Key": "ContainmentTime", "Value": datetime.now(timezone.utc).isoformat()},
                {"Key": "OriginalSecurityGroups", "Value": ",".join(current_sgs)},
            ],
        )
        findings.append({"action": "tag_instance", "status": "OK"})
    except ClientError as e:
        findings.append({"action": "tag_instance", "status": "FAIL", "detail": str(e)})

    return findings


def create_forensic_snapshot(session, instance_id):
    """Create EBS snapshots for forensic preservation."""
    ec2 = session.client("ec2")
    findings = []
    print(f"[*] Creating forensic snapshots for: {instance_id}")

    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        instance = resp["Reservations"][0]["Instances"][0]
        volumes = []
        for mapping in instance.get("BlockDeviceMappings", []):
            vol_id = mapping.get("Ebs", {}).get("VolumeId")
            if vol_id:
                volumes.append((mapping["DeviceName"], vol_id))
    except ClientError as e:
        findings.append({"action": "describe_volumes", "status": "FAIL", "detail": str(e)})
        return findings

    for device_name, vol_id in volumes:
        try:
            snap = ec2.create_snapshot(
                VolumeId=vol_id,
                Description=f"Forensic snapshot - {instance_id} {device_name} - "
                            f"{datetime.now(timezone.utc).isoformat()}",
                TagSpecifications=[{
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "Purpose", "Value": "Forensic-Preservation"},
                        {"Key": "SourceInstance", "Value": instance_id},
                        {"Key": "SourceVolume", "Value": vol_id},
                        {"Key": "CreatedBy", "Value": "incident-containment-agent"},
                    ],
                }],
            )
            findings.append({
                "action": "create_snapshot",
                "status": "OK",
                "detail": f"{vol_id} ({device_name}) -> {snap['SnapshotId']}",
            })
        except ClientError as e:
            findings.append({"action": "create_snapshot", "status": "FAIL",
                             "detail": f"{vol_id}: {e}"})

    return findings


def revoke_iam_credentials(session, username):
    """Revoke all IAM credentials for a compromised user."""
    iam = session.client("iam")
    findings = []
    print(f"[*] Revoking credentials for IAM user: {username}")

    # Deactivate access keys
    try:
        keys = iam.list_access_keys(UserName=username)
        for key in keys.get("AccessKeyMetadata", []):
            key_id = key["AccessKeyId"]
            iam.update_access_key(
                UserName=username, AccessKeyId=key_id, Status="Inactive"
            )
            findings.append({"action": "deactivate_access_key", "status": "OK",
                             "detail": f"Key {key_id[:8]}... deactivated"})
    except ClientError as e:
        findings.append({"action": "deactivate_access_keys", "status": "FAIL", "detail": str(e)})

    # Invalidate console session by attaching deny-all inline policy
    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
    })
    try:
        iam.put_user_policy(
            UserName=username,
            PolicyName="IncidentDenyAll",
            PolicyDocument=deny_policy,
        )
        findings.append({"action": "attach_deny_policy", "status": "OK",
                         "detail": "Deny-all policy attached"})
    except ClientError as e:
        findings.append({"action": "attach_deny_policy", "status": "FAIL", "detail": str(e)})

    # Delete login profile (console access)
    try:
        iam.delete_login_profile(UserName=username)
        findings.append({"action": "delete_console_access", "status": "OK"})
    except iam.exceptions.NoSuchEntityException:
        findings.append({"action": "delete_console_access", "status": "SKIP",
                         "detail": "No console access configured"})
    except ClientError as e:
        findings.append({"action": "delete_console_access", "status": "FAIL", "detail": str(e)})

    return findings


def restrict_s3_bucket(session, bucket_name):
    """Restrict S3 bucket access during incident containment."""
    s3 = session.client("s3")
    findings = []
    print(f"[*] Restricting S3 bucket: {bucket_name}")

    # Block public access
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        findings.append({"action": "block_public_access", "status": "OK"})
    except ClientError as e:
        findings.append({"action": "block_public_access", "status": "FAIL", "detail": str(e)})

    # Enable versioning (preserve evidence)
    try:
        s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"Status": "Enabled"},
        )
        findings.append({"action": "enable_versioning", "status": "OK"})
    except ClientError as e:
        findings.append({"action": "enable_versioning", "status": "FAIL", "detail": str(e)})

    return findings


def format_summary(all_actions):
    """Print containment summary."""
    print(f"\n{'='*60}")
    print("  Cloud Incident Containment Report")
    print(f"{'='*60}")

    success = sum(1 for a in all_actions if a.get("status") == "OK")
    failed = sum(1 for a in all_actions if a.get("status") == "FAIL")
    print(f"  Actions  : {len(all_actions)}")
    print(f"  Success  : {success}")
    print(f"  Failed   : {failed}")

    print("\n  Actions Taken:")
    for a in all_actions:
        icon = "OK" if a["status"] == "OK" else "!!" if a["status"] == "FAIL" else "--"
        print(f"    [{icon}] {a['action']:30s} {a.get('detail', '')[:50]}")


def main():
    parser = argparse.ArgumentParser(
        description="AWS cloud incident containment agent"
    )
    sub = parser.add_subparsers(dest="command")

    p_iso = sub.add_parser("isolate", help="Isolate EC2 instance")
    p_iso.add_argument("--instance-id", required=True)

    p_snap = sub.add_parser("snapshot", help="Create forensic snapshots")
    p_snap.add_argument("--instance-id", required=True)

    p_iam = sub.add_parser("revoke-iam", help="Revoke IAM user credentials")
    p_iam.add_argument("--username", required=True)

    p_s3 = sub.add_parser("restrict-s3", help="Restrict S3 bucket")
    p_s3.add_argument("--bucket", required=True)

    p_full = sub.add_parser("full-contain", help="Full containment: isolate + snapshot + IAM")
    p_full.add_argument("--instance-id", required=True)
    p_full.add_argument("--username", help="IAM user to revoke")
    p_full.add_argument("--bucket", help="S3 bucket to restrict")

    parser.add_argument("--profile", help="AWS CLI profile")
    parser.add_argument("--region", help="AWS region")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    session = get_session(args.profile, args.region)
    all_actions = []

    if args.command == "isolate":
        all_actions.extend(isolate_ec2_instance(session, args.instance_id))
    elif args.command == "snapshot":
        all_actions.extend(create_forensic_snapshot(session, args.instance_id))
    elif args.command == "revoke-iam":
        all_actions.extend(revoke_iam_credentials(session, args.username))
    elif args.command == "restrict-s3":
        all_actions.extend(restrict_s3_bucket(session, args.bucket))
    elif args.command == "full-contain":
        all_actions.extend(isolate_ec2_instance(session, args.instance_id))
        all_actions.extend(create_forensic_snapshot(session, args.instance_id))
        if args.username:
            all_actions.extend(revoke_iam_credentials(session, args.username))
        if args.bucket:
            all_actions.extend(restrict_s3_bucket(session, args.bucket))

    format_summary(all_actions)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "AWS Incident Containment",
        "command": args.command,
        "actions": all_actions,
        "success_count": sum(1 for a in all_actions if a["status"] == "OK"),
        "fail_count": sum(1 for a in all_actions if a["status"] == "FAIL"),
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
