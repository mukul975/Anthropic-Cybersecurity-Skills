#!/usr/bin/env python3
"""Cloud infrastructure penetration testing agent using boto3 and ScoutSuite."""

import json
import sys
import argparse
import subprocess
from datetime import datetime

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("Install: pip install boto3")
    sys.exit(1)


def enumerate_public_resources(session):
    """Find publicly accessible resources across AWS services."""
    findings = []
    ec2 = session.client("ec2")
    for sg in ec2.describe_security_groups()["SecurityGroups"]:
        for perm in sg.get("IpPermissions", []):
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    findings.append({
                        "type": "open_security_group",
                        "resource": sg["GroupId"],
                        "port": perm.get("FromPort", "all"),
                        "severity": "HIGH",
                    })
    s3 = session.client("s3")
    for bucket in s3.list_buckets().get("Buckets", []):
        try:
            acl = s3.get_bucket_acl(Bucket=bucket["Name"])
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI", "").endswith("AllUsers"):
                    findings.append({
                        "type": "public_s3_bucket",
                        "resource": bucket["Name"],
                        "permission": grant["Permission"],
                        "severity": "CRITICAL",
                    })
        except ClientError:
            pass
    return findings


def check_iam_weaknesses(session):
    """Audit IAM for privilege escalation paths."""
    iam = session.client("iam")
    issues = []
    for user in iam.list_users()["Users"]:
        policies = iam.list_attached_user_policies(UserName=user["UserName"])
        for pol in policies["AttachedPolicies"]:
            if pol["PolicyArn"].endswith("/AdministratorAccess"):
                issues.append({
                    "type": "admin_user",
                    "user": user["UserName"],
                    "policy": pol["PolicyName"],
                    "severity": "HIGH",
                })
        keys = iam.list_access_keys(UserName=user["UserName"])
        for key in keys["AccessKeyMetadata"]:
            if key["Status"] == "Active":
                age = (datetime.utcnow() - key["CreateDate"].replace(tzinfo=None)).days
                if age > 90:
                    issues.append({
                        "type": "stale_access_key",
                        "user": user["UserName"],
                        "key_id": key["AccessKeyId"],
                        "age_days": age,
                        "severity": "MEDIUM",
                    })
    return issues


def check_metadata_service(session):
    """Check EC2 instances for IMDSv1 (SSRF-exploitable metadata)."""
    ec2 = session.client("ec2")
    vulnerable = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                md = inst.get("MetadataOptions", {})
                if md.get("HttpTokens") != "required":
                    vulnerable.append({
                        "type": "imdsv1_enabled",
                        "instance_id": inst["InstanceId"],
                        "state": inst["State"]["Name"],
                        "severity": "HIGH",
                    })
    return vulnerable


def run_scoutsuite_scan(provider="aws"):
    """Run ScoutSuite for comprehensive cloud audit."""
    cmd = ["scout", provider, "--no-browser", "--report-dir", "/tmp/scoutsuite-report"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return {"status": "completed", "output": result.stdout[-500:]}
    except FileNotFoundError:
        return {"status": "error", "message": "ScoutSuite not installed: pip install scoutsuite"}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "message": "ScoutSuite scan exceeded 10 minute timeout"}


def run_pentest(profile=None, region="us-east-1"):
    """Execute cloud infrastructure penetration test."""
    session = boto3.Session(profile_name=profile, region_name=region)
    print(f"\n{'='*60}")
    print(f"  CLOUD INFRASTRUCTURE PENETRATION TEST")
    print(f"  Region: {region} | Profile: {profile or 'default'}")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    public = enumerate_public_resources(session)
    print(f"--- PUBLIC EXPOSURE ({len(public)} findings) ---")
    for f in public[:10]:
        print(f"  [{f['severity']}] {f['type']}: {f['resource']}")

    iam_issues = check_iam_weaknesses(session)
    print(f"\n--- IAM WEAKNESSES ({len(iam_issues)} findings) ---")
    for f in iam_issues[:10]:
        print(f"  [{f['severity']}] {f['type']}: {f.get('user', f.get('resource', 'N/A'))}")

    metadata = check_metadata_service(session)
    print(f"\n--- IMDSv1 EXPOSURE ({len(metadata)} instances) ---")
    for f in metadata[:10]:
        print(f"  [{f['severity']}] {f['instance_id']} ({f['state']})")

    return {"public_exposure": public, "iam_issues": iam_issues, "imdsv1": metadata}


def main():
    parser = argparse.ArgumentParser(description="Cloud Infrastructure Pentest Agent")
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--scan", action="store_true", help="Run full pentest scan")
    parser.add_argument("--scoutsuite", action="store_true", help="Run ScoutSuite audit")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    if args.scoutsuite:
        report = run_scoutsuite_scan()
        print(json.dumps(report, indent=2))
    elif args.scan:
        report = run_pentest(args.profile, args.region)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n[+] Report saved to {args.output}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
