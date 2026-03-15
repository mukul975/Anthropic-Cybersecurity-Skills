#!/usr/bin/env python3
"""Agent for building cloud security posture management across AWS/Azure/GCP."""

import os
import json
import argparse
from datetime import datetime

import boto3
from botocore.exceptions import ClientError


def check_s3_public_buckets(session):
    """Check for publicly accessible S3 buckets."""
    s3 = session.client("s3")
    buckets = s3.list_buckets()["Buckets"]
    findings = []
    for b in buckets:
        name = b["Name"]
        try:
            pab = s3.get_public_access_block(Bucket=name)
            config = pab["PublicAccessBlockConfiguration"]
            if not all([config.get("BlockPublicAcls"), config.get("IgnorePublicAcls"),
                        config.get("BlockPublicPolicy"), config.get("RestrictPublicBuckets")]):
                findings.append({"bucket": name, "issue": "Incomplete public access block", "severity": "HIGH"})
        except ClientError:
            findings.append({"bucket": name, "issue": "No public access block configured", "severity": "HIGH"})
    return findings


def check_unencrypted_ebs(session):
    """Check for unencrypted EBS volumes."""
    ec2 = session.client("ec2")
    volumes = ec2.describe_volumes()["Volumes"]
    unencrypted = [
        {"volume_id": v["VolumeId"], "state": v["State"], "size_gb": v["Size"]}
        for v in volumes if not v.get("Encrypted")
    ]
    return unencrypted


def check_public_security_groups(session):
    """Check for security groups allowing unrestricted inbound access."""
    ec2 = session.client("ec2")
    sgs = ec2.describe_security_groups()["SecurityGroups"]
    findings = []
    dangerous_ports = [22, 3389, 3306, 5432, 1433, 27017]
    for sg in sgs:
        for rule in sg.get("IpPermissions", []):
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 65535)
                    severity = "CRITICAL" if any(from_port <= p <= to_port for p in dangerous_ports) else "HIGH"
                    findings.append({
                        "sg_id": sg["GroupId"],
                        "sg_name": sg.get("GroupName"),
                        "port_range": f"{from_port}-{to_port}",
                        "source": "0.0.0.0/0",
                        "severity": severity,
                    })
    return findings


def check_iam_users_without_mfa(session):
    """Check for IAM users without MFA enabled."""
    iam = session.client("iam")
    users = iam.list_users()["Users"]
    no_mfa = []
    for user in users:
        mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
        if not mfa_devices:
            no_mfa.append({"username": user["UserName"], "created": str(user["CreateDate"])})
    return no_mfa


def check_rds_public_access(session):
    """Check for RDS instances with public accessibility."""
    rds = session.client("rds")
    instances = rds.describe_db_instances()["DBInstances"]
    public = [
        {"instance": db["DBInstanceIdentifier"], "engine": db["Engine"], "endpoint": db.get("Endpoint", {}).get("Address", "")}
        for db in instances if db.get("PubliclyAccessible")
    ]
    return public


def check_cloudtrail_enabled(session):
    """Check if CloudTrail is enabled with multi-region logging."""
    ct = session.client("cloudtrail")
    trails = ct.describe_trails()["trailList"]
    multiregion = [t for t in trails if t.get("IsMultiRegionTrail")]
    if not multiregion:
        return {"status": "FAIL", "detail": "No multi-region CloudTrail found"}
    return {"status": "PASS", "trails": len(multiregion)}


def calculate_posture_score(findings_summary):
    """Calculate an overall security posture score."""
    total_checks = sum(findings_summary.values())
    if total_checks == 0:
        return 100
    critical = findings_summary.get("critical", 0)
    high = findings_summary.get("high", 0)
    medium = findings_summary.get("medium", 0)
    deductions = (critical * 15) + (high * 8) + (medium * 3)
    return max(0, 100 - deductions)


def main():
    parser = argparse.ArgumentParser(description="Cloud Security Posture Management Agent")
    parser.add_argument("--profile", default=os.getenv("AWS_PROFILE"))
    parser.add_argument("--region", default=os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
    parser.add_argument("--output", default="cspm_report.json")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    account = session.client("sts").get_caller_identity()["Account"]
    print(f"[+] CSPM scan for account {account}")

    report = {"account": account, "scan_date": datetime.utcnow().isoformat(), "findings": {}}

    print("[+] Checking S3 bucket public access...")
    report["findings"]["s3_public"] = check_s3_public_buckets(session)
    print(f"    Issues: {len(report['findings']['s3_public'])}")

    print("[+] Checking unencrypted EBS volumes...")
    report["findings"]["unencrypted_ebs"] = check_unencrypted_ebs(session)
    print(f"    Unencrypted: {len(report['findings']['unencrypted_ebs'])}")

    print("[+] Checking public security groups...")
    report["findings"]["public_sgs"] = check_public_security_groups(session)
    print(f"    Open rules: {len(report['findings']['public_sgs'])}")

    print("[+] Checking IAM users without MFA...")
    report["findings"]["no_mfa_users"] = check_iam_users_without_mfa(session)
    print(f"    Without MFA: {len(report['findings']['no_mfa_users'])}")

    print("[+] Checking public RDS instances...")
    report["findings"]["public_rds"] = check_rds_public_access(session)
    print(f"    Public: {len(report['findings']['public_rds'])}")

    print("[+] Checking CloudTrail...")
    report["findings"]["cloudtrail"] = check_cloudtrail_enabled(session)

    critical = sum(1 for f in report["findings"].get("public_sgs", []) if f.get("severity") == "CRITICAL")
    high = len(report["findings"]["s3_public"]) + len(report["findings"]["no_mfa_users"])
    medium = len(report["findings"]["unencrypted_ebs"])
    report["posture_score"] = calculate_posture_score({"critical": critical, "high": high, "medium": medium})
    print(f"\n[+] Posture Score: {report['posture_score']}/100")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
