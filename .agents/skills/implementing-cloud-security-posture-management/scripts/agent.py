#!/usr/bin/env python3
"""Cloud Security Posture Management (CSPM) agent across AWS, Azure, and GCP."""

import json
import sys
import argparse
import subprocess
from datetime import datetime
from collections import Counter

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None


def run_prowler_scan(provider="aws", compliance="cis_level1", output_format="json"):
    """Run Prowler CSPM scan against a cloud provider."""
    cmd = ["prowler", provider, "--compliance", compliance,
           "-M", output_format, "--output-directory", "/tmp/prowler-output"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return {"status": "completed", "returncode": result.returncode,
                "output_dir": "/tmp/prowler-output"}
    except FileNotFoundError:
        return {"error": "Prowler not installed. Run: pip install prowler"}
    except subprocess.TimeoutExpired:
        return {"error": "Prowler scan timed out after 10 minutes"}


def check_aws_security_posture(region="us-east-1"):
    """Run basic AWS security posture checks using boto3."""
    if boto3 is None:
        return {"error": "boto3 not installed"}
    findings = []

    s3 = boto3.client("s3", region_name=region)
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            try:
                pab = s3.get_public_access_block(Bucket=name)
                config = pab["PublicAccessBlockConfiguration"]
                if not all([config["BlockPublicAcls"], config["BlockPublicPolicy"],
                            config["IgnorePublicAcls"], config["RestrictPublicBuckets"]]):
                    findings.append({"check": "S3_PUBLIC_ACCESS", "resource": name,
                                     "severity": "HIGH", "status": "FAIL",
                                     "detail": "Public access block not fully enabled"})
            except ClientError:
                findings.append({"check": "S3_PUBLIC_ACCESS", "resource": name,
                                 "severity": "HIGH", "status": "FAIL",
                                 "detail": "No public access block configured"})
            try:
                s3.get_bucket_encryption(Bucket=name)
            except ClientError:
                findings.append({"check": "S3_ENCRYPTION", "resource": name,
                                 "severity": "MEDIUM", "status": "FAIL",
                                 "detail": "Default encryption not enabled"})
    except ClientError as e:
        findings.append({"check": "S3_ACCESS", "status": "ERROR", "detail": str(e)})

    iam = boto3.client("iam", region_name=region)
    try:
        acct_summary = iam.get_account_summary()["SummaryMap"]
        if acct_summary.get("AccountMFAEnabled", 0) == 0:
            findings.append({"check": "ROOT_MFA", "resource": "root-account",
                             "severity": "CRITICAL", "status": "FAIL",
                             "detail": "Root account MFA not enabled"})
        users = iam.list_users()["Users"]
        for user in users:
            keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
            for key in keys:
                age = (datetime.utcnow() - key["CreateDate"].replace(tzinfo=None)).days
                if age > 90:
                    findings.append({"check": "IAM_KEY_ROTATION", "resource": user["UserName"],
                                     "severity": "MEDIUM", "status": "FAIL",
                                     "detail": f"Access key {key['AccessKeyId']} is {age} days old"})
    except ClientError as e:
        findings.append({"check": "IAM_ACCESS", "status": "ERROR", "detail": str(e)})

    ec2 = boto3.client("ec2", region_name=region)
    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        for sg in sgs:
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        port = rule.get("FromPort", "all")
                        if port in [22, 3389, 0, -1]:
                            findings.append({"check": "SG_OPEN_PORTS", "resource": sg["GroupId"],
                                             "severity": "HIGH", "status": "FAIL",
                                             "detail": f"Port {port} open to 0.0.0.0/0"})
    except ClientError as e:
        findings.append({"check": "EC2_ACCESS", "status": "ERROR", "detail": str(e)})

    ct = boto3.client("cloudtrail", region_name=region)
    try:
        trails = ct.describe_trails()["trailList"]
        if not trails:
            findings.append({"check": "CLOUDTRAIL_ENABLED", "resource": "account",
                             "severity": "CRITICAL", "status": "FAIL",
                             "detail": "No CloudTrail trails configured"})
        for trail in trails:
            status = ct.get_trail_status(Name=trail["TrailARN"])
            if not status.get("IsLogging"):
                findings.append({"check": "CLOUDTRAIL_LOGGING", "resource": trail["Name"],
                                 "severity": "CRITICAL", "status": "FAIL",
                                 "detail": "CloudTrail is not actively logging"})
    except ClientError as e:
        findings.append({"check": "CLOUDTRAIL_ACCESS", "status": "ERROR", "detail": str(e)})

    return findings


def generate_posture_report(findings):
    """Generate a CSPM posture report from findings."""
    severity_counts = Counter(f["severity"] for f in findings if f.get("severity"))
    check_counts = Counter(f["check"] for f in findings)
    fail_count = sum(1 for f in findings if f.get("status") == "FAIL")
    pass_rate = round((1 - fail_count / max(len(findings), 1)) * 100, 1)

    print(f"\n{'='*60}")
    print(f"  CSPM POSTURE REPORT")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    print(f"--- SUMMARY ---")
    print(f"  Total Checks: {len(findings)}")
    print(f"  Failed: {fail_count}")
    print(f"  Pass Rate: {pass_rate}%\n")

    print(f"--- BY SEVERITY ---")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(sev, 0)
        bar = "#" * count
        print(f"  {sev:<10} {count:>3} {bar}")

    print(f"\n--- FAILED CHECKS ---")
    for f in findings:
        if f.get("status") == "FAIL":
            print(f"  [{f['severity']}] {f['check']}: {f.get('resource', 'N/A')}")
            print(f"    {f.get('detail', '')}")

    print(f"\n{'='*60}\n")
    return {"total": len(findings), "failed": fail_count, "pass_rate": pass_rate,
            "by_severity": dict(severity_counts)}


def main():
    parser = argparse.ArgumentParser(description="CSPM Agent")
    parser.add_argument("--provider", default="aws", choices=["aws", "azure", "gcp"])
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--prowler", action="store_true", help="Run Prowler scan")
    parser.add_argument("--scan", action="store_true", help="Run built-in posture scan")
    parser.add_argument("--output", help="Save report to JSON")
    args = parser.parse_args()

    if args.prowler:
        result = run_prowler_scan(args.provider)
        print(json.dumps(result, indent=2))
    elif args.scan:
        findings = check_aws_security_posture(args.region)
        report = generate_posture_report(findings)
        if args.output:
            with open(args.output, "w") as f:
                json.dump({"findings": findings, "summary": report}, f, indent=2, default=str)
            print(f"[+] Report saved to {args.output}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
