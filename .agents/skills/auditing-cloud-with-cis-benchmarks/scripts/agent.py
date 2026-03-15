#!/usr/bin/env python3
"""Agent for auditing cloud infrastructure against CIS Benchmarks using boto3."""

import os
import json
import argparse
from datetime import datetime

import boto3
from botocore.exceptions import ClientError


def check_root_access_keys(session):
    """CIS 1.4 - Ensure no root account access key exists."""
    iam = session.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    root_keys = summary.get("AccountAccessKeysPresent", 0)
    return {"control": "1.4", "description": "Root access keys", "status": "FAIL" if root_keys > 0 else "PASS", "detail": f"{root_keys} keys"}


def check_root_mfa(session):
    """CIS 1.5 - Ensure MFA is enabled for the root account."""
    iam = session.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    mfa = summary.get("AccountMFAEnabled", 0)
    return {"control": "1.5", "description": "Root MFA", "status": "PASS" if mfa else "FAIL"}


def check_password_policy(session):
    """CIS 1.8-1.11 - Ensure IAM password policy is strong."""
    iam = session.client("iam")
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        issues = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append("MinLength < 14")
        if not policy.get("RequireUppercaseCharacters"):
            issues.append("No uppercase required")
        if not policy.get("RequireLowercaseCharacters"):
            issues.append("No lowercase required")
        if not policy.get("RequireNumbers"):
            issues.append("No numbers required")
        if not policy.get("RequireSymbols"):
            issues.append("No symbols required")
        return {"control": "1.8-1.11", "description": "Password policy", "status": "FAIL" if issues else "PASS", "detail": issues}
    except ClientError:
        return {"control": "1.8", "description": "Password policy", "status": "FAIL", "detail": "No policy set"}


def check_cloudtrail_multiregion(session):
    """CIS 3.1 - Ensure CloudTrail is enabled in all regions."""
    ct = session.client("cloudtrail")
    trails = ct.describe_trails()["trailList"]
    multiregion = [t for t in trails if t.get("IsMultiRegionTrail")]
    return {"control": "3.1", "description": "CloudTrail multi-region", "status": "PASS" if multiregion else "FAIL", "detail": f"{len(multiregion)} multi-region trails"}


def check_cloudtrail_log_validation(session):
    """CIS 3.2 - Ensure CloudTrail log file validation is enabled."""
    ct = session.client("cloudtrail")
    trails = ct.describe_trails()["trailList"]
    no_validation = [t["Name"] for t in trails if not t.get("LogFileValidationEnabled")]
    return {"control": "3.2", "description": "Log file validation", "status": "FAIL" if no_validation else "PASS", "detail": no_validation}


def check_s3_encryption(session):
    """CIS 2.1.1 - Ensure S3 default encryption is enabled."""
    s3 = session.client("s3")
    buckets = s3.list_buckets()["Buckets"]
    unencrypted = []
    for b in buckets:
        try:
            s3.get_bucket_encryption(Bucket=b["Name"])
        except ClientError:
            unencrypted.append(b["Name"])
    return {"control": "2.1.1", "description": "S3 default encryption", "status": "FAIL" if unencrypted else "PASS", "detail": unencrypted}


def check_vpc_flow_logs(session):
    """CIS 5.1 - Ensure VPC flow logging is enabled."""
    ec2 = session.client("ec2")
    vpcs = ec2.describe_vpcs()["Vpcs"]
    flow_logs = ec2.describe_flow_logs()["FlowLogs"]
    logged_vpcs = {fl["ResourceId"] for fl in flow_logs}
    missing = [v["VpcId"] for v in vpcs if v["VpcId"] not in logged_vpcs]
    return {"control": "5.1", "description": "VPC flow logs", "status": "FAIL" if missing else "PASS", "detail": missing}


def check_default_sg_restrictions(session):
    """CIS 5.4 - Ensure default security group restricts all traffic."""
    ec2 = session.client("ec2")
    sgs = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": ["default"]}])["SecurityGroups"]
    open_default = []
    for sg in sgs:
        if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        open_default.append(sg["GroupId"])
    return {"control": "5.4", "description": "Default SG restrictions", "status": "FAIL" if open_default else "PASS", "detail": open_default}


def run_full_audit(session):
    """Execute all CIS benchmark checks."""
    checks = [
        check_root_access_keys, check_root_mfa, check_password_policy,
        check_cloudtrail_multiregion, check_cloudtrail_log_validation,
        check_s3_encryption, check_vpc_flow_logs, check_default_sg_restrictions,
    ]
    results = []
    for check_fn in checks:
        result = check_fn(session)
        results.append(result)
        status_icon = "PASS" if result["status"] == "PASS" else "FAIL"
        print(f"  [{status_icon}] {result['control']}: {result['description']}")
    return results


def main():
    parser = argparse.ArgumentParser(description="CIS Benchmark Cloud Audit Agent")
    parser.add_argument("--profile", default=os.getenv("AWS_PROFILE"))
    parser.add_argument("--region", default=os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
    parser.add_argument("--output", default="cis_audit_report.json")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    account = session.client("sts").get_caller_identity()["Account"]
    print(f"[+] CIS Benchmark Audit for account {account}")

    results = run_full_audit(session)
    passed = sum(1 for r in results if r["status"] == "PASS")
    total = len(results)
    score = int(passed / total * 100) if total else 0

    report = {
        "account": account,
        "benchmark": "CIS AWS Foundations v5.0",
        "audit_date": datetime.utcnow().isoformat(),
        "compliance_score": f"{score}%",
        "passed": passed,
        "failed": total - passed,
        "checks": results,
    }
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[+] Score: {score}% ({passed}/{total} passed)")
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
