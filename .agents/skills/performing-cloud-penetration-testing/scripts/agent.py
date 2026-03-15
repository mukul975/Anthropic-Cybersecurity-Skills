#!/usr/bin/env python3
"""
Cloud Penetration Testing Agent — AUTHORIZED TESTING ONLY
Performs authorized cloud infrastructure security assessment across AWS
by enumerating IAM, S3, EC2, and Lambda for misconfigurations.

WARNING: Only use with explicit written authorization on approved accounts.
"""

import json
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError


def enumerate_s3_buckets() -> list[dict]:
    """Enumerate S3 buckets and check for public access misconfigurations."""
    s3 = boto3.client("s3")
    findings = []

    try:
        buckets = s3.list_buckets()["Buckets"]
    except ClientError as e:
        return [{"error": str(e)}]

    for bucket in buckets:
        name = bucket["Name"]
        finding = {"bucket": name, "issues": []}

        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") in (
                    "http://acs.amazonaws.com/groups/global/AllUsers",
                    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                ):
                    finding["issues"].append({
                        "type": "PUBLIC_ACL",
                        "severity": "HIGH",
                        "detail": f"Bucket grants {grant['Permission']} to {grantee['URI']}",
                    })
        except ClientError:
            pass

        try:
            policy = s3.get_bucket_policy(Bucket=name)
            policy_doc = json.loads(policy["Policy"])
            for stmt in policy_doc.get("Statement", []):
                if stmt.get("Effect") == "Allow" and stmt.get("Principal") in ("*", {"AWS": "*"}):
                    finding["issues"].append({
                        "type": "PUBLIC_POLICY",
                        "severity": "HIGH",
                        "detail": f"Policy allows public access: {stmt.get('Action')}",
                    })
        except ClientError:
            pass

        try:
            encryption = s3.get_bucket_encryption(Bucket=name)
        except ClientError:
            finding["issues"].append({
                "type": "NO_ENCRYPTION",
                "severity": "MEDIUM",
                "detail": "Bucket does not have default encryption enabled",
            })

        findings.append(finding)

    return findings


def enumerate_security_groups(region: str = "us-east-1") -> list[dict]:
    """Enumerate EC2 security groups for overly permissive rules."""
    ec2 = boto3.client("ec2", region_name=region)
    findings = []

    sgs = ec2.describe_security_groups()["SecurityGroups"]
    for sg in sgs:
        sg_issues = []
        for perm in sg.get("IpPermissions", []):
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    port = perm.get("FromPort", "all")
                    proto = perm.get("IpProtocol", "all")
                    severity = "CRITICAL" if port in (22, 3389, 3306, 5432) else "HIGH"
                    sg_issues.append({
                        "type": "OPEN_INGRESS",
                        "severity": severity,
                        "detail": f"Port {port}/{proto} open to 0.0.0.0/0",
                    })

        if sg_issues:
            findings.append({
                "sg_id": sg["GroupId"],
                "sg_name": sg.get("GroupName", ""),
                "vpc_id": sg.get("VpcId", ""),
                "issues": sg_issues,
            })

    return findings


def enumerate_lambda_functions(region: str = "us-east-1") -> list[dict]:
    """Enumerate Lambda functions for security misconfigurations."""
    lam = boto3.client("lambda", region_name=region)
    findings = []

    try:
        functions = lam.list_functions()["Functions"]
    except ClientError as e:
        return [{"error": str(e)}]

    for func in functions:
        func_finding = {"function_name": func["FunctionName"], "issues": []}

        env_vars = func.get("Environment", {}).get("Variables", {})
        sensitive_patterns = ["password", "secret", "key", "token", "api_key"]
        for var_name in env_vars:
            if any(p in var_name.lower() for p in sensitive_patterns):
                func_finding["issues"].append({
                    "type": "SENSITIVE_ENV_VAR",
                    "severity": "HIGH",
                    "detail": f"Potentially sensitive env var: {var_name}",
                })

        if not func.get("VpcConfig", {}).get("VpcId"):
            func_finding["issues"].append({
                "type": "NO_VPC",
                "severity": "LOW",
                "detail": "Function not in VPC - has internet access",
            })

        if func_finding["issues"]:
            findings.append(func_finding)

    return findings


def check_imds_v1(region: str = "us-east-1") -> list[dict]:
    """Check EC2 instances for IMDSv1 (vulnerable to SSRF attacks)."""
    ec2 = boto3.client("ec2", region_name=region)
    findings = []

    instances = ec2.describe_instances()
    for reservation in instances["Reservations"]:
        for inst in reservation["Instances"]:
            metadata_options = inst.get("MetadataOptions", {})
            if metadata_options.get("HttpTokens") != "required":
                findings.append({
                    "instance_id": inst["InstanceId"],
                    "state": inst["State"]["Name"],
                    "severity": "HIGH",
                    "detail": "IMDSv1 enabled - vulnerable to SSRF credential theft",
                })

    return findings


def generate_report(s3: list, sgs: list, lambdas: list, imds: list) -> str:
    """Generate cloud penetration testing report."""
    total_issues = (
        sum(len(b.get("issues", [])) for b in s3) +
        sum(len(s.get("issues", [])) for s in sgs) +
        sum(len(l.get("issues", [])) for l in lambdas) +
        len(imds)
    )

    lines = [
        "CLOUD PENETRATION TESTING REPORT — AUTHORIZED TESTING ONLY",
        "=" * 60,
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Total Findings: {total_issues}",
        "",
        f"S3 BUCKETS ({len(s3)} scanned):",
    ]
    for b in s3:
        if b.get("issues"):
            for issue in b["issues"]:
                lines.append(f"  [{issue['severity']}] {b['bucket']}: {issue['detail']}")

    lines.append(f"\nSECURITY GROUPS ({len(sgs)} with issues):")
    for sg in sgs:
        for issue in sg["issues"]:
            lines.append(f"  [{issue['severity']}] {sg['sg_id']}: {issue['detail']}")

    lines.append(f"\nLAMBDA FUNCTIONS ({len(lambdas)} with issues):")
    for l in lambdas:
        for issue in l["issues"]:
            lines.append(f"  [{issue['severity']}] {l['function_name']}: {issue['detail']}")

    lines.append(f"\nIMDSv1 INSTANCES ({len(imds)} vulnerable):")
    for i in imds:
        lines.append(f"  [{i['severity']}] {i['instance_id']}: {i['detail']}")

    return "\n".join(lines)


if __name__ == "__main__":
    print("[!] CLOUD PENETRATION TESTING — AUTHORIZED TESTING ONLY\n")
    region = sys.argv[1] if len(sys.argv) > 1 else "us-east-1"

    print("[*] Enumerating S3 buckets...")
    s3_findings = enumerate_s3_buckets()

    print("[*] Enumerating security groups...")
    sg_findings = enumerate_security_groups(region)

    print("[*] Enumerating Lambda functions...")
    lambda_findings = enumerate_lambda_functions(region)

    print("[*] Checking IMDSv1 exposure...")
    imds_findings = check_imds_v1(region)

    report = generate_report(s3_findings, sg_findings, lambda_findings, imds_findings)
    print(report)

    output = f"cloud_pentest_{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
    with open(output, "w") as f:
        json.dump({"s3": s3_findings, "security_groups": sg_findings,
                    "lambda": lambda_findings, "imds": imds_findings}, f, indent=2)
    print(f"\n[*] Results saved to {output}")
