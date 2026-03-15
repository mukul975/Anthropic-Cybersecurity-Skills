#!/usr/bin/env python3
"""Zero trust cloud architecture assessment agent using AWS, Azure, and GCP SDKs."""

import json
import sys
import argparse
from datetime import datetime

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.authorization import AuthorizationManagementClient
    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False

try:
    from google.cloud import compute_v1
    HAS_GCP = True
except ImportError:
    HAS_GCP = False


ZERO_TRUST_PILLARS = [
    {"pillar": "Identity", "description": "Verify every identity with strong auth",
     "checks": ["MFA enforcement", "Conditional access policies", "Least privilege RBAC",
                 "Service account key rotation", "Passwordless authentication"]},
    {"pillar": "Device", "description": "Validate device posture before granting access",
     "checks": ["Device compliance policies", "MDM enrollment required",
                 "Certificate-based device identity", "OS patch level enforcement"]},
    {"pillar": "Network", "description": "Micro-segment and encrypt all communications",
     "checks": ["VPC/VNet segmentation", "Private endpoints for services",
                 "No public IPs on internal workloads", "TLS everywhere",
                 "Identity-Aware Proxy deployment"]},
    {"pillar": "Application", "description": "Secure app access without network trust",
     "checks": ["OAuth2/OIDC authentication", "API gateway with auth",
                 "No VPN-dependent access", "Runtime application self-protection"]},
    {"pillar": "Data", "description": "Classify and protect data at all states",
     "checks": ["Encryption at rest", "Encryption in transit",
                 "Data classification labels", "DLP policies active"]},
    {"pillar": "Visibility", "description": "Continuous monitoring and analytics",
     "checks": ["Centralized logging", "SIEM integration",
                 "User behavior analytics", "Real-time alerting"]},
]


def assess_aws_zero_trust(region="us-east-1"):
    """Assess AWS zero trust posture."""
    if boto3 is None:
        return {"error": "boto3 not installed"}
    findings = []

    iam = boto3.client("iam", region_name=region)
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 0:
            findings.append({"pillar": "Identity", "check": "Root MFA",
                             "status": "FAIL", "severity": "CRITICAL",
                             "detail": "Root account MFA not enabled"})
        else:
            findings.append({"pillar": "Identity", "check": "Root MFA",
                             "status": "PASS", "detail": "Root MFA enabled"})
        users = iam.list_users()["Users"]
        for user in users[:20]:
            mfa = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
            if not mfa:
                findings.append({"pillar": "Identity", "check": "User MFA",
                                 "status": "FAIL", "severity": "HIGH",
                                 "detail": f"User {user['UserName']} has no MFA"})
    except ClientError as e:
        findings.append({"pillar": "Identity", "check": "IAM", "status": "ERROR", "detail": str(e)})

    ec2 = boto3.client("ec2", region_name=region)
    try:
        instances = ec2.describe_instances()
        for reservation in instances.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                if inst.get("PublicIpAddress"):
                    findings.append({"pillar": "Network", "check": "Public IP",
                                     "status": "FAIL", "severity": "MEDIUM",
                                     "detail": f"Instance {inst['InstanceId']} has public IP "
                                               f"{inst['PublicIpAddress']}"})
    except ClientError as e:
        findings.append({"pillar": "Network", "status": "ERROR", "detail": str(e)})

    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        for sg in sgs:
            for rule in sg.get("IpPermissions", []):
                for ip in rule.get("IpRanges", []):
                    if ip.get("CidrIp") == "0.0.0.0/0":
                        port = rule.get("FromPort", "all")
                        findings.append({"pillar": "Network", "check": "Security Group",
                                         "status": "FAIL", "severity": "HIGH",
                                         "detail": f"SG {sg['GroupId']} port {port} open to 0.0.0.0/0"})
    except ClientError as e:
        findings.append({"pillar": "Network", "status": "ERROR", "detail": str(e)})

    s3 = boto3.client("s3", region_name=region)
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets[:20]:
            try:
                enc = s3.get_bucket_encryption(Bucket=bucket["Name"])
                findings.append({"pillar": "Data", "check": "S3 Encryption",
                                 "status": "PASS", "detail": f"{bucket['Name']} encrypted"})
            except ClientError:
                findings.append({"pillar": "Data", "check": "S3 Encryption",
                                 "status": "FAIL", "severity": "HIGH",
                                 "detail": f"Bucket {bucket['Name']} has no default encryption"})
    except ClientError as e:
        findings.append({"pillar": "Data", "status": "ERROR", "detail": str(e)})

    ct = boto3.client("cloudtrail", region_name=region)
    try:
        trails = ct.describe_trails()["trailList"]
        if trails:
            findings.append({"pillar": "Visibility", "check": "CloudTrail",
                             "status": "PASS", "detail": f"{len(trails)} trail(s) configured"})
        else:
            findings.append({"pillar": "Visibility", "check": "CloudTrail",
                             "status": "FAIL", "severity": "CRITICAL",
                             "detail": "No CloudTrail trails configured"})
    except ClientError as e:
        findings.append({"pillar": "Visibility", "status": "ERROR", "detail": str(e)})

    return findings


def generate_zero_trust_scorecard(findings):
    """Generate a zero trust maturity scorecard from findings."""
    pillar_scores = {}
    for f in findings:
        pillar = f.get("pillar", "Unknown")
        if pillar not in pillar_scores:
            pillar_scores[pillar] = {"pass": 0, "fail": 0, "error": 0}
        status = f.get("status", "ERROR")
        if status == "PASS":
            pillar_scores[pillar]["pass"] += 1
        elif status == "FAIL":
            pillar_scores[pillar]["fail"] += 1
        else:
            pillar_scores[pillar]["error"] += 1

    scorecard = {}
    for pillar, counts in pillar_scores.items():
        total = counts["pass"] + counts["fail"]
        score = round(counts["pass"] / max(total, 1) * 100, 1)
        maturity = "Advanced" if score >= 80 else "Initial" if score >= 50 else "Traditional"
        scorecard[pillar] = {"score": score, "maturity": maturity,
                             "passed": counts["pass"], "failed": counts["fail"]}
    return scorecard


def run_zero_trust_assessment(region="us-east-1"):
    """Run comprehensive zero trust assessment."""
    print(f"\n{'='*60}")
    print(f"  ZERO TRUST CLOUD ARCHITECTURE ASSESSMENT")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    print(f"--- ZERO TRUST PILLARS ---")
    for p in ZERO_TRUST_PILLARS:
        print(f"  {p['pillar']}: {p['description']}")
        for c in p["checks"]:
            print(f"    - {c}")

    print(f"\n--- AWS ASSESSMENT (region: {region}) ---")
    findings = assess_aws_zero_trust(region)

    pass_count = sum(1 for f in findings if f.get("status") == "PASS")
    fail_count = sum(1 for f in findings if f.get("status") == "FAIL")
    print(f"  Total checks: {len(findings)}")
    print(f"  Passed: {pass_count} | Failed: {fail_count}")

    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    high = [f for f in findings if f.get("severity") == "HIGH"]
    if critical:
        print(f"\n  CRITICAL FINDINGS ({len(critical)}):")
        for f in critical:
            print(f"    [{f['pillar']}] {f.get('check', 'N/A')}: {f['detail']}")
    if high:
        print(f"\n  HIGH FINDINGS ({len(high)}):")
        for f in high[:10]:
            print(f"    [{f['pillar']}] {f.get('check', 'N/A')}: {f['detail']}")

    scorecard = generate_zero_trust_scorecard(findings)
    print(f"\n--- ZERO TRUST SCORECARD ---")
    for pillar, scores in scorecard.items():
        bar = "#" * int(scores["score"] / 5)
        print(f"  {pillar:<15} {scores['score']:>5.1f}% [{scores['maturity']}] {bar}")

    overall = round(sum(s["score"] for s in scorecard.values()) / max(len(scorecard), 1), 1)
    print(f"\n  OVERALL ZERO TRUST MATURITY: {overall}%")
    maturity = "Advanced" if overall >= 80 else "Initial" if overall >= 50 else "Traditional"
    print(f"  Maturity Level: {maturity}")

    print(f"\n{'='*60}\n")
    return {"findings": findings, "scorecard": scorecard, "overall_score": overall}


def main():
    parser = argparse.ArgumentParser(description="Zero Trust Cloud Architecture Agent")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--assess", action="store_true", help="Run zero trust assessment")
    parser.add_argument("--pillars", action="store_true", help="Show zero trust pillars")
    parser.add_argument("--output", help="Save report to JSON")
    args = parser.parse_args()

    if args.pillars:
        for p in ZERO_TRUST_PILLARS:
            print(f"\n{p['pillar']}: {p['description']}")
            for c in p["checks"]:
                print(f"  - {c}")
    elif args.assess:
        report = run_zero_trust_assessment(args.region)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"[+] Report saved to {args.output}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
