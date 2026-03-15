#!/usr/bin/env python3
"""Agent for auditing AWS S3 bucket permissions using boto3."""

import os
import json
import argparse
from datetime import datetime

import boto3
from botocore.exceptions import ClientError


def get_session(profile=None, region=None):
    """Create a boto3 session."""
    kwargs = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return boto3.Session(**kwargs)


def list_all_buckets(session):
    """List all S3 buckets in the account."""
    s3 = session.client("s3")
    response = s3.list_buckets()
    buckets = []
    for b in response.get("Buckets", []):
        loc = s3.get_bucket_location(Bucket=b["Name"])
        region = loc.get("LocationConstraint") or "us-east-1"
        buckets.append({"name": b["Name"], "created": str(b["CreationDate"]), "region": region})
    return buckets


def check_public_access_block(session, bucket_name):
    """Check bucket-level public access block settings."""
    s3 = session.client("s3")
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]
        return {
            "configured": True,
            "block_public_acls": config.get("BlockPublicAcls", False),
            "ignore_public_acls": config.get("IgnorePublicAcls", False),
            "block_public_policy": config.get("BlockPublicPolicy", False),
            "restrict_public_buckets": config.get("RestrictPublicBuckets", False),
        }
    except ClientError:
        return {"configured": False}


def check_bucket_acl(session, bucket_name):
    """Check bucket ACL for public grants."""
    s3 = session.client("s3")
    acl = s3.get_bucket_acl(Bucket=bucket_name)
    public_grants = []
    public_uris = [
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    ]
    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        if grantee.get("URI") in public_uris:
            public_grants.append({
                "grantee": grantee.get("URI"),
                "permission": grant.get("Permission"),
            })
    return public_grants


def check_bucket_policy(session, bucket_name):
    """Check bucket policy for wildcard principals."""
    s3 = session.client("s3")
    try:
        policy_str = s3.get_bucket_policy(Bucket=bucket_name)["Policy"]
        policy = json.loads(policy_str)
        issues = []
        for stmt in policy.get("Statement", []):
            principal = stmt.get("Principal", {})
            if principal == "*" or principal == {"AWS": "*"}:
                issues.append({
                    "effect": stmt.get("Effect"),
                    "action": stmt.get("Action"),
                    "condition": stmt.get("Condition", "NONE"),
                })
        return {"has_policy": True, "wildcard_issues": issues}
    except ClientError:
        return {"has_policy": False, "wildcard_issues": []}


def check_encryption(session, bucket_name):
    """Check if default encryption is enabled."""
    s3 = session.client("s3")
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if rules:
            algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
            return {"enabled": True, "algorithm": algo}
    except ClientError:
        pass
    return {"enabled": False, "algorithm": None}


def check_versioning(session, bucket_name):
    """Check if versioning is enabled."""
    s3 = session.client("s3")
    resp = s3.get_bucket_versioning(Bucket=bucket_name)
    return {"status": resp.get("Status", "Disabled")}


def check_logging(session, bucket_name):
    """Check if server access logging is enabled."""
    s3 = session.client("s3")
    resp = s3.get_bucket_logging(Bucket=bucket_name)
    enabled = "LoggingEnabled" in resp
    return {"enabled": enabled}


def audit_bucket(session, bucket_name):
    """Run full security audit on a single bucket."""
    return {
        "bucket": bucket_name,
        "public_access_block": check_public_access_block(session, bucket_name),
        "public_acl_grants": check_bucket_acl(session, bucket_name),
        "bucket_policy": check_bucket_policy(session, bucket_name),
        "encryption": check_encryption(session, bucket_name),
        "versioning": check_versioning(session, bucket_name),
        "logging": check_logging(session, bucket_name),
    }


def classify_risk(audit_result):
    """Classify risk level for a bucket based on audit findings."""
    risk = "LOW"
    if audit_result["public_acl_grants"]:
        risk = "CRITICAL"
    elif audit_result["bucket_policy"]["wildcard_issues"]:
        risk = "HIGH"
    elif not audit_result["encryption"]["enabled"]:
        risk = "MEDIUM"
    elif not audit_result["public_access_block"]["configured"]:
        risk = "MEDIUM"
    audit_result["risk_level"] = risk
    return audit_result


def main():
    parser = argparse.ArgumentParser(description="AWS S3 Bucket Permissions Audit Agent")
    parser.add_argument("--profile", default=os.getenv("AWS_PROFILE"))
    parser.add_argument("--region", default=os.getenv("AWS_DEFAULT_REGION"))
    parser.add_argument("--bucket", help="Audit a specific bucket")
    parser.add_argument("--output", default="s3_audit_report.json")
    args = parser.parse_args()

    session = get_session(args.profile, args.region)
    account_id = session.client("sts").get_caller_identity()["Account"]
    print(f"[+] Auditing S3 buckets in account {account_id}")

    if args.bucket:
        buckets = [{"name": args.bucket}]
    else:
        buckets = list_all_buckets(session)
    print(f"[+] Found {len(buckets)} buckets")

    results = []
    for b in buckets:
        name = b["name"]
        print(f"  Auditing {name}...")
        audit = audit_bucket(session, name)
        audit = classify_risk(audit)
        results.append(audit)
        if audit["risk_level"] in ("CRITICAL", "HIGH"):
            print(f"    [{audit['risk_level']}] {name}")

    report = {
        "account": account_id,
        "audit_date": datetime.utcnow().isoformat(),
        "total_buckets": len(results),
        "critical": sum(1 for r in results if r["risk_level"] == "CRITICAL"),
        "high": sum(1 for r in results if r["risk_level"] == "HIGH"),
        "buckets": results,
    }
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
