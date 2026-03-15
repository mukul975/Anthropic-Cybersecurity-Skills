#!/usr/bin/env python3
"""S3 bucket misconfiguration remediation agent using boto3."""

import json
import sys

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("Install: pip install boto3")
    sys.exit(1)


def get_s3_client(region="us-east-1"):
    return boto3.client("s3", region_name=region)


def list_all_buckets(s3):
    """List all S3 buckets in the account."""
    resp = s3.list_buckets()
    return [b["Name"] for b in resp.get("Buckets", [])]


def check_public_access_block(s3, bucket):
    """Check if S3 Block Public Access is enabled."""
    try:
        config = s3.get_public_access_block(Bucket=bucket)
        block = config["PublicAccessBlockConfiguration"]
        all_blocked = all([
            block.get("BlockPublicAcls", False),
            block.get("IgnorePublicAcls", False),
            block.get("BlockPublicPolicy", False),
            block.get("RestrictPublicBuckets", False),
        ])
        return {"bucket": bucket, "block_config": block, "fully_blocked": all_blocked}
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return {"bucket": bucket, "block_config": None, "fully_blocked": False}
        raise


def check_bucket_policy(s3, bucket):
    """Check bucket policy for public access grants."""
    try:
        policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
        findings = []
        for stmt in policy.get("Statement", []):
            principal = stmt.get("Principal", {})
            effect = stmt.get("Effect", "")
            if principal == "*" or principal == {"AWS": "*"}:
                if effect == "Allow":
                    findings.append({
                        "sid": stmt.get("Sid", "unnamed"),
                        "effect": effect,
                        "principal": str(principal),
                        "action": stmt.get("Action"),
                        "risk": "CRITICAL",
                    })
        return {"bucket": bucket, "has_policy": True, "public_statements": findings}
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return {"bucket": bucket, "has_policy": False, "public_statements": []}
        raise


def check_bucket_acl(s3, bucket):
    """Check bucket ACL for public grants."""
    acl = s3.get_bucket_acl(Bucket=bucket)
    public_grants = []
    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI", "")
        if "AllUsers" in uri or "AuthenticatedUsers" in uri:
            public_grants.append({
                "grantee": uri,
                "permission": grant.get("Permission"),
                "risk": "CRITICAL" if grant.get("Permission") in ("FULL_CONTROL", "WRITE") else "HIGH",
            })
    return {"bucket": bucket, "public_grants": public_grants}


def check_encryption(s3, bucket):
    """Check if default encryption is enabled."""
    try:
        config = s3.get_bucket_encryption(Bucket=bucket)
        rules = config.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        encryption = None
        for rule in rules:
            sse = rule.get("ApplyServerSideEncryptionByDefault", {})
            encryption = sse.get("SSEAlgorithm")
        return {"bucket": bucket, "encrypted": True, "algorithm": encryption}
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return {"bucket": bucket, "encrypted": False, "algorithm": None}
        raise


def check_versioning(s3, bucket):
    """Check if versioning is enabled."""
    resp = s3.get_bucket_versioning(Bucket=bucket)
    return {
        "bucket": bucket,
        "status": resp.get("Status", "Disabled"),
        "mfa_delete": resp.get("MFADelete", "Disabled"),
    }


def check_logging(s3, bucket):
    """Check if access logging is enabled."""
    resp = s3.get_bucket_logging(Bucket=bucket)
    logging_config = resp.get("LoggingEnabled")
    return {
        "bucket": bucket,
        "logging_enabled": logging_config is not None,
        "target_bucket": logging_config.get("TargetBucket") if logging_config else None,
    }


def enable_public_access_block(s3, bucket):
    """Enable S3 Block Public Access on a bucket."""
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    return {"bucket": bucket, "action": "block_public_access", "status": "applied"}


def enable_encryption(s3, bucket, algorithm="aws:kms"):
    """Enable default encryption on a bucket."""
    config = {
        "Rules": [{
            "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": algorithm},
            "BucketKeyEnabled": True,
        }]
    }
    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration=config,
    )
    return {"bucket": bucket, "action": "enable_encryption", "algorithm": algorithm}


def enable_versioning(s3, bucket):
    """Enable versioning on a bucket."""
    s3.put_bucket_versioning(
        Bucket=bucket,
        VersioningConfiguration={"Status": "Enabled"},
    )
    return {"bucket": bucket, "action": "enable_versioning", "status": "Enabled"}


def audit_all_buckets(s3):
    """Run full security audit across all buckets."""
    buckets = list_all_buckets(s3)
    results = []
    for bucket in buckets:
        finding = {"bucket": bucket, "issues": []}
        pab = check_public_access_block(s3, bucket)
        if not pab["fully_blocked"]:
            finding["issues"].append("Public access block not fully enabled")
        policy = check_bucket_policy(s3, bucket)
        if policy["public_statements"]:
            finding["issues"].append(f"{len(policy['public_statements'])} public policy statement(s)")
        acl = check_bucket_acl(s3, bucket)
        if acl["public_grants"]:
            finding["issues"].append(f"{len(acl['public_grants'])} public ACL grant(s)")
        enc = check_encryption(s3, bucket)
        if not enc["encrypted"]:
            finding["issues"].append("No default encryption")
        ver = check_versioning(s3, bucket)
        if ver["status"] != "Enabled":
            finding["issues"].append("Versioning disabled")
        log = check_logging(s3, bucket)
        if not log["logging_enabled"]:
            finding["issues"].append("Access logging disabled")
        finding["issue_count"] = len(finding["issues"])
        finding["risk"] = "CRITICAL" if any("public" in i.lower() for i in finding["issues"]) else (
            "HIGH" if finding["issue_count"] >= 3 else "MEDIUM" if finding["issue_count"] >= 1 else "LOW"
        )
        results.append(finding)
    return sorted(results, key=lambda x: -x["issue_count"])


def print_audit_report(results):
    print("S3 Bucket Security Audit Report")
    print("=" * 50)
    print(f"Buckets Audited: {len(results)}")
    critical = sum(1 for r in results if r["risk"] == "CRITICAL")
    print(f"Critical: {critical}")
    for r in results:
        if r["issue_count"] == 0:
            continue
        print(f"\n[{r['risk']}] {r['bucket']} ({r['issue_count']} issues)")
        for issue in r["issues"]:
            print(f"  - {issue}")


if __name__ == "__main__":
    region = sys.argv[1] if len(sys.argv) > 1 else "us-east-1"
    s3 = get_s3_client(region)
    results = audit_all_buckets(s3)
    print_audit_report(results)
