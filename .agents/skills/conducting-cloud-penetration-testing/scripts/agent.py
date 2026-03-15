#!/usr/bin/env python3
# For authorized penetration testing and lab environments only
"""Cloud Penetration Testing Agent - Enumerates and tests AWS IAM misconfigurations."""

import json
import logging
import argparse
import subprocess
from datetime import datetime

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def enumerate_iam_users():
    """Enumerate all IAM users in the AWS account."""
    cmd = ["aws", "iam", "list-users", "--output", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        users = json.loads(result.stdout).get("Users", [])
        logger.info("Enumerated %d IAM users", len(users))
        return [{"username": u["UserName"], "arn": u["Arn"], "created": u["CreateDate"]} for u in users]
    return []


def enumerate_iam_roles():
    """Enumerate IAM roles and identify cross-account trust relationships."""
    cmd = ["aws", "iam", "list-roles", "--output", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        roles = json.loads(result.stdout).get("Roles", [])
        cross_account = []
        for role in roles:
            policy_doc = role.get("AssumeRolePolicyDocument", {})
            for statement in policy_doc.get("Statement", []):
                principal = statement.get("Principal", {})
                aws_principal = principal.get("AWS", "")
                if isinstance(aws_principal, str) and ":root" in aws_principal:
                    cross_account.append({
                        "role": role["RoleName"],
                        "arn": role["Arn"],
                        "trusted_account": aws_principal,
                    })
        logger.info("Found %d cross-account trust roles", len(cross_account))
        return cross_account
    return []


def check_imds_v1_instances():
    """Check for EC2 instances running with IMDSv1 (vulnerable to SSRF)."""
    cmd = [
        "aws", "ec2", "describe-instances",
        "--query", "Reservations[*].Instances[*].[InstanceId,MetadataOptions.HttpTokens,State.Name]",
        "--output", "json",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        instances = json.loads(result.stdout)
        vulnerable = []
        for reservation in instances:
            for inst in reservation:
                if inst[1] == "optional" and inst[2] == "running":
                    vulnerable.append({"instance_id": inst[0], "imds": "v1 (optional)", "state": inst[2]})
        logger.info("Found %d instances with IMDSv1 enabled", len(vulnerable))
        return vulnerable
    return []


def check_public_s3_buckets():
    """Enumerate S3 buckets and check for public access."""
    cmd = ["aws", "s3api", "list-buckets", "--query", "Buckets[*].Name", "--output", "text"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return []
    buckets = result.stdout.strip().split()
    public_buckets = []
    for bucket in buckets:
        status_cmd = ["aws", "s3api", "get-bucket-policy-status", "--bucket", bucket, "--output", "json"]
        r = subprocess.run(status_cmd, capture_output=True, text=True)
        if r.returncode == 0:
            policy_status = json.loads(r.stdout)
            if policy_status.get("PolicyStatus", {}).get("IsPublic", False):
                public_buckets.append(bucket)
                logger.warning("PUBLIC bucket found: %s", bucket)
    return public_buckets


def check_lambda_env_secrets():
    """Check Lambda functions for secrets in environment variables."""
    cmd = ["aws", "lambda", "list-functions", "--query", "Functions[*].FunctionName", "--output", "text"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return []
    functions = result.stdout.strip().split()
    findings = []
    sensitive_keys = ["password", "secret", "key", "token", "api_key", "database_url", "connection_string"]
    for fn in functions:
        env_cmd = [
            "aws", "lambda", "get-function-configuration",
            "--function-name", fn,
            "--query", "Environment.Variables",
            "--output", "json",
        ]
        r = subprocess.run(env_cmd, capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip() != "null":
            env_vars = json.loads(r.stdout)
            exposed = [k for k in env_vars if any(s in k.lower() for s in sensitive_keys)]
            if exposed:
                findings.append({"function": fn, "exposed_keys": exposed})
                logger.warning("Lambda %s has sensitive env vars: %s", fn, exposed)
    return findings


def test_privesc_create_policy_version(policy_arn):
    """Test if iam:CreatePolicyVersion can be used for privilege escalation."""
    cmd = [
        "aws", "iam", "simulate-principal-policy",
        "--policy-source-arn", policy_arn,
        "--action-names", "iam:CreatePolicyVersion",
        "--output", "json",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        eval_results = json.loads(result.stdout).get("EvaluationResults", [])
        for er in eval_results:
            if er.get("EvalDecision") == "allowed":
                logger.warning("Privesc possible: %s has iam:CreatePolicyVersion", policy_arn)
                return True
    return False


def generate_report(users, cross_account_roles, imdsv1_instances, public_buckets, lambda_secrets):
    """Generate cloud penetration test findings report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "iam_users": len(users),
        "cross_account_trusts": cross_account_roles,
        "imdsv1_vulnerable_instances": imdsv1_instances,
        "public_s3_buckets": public_buckets,
        "lambda_env_secrets": lambda_secrets,
        "finding_count": (
            len(cross_account_roles) + len(imdsv1_instances) +
            len(public_buckets) + len(lambda_secrets)
        ),
    }
    print(json.dumps(report, indent=2))
    return report


def main():
    parser = argparse.ArgumentParser(description="Cloud Penetration Testing Agent")
    parser.add_argument("--profile", default="default", help="AWS CLI profile")
    parser.add_argument("--output", default="cloud_pentest_report.json")
    args = parser.parse_args()

    users = enumerate_iam_users()
    cross_account = enumerate_iam_roles()
    imdsv1 = check_imds_v1_instances()
    public_buckets = check_public_s3_buckets()
    lambda_secrets = check_lambda_env_secrets()

    report = generate_report(users, cross_account, imdsv1, public_buckets, lambda_secrets)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Cloud pentest report saved to %s", args.output)


if __name__ == "__main__":
    main()
