#!/usr/bin/env python3
"""Agent for auditing and securing AWS Lambda execution roles."""

import boto3
import json
import sys
import argparse
from datetime import datetime, timedelta, timezone


def list_lambda_roles(region="us-east-1"):
    """List all Lambda functions and their execution roles."""
    lam = boto3.client("lambda", region_name=region)
    iam = boto3.client("iam")
    functions = []
    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        for func in page["Functions"]:
            role_arn = func["Role"]
            role_name = role_arn.split("/")[-1]
            functions.append({
                "function_name": func["FunctionName"],
                "runtime": func.get("Runtime", "N/A"),
                "role_name": role_name,
                "role_arn": role_arn,
            })
            print(f"  {func['FunctionName']} -> {role_name} ({func.get('Runtime', 'N/A')})")
    print(f"\n[*] Total Lambda functions: {len(functions)}")
    return functions


def audit_role_permissions(role_name):
    """Analyze attached and inline policies for a Lambda execution role."""
    iam = boto3.client("iam")
    findings = []
    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    broad_policies = ["AdministratorAccess", "PowerUserAccess", "AmazonS3FullAccess",
                      "AmazonDynamoDBFullAccess", "AmazonSQSFullAccess"]
    for pol in attached:
        if pol["PolicyName"] in broad_policies:
            findings.append({
                "type": "OVERPRIVILEGED_MANAGED_POLICY", "severity": "CRITICAL",
                "role": role_name, "policy": pol["PolicyName"],
                "detail": f"Broad managed policy '{pol['PolicyName']}' attached to Lambda role",
            })
            print(f"  [!] CRITICAL: {role_name} has {pol['PolicyName']}")

    inline_names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    for pol_name in inline_names:
        doc = iam.get_role_policy(RoleName=role_name, PolicyName=pol_name)["PolicyDocument"]
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            wildcard_actions = [a for a in actions if a.endswith(":*") or a == "*"]
            if wildcard_actions and "*" in resources:
                findings.append({
                    "type": "WILDCARD_POLICY", "severity": "HIGH",
                    "role": role_name, "policy": pol_name,
                    "detail": f"Wildcard actions {wildcard_actions} on Resource '*'",
                })
                print(f"  [!] HIGH: {role_name}/{pol_name} has wildcard actions on *")
    return findings


def check_permission_boundary(role_name):
    """Check if a Lambda execution role has a permission boundary."""
    iam = boto3.client("iam")
    role = iam.get_role(RoleName=role_name)["Role"]
    boundary = role.get("PermissionsBoundary")
    if boundary:
        print(f"  [OK] {role_name} has boundary: {boundary['PermissionsBoundaryArn']}")
        return True
    else:
        print(f"  [!] {role_name} has NO permission boundary")
        return False


def check_trust_policy(role_name):
    """Validate the trust policy for confused deputy prevention."""
    iam = boto3.client("iam")
    role = iam.get_role(RoleName=role_name)["Role"]
    trust_doc = role["AssumeRolePolicyDocument"]
    findings = []
    for stmt in trust_doc.get("Statement", []):
        conditions = stmt.get("Condition", {})
        principal = stmt.get("Principal", {})
        service = principal.get("Service", "")
        if service == "lambda.amazonaws.com" and not conditions:
            findings.append({
                "type": "MISSING_TRUST_CONDITION", "severity": "MEDIUM",
                "role": role_name,
                "detail": "Trust policy lacks aws:SourceAccount or aws:SourceArn condition",
            })
            print(f"  [!] MEDIUM: {role_name} trust policy lacks confused deputy prevention")
    return findings


def validate_with_access_analyzer(policy_document, region="us-east-1"):
    """Validate a policy document using IAM Access Analyzer."""
    aa = boto3.client("accessanalyzer", region_name=region)
    response = aa.validate_policy(
        policyDocument=json.dumps(policy_document),
        policyType="IDENTITY_POLICY",
    )
    findings = response.get("findings", [])
    for f in findings:
        print(f"  [{f['findingType']}] {f['issueCode']}: {f.get('findingDetails', '')}")
    return findings


def full_audit(region="us-east-1"):
    """Run a complete audit of all Lambda execution roles."""
    print("[*] Starting Lambda execution role audit...")
    functions = list_lambda_roles(region)
    all_findings = []
    audited_roles = set()

    for func in functions:
        role_name = func["role_name"]
        if role_name in audited_roles:
            continue
        audited_roles.add(role_name)
        print(f"\n[*] Auditing role: {role_name}")
        all_findings.extend(audit_role_permissions(role_name))
        all_findings.extend(check_trust_policy(role_name))
        has_boundary = check_permission_boundary(role_name)
        if not has_boundary:
            all_findings.append({
                "type": "NO_PERMISSION_BOUNDARY", "severity": "MEDIUM",
                "role": role_name, "detail": "No permission boundary applied",
            })

    critical = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    print(f"\n[*] Audit complete: {len(all_findings)} findings "
          f"(Critical: {critical}, High: {high}, Medium: {medium})")
    return all_findings


def main():
    parser = argparse.ArgumentParser(description="AWS Lambda Execution Role Security Agent")
    parser.add_argument("action", choices=["list", "audit-role", "full-audit", "check-boundary",
                                           "check-trust", "validate-policy"])
    parser.add_argument("--role", help="Role name to audit")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--policy-file", help="Policy JSON file to validate")
    parser.add_argument("-o", "--output", default="lambda_role_audit.json")
    args = parser.parse_args()

    if args.action == "list":
        list_lambda_roles(args.region)
    elif args.action == "audit-role":
        audit_role_permissions(args.role)
    elif args.action == "full-audit":
        findings = full_audit(args.region)
        with open(args.output, "w") as f:
            json.dump(findings, f, indent=2, default=str)
        print(f"[*] Report saved to {args.output}")
    elif args.action == "check-boundary":
        check_permission_boundary(args.role)
    elif args.action == "check-trust":
        check_trust_policy(args.role)
    elif args.action == "validate-policy":
        with open(args.policy_file) as f:
            doc = json.load(f)
        validate_with_access_analyzer(doc, args.region)


if __name__ == "__main__":
    main()
