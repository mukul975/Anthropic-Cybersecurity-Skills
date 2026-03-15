#!/usr/bin/env python3
"""Detect AWS IAM privilege escalation paths using boto3 policy analysis."""

import json
import argparse
from datetime import datetime
from collections import defaultdict

try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

ESCALATION_COMBOS = [
    {"name": "CreatePolicyVersion", "permissions": ["iam:CreatePolicyVersion"],
     "description": "Create new policy version with elevated privileges", "severity": "critical"},
    {"name": "SetDefaultPolicyVersion", "permissions": ["iam:SetDefaultPolicyVersion"],
     "description": "Set a previously created permissive policy version as default", "severity": "critical"},
    {"name": "PassRole+Lambda", "permissions": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
     "description": "Pass privileged role to Lambda and invoke it", "severity": "critical"},
    {"name": "PassRole+EC2", "permissions": ["iam:PassRole", "ec2:RunInstances"],
     "description": "Launch EC2 with privileged instance profile", "severity": "critical"},
    {"name": "PassRole+CloudFormation", "permissions": ["iam:PassRole", "cloudformation:CreateStack"],
     "description": "Deploy CloudFormation stack with privileged role", "severity": "high"},
    {"name": "AttachUserPolicy", "permissions": ["iam:AttachUserPolicy"],
     "description": "Attach AdministratorAccess to own user", "severity": "critical"},
    {"name": "AttachGroupPolicy", "permissions": ["iam:AttachGroupPolicy"],
     "description": "Attach AdministratorAccess to own group", "severity": "critical"},
    {"name": "AttachRolePolicy", "permissions": ["iam:AttachRolePolicy"],
     "description": "Attach elevated policy to assumable role", "severity": "high"},
    {"name": "PutUserPolicy", "permissions": ["iam:PutUserPolicy"],
     "description": "Add inline policy to own user", "severity": "critical"},
    {"name": "PutGroupPolicy", "permissions": ["iam:PutGroupPolicy"],
     "description": "Add inline policy to own group", "severity": "high"},
    {"name": "AssumeRole", "permissions": ["sts:AssumeRole"],
     "description": "Assume role with higher privileges", "severity": "medium"},
    {"name": "PassRole+SageMaker", "permissions": ["iam:PassRole", "sagemaker:CreateNotebookInstance"],
     "description": "Create SageMaker notebook with privileged role", "severity": "high"},
    {"name": "UpdateAssumeRolePolicy", "permissions": ["iam:UpdateAssumeRolePolicy"],
     "description": "Modify trust policy to assume privileged role", "severity": "critical"},
    {"name": "PassRole+SSM", "permissions": ["iam:PassRole", "ssm:SendCommand"],
     "description": "Execute commands on EC2 via SSM with privileged role", "severity": "critical"},
]


def get_account_authorization(profile=None):
    """Download full IAM authorization details via boto3."""
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    iam = session.client("iam")
    paginator = iam.get_paginator("get_account_authorization_details")
    details = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    for page in paginator.paginate():
        details["UserDetailList"].extend(page.get("UserDetailList", []))
        details["GroupDetailList"].extend(page.get("GroupDetailList", []))
        details["RoleDetailList"].extend(page.get("RoleDetailList", []))
        details["Policies"].extend(page.get("Policies", []))
    return details


def extract_policy_actions(policy_document):
    """Extract all actions from a policy document."""
    actions = set()
    if isinstance(policy_document, str):
        policy_document = json.loads(policy_document)
    for statement in policy_document.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue
        stmt_actions = statement.get("Action", [])
        if isinstance(stmt_actions, str):
            stmt_actions = [stmt_actions]
        for action in stmt_actions:
            actions.add(action.lower())
        resource = statement.get("Resource", "")
        if resource == "*" or (isinstance(resource, list) and "*" in resource):
            actions.add("__wildcard_resource__")
    return actions


def check_escalation_paths(actions):
    """Check if a set of actions contains known privilege escalation combos."""
    findings = []
    has_wildcard = "iam:*" in actions or "*" in actions
    for combo in ESCALATION_COMBOS:
        required = {p.lower() for p in combo["permissions"]}
        if has_wildcard or required.issubset(actions):
            findings.append({
                "escalation_path": combo["name"],
                "required_permissions": combo["permissions"],
                "description": combo["description"],
                "severity": combo["severity"],
            })
    return findings


def analyze_wildcard_policies(actions):
    """Flag dangerous wildcard action patterns."""
    dangerous_wildcards = []
    wildcard_patterns = [a for a in actions if a.endswith(":*") or a == "*"]
    dangerous_services = {"iam:*", "sts:*", "lambda:*", "ec2:*", "s3:*", "cloudformation:*", "*"}
    for wp in wildcard_patterns:
        if wp in dangerous_services:
            dangerous_wildcards.append({
                "action": wp, "severity": "critical" if wp in {"iam:*", "*"} else "high",
                "finding": f"Wildcard action {wp} grants broad access",
            })
    return dangerous_wildcards


def analyze_account(auth_details):
    """Analyze all principals for escalation paths."""
    findings = []
    for user in auth_details.get("UserDetailList", []):
        all_actions = set()
        for policy in user.get("UserPolicyList", []):
            all_actions.update(extract_policy_actions(policy.get("PolicyDocument", {})))
        for policy in user.get("AttachedManagedPolicies", []):
            arn = policy.get("PolicyArn", "")
            for p in auth_details.get("Policies", []):
                if p.get("Arn") == arn:
                    for ver in p.get("PolicyVersionList", []):
                        if ver.get("IsDefaultVersion"):
                            all_actions.update(extract_policy_actions(ver.get("Document", {})))
        escalations = check_escalation_paths(all_actions)
        wildcards = analyze_wildcard_policies(all_actions)
        if escalations or wildcards:
            findings.append({
                "principal_type": "User", "principal_name": user.get("UserName"),
                "arn": user.get("Arn"), "escalation_paths": escalations,
                "wildcard_findings": wildcards,
            })
    for role in auth_details.get("RoleDetailList", []):
        all_actions = set()
        for policy in role.get("RolePolicyList", []):
            all_actions.update(extract_policy_actions(policy.get("PolicyDocument", {})))
        for policy in role.get("AttachedManagedPolicies", []):
            arn = policy.get("PolicyArn", "")
            for p in auth_details.get("Policies", []):
                if p.get("Arn") == arn:
                    for ver in p.get("PolicyVersionList", []):
                        if ver.get("IsDefaultVersion"):
                            all_actions.update(extract_policy_actions(ver.get("Document", {})))
        escalations = check_escalation_paths(all_actions)
        wildcards = analyze_wildcard_policies(all_actions)
        if escalations or wildcards:
            findings.append({
                "principal_type": "Role", "principal_name": role.get("RoleName"),
                "arn": role.get("Arn"), "escalation_paths": escalations,
                "wildcard_findings": wildcards,
            })
    return findings


def generate_report(findings, source):
    """Generate privilege escalation analysis report."""
    severity_counts = defaultdict(int)
    for f in findings:
        for esc in f.get("escalation_paths", []):
            severity_counts[esc["severity"]] += 1
        for wc in f.get("wildcard_findings", []):
            severity_counts[wc["severity"]] += 1
    return {
        "report_time": datetime.utcnow().isoformat(),
        "source": source,
        "total_principals_with_findings": len(findings),
        "severity_summary": dict(severity_counts),
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="AWS IAM Privilege Escalation Detector")
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--input-file", help="Pre-downloaded authorization details JSON")
    parser.add_argument("--output", default="iam_escalation_report.json")
    args = parser.parse_args()

    if args.input_file:
        with open(args.input_file) as f:
            auth_details = json.load(f)
        source = args.input_file
    elif HAS_BOTO3:
        auth_details = get_account_authorization(args.profile)
        source = f"live-account (profile={args.profile or 'default'})"
    else:
        print("[!] boto3 not installed and no --input-file provided")
        return

    findings = analyze_account(auth_details)
    report = generate_report(findings, source)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Analyzed {len(auth_details.get('UserDetailList', []))} users, "
          f"{len(auth_details.get('RoleDetailList', []))} roles")
    print(f"[+] Found {len(findings)} principals with escalation paths")
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
