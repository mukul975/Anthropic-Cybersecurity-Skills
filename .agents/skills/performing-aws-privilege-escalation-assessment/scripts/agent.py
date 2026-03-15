#!/usr/bin/env python3
"""
AWS Privilege Escalation Assessment Agent — AUTHORIZED TESTING ONLY
Assesses AWS IAM configurations for privilege escalation paths using boto3
and enumerates dangerous policy combinations.

WARNING: Only use with explicit written authorization on approved AWS accounts.
"""

import json
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError


def get_caller_identity() -> dict:
    """Get current AWS identity information."""
    sts = boto3.client("sts")
    identity = sts.get_caller_identity()
    return {
        "account": identity["Account"],
        "arn": identity["Arn"],
        "user_id": identity["UserId"],
    }


def enumerate_iam_users() -> list[dict]:
    """Enumerate all IAM users and their attached policies."""
    iam = boto3.client("iam")
    users = []
    paginator = iam.get_paginator("list_users")

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            attached = iam.list_attached_user_policies(UserName=username)
            inline = iam.list_user_policies(UserName=username)
            groups = iam.list_groups_for_user(UserName=username)

            users.append({
                "username": username,
                "arn": user["Arn"],
                "attached_policies": [p["PolicyArn"] for p in attached["AttachedPolicies"]],
                "inline_policies": inline["PolicyNames"],
                "groups": [g["GroupName"] for g in groups["Groups"]],
                "has_console": user.get("PasswordLastUsed") is not None,
            })

    return users


def enumerate_iam_roles() -> list[dict]:
    """Enumerate IAM roles and their trust policies."""
    iam = boto3.client("iam")
    roles = []
    paginator = iam.get_paginator("list_roles")

    for page in paginator.paginate():
        for role in page["Roles"]:
            trust = role.get("AssumeRolePolicyDocument", {})
            attached = iam.list_attached_role_policies(RoleName=role["RoleName"])

            roles.append({
                "role_name": role["RoleName"],
                "arn": role["Arn"],
                "trust_policy": trust,
                "attached_policies": [p["PolicyArn"] for p in attached["AttachedPolicies"]],
            })

    return roles


def check_dangerous_permissions(users: list[dict]) -> list[dict]:
    """Identify users with dangerous permission combinations for privilege escalation."""
    iam = boto3.client("iam")
    escalation_paths = []

    dangerous_actions = [
        "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
        "iam:PassRole", "iam:CreateRole", "iam:AttachUserPolicy",
        "iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:PutRolePolicy",
        "iam:AddUserToGroup", "iam:UpdateAssumeRolePolicy",
        "sts:AssumeRole", "lambda:CreateFunction", "lambda:InvokeFunction",
        "lambda:UpdateFunctionCode", "ec2:RunInstances",
        "cloudformation:CreateStack", "glue:CreateDevEndpoint",
        "datapipeline:CreatePipeline", "ssm:SendCommand",
    ]

    for user in users:
        user_dangerous = []
        for policy_arn in user["attached_policies"]:
            try:
                policy = iam.get_policy(PolicyArn=policy_arn)
                version_id = policy["Policy"]["DefaultVersionId"]
                version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
                statements = version["PolicyVersion"]["Document"].get("Statement", [])

                for stmt in statements:
                    if stmt.get("Effect") != "Allow":
                        continue
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    for action in actions:
                        if action == "*" or action in dangerous_actions:
                            user_dangerous.append({
                                "policy": policy_arn,
                                "action": action,
                                "resource": stmt.get("Resource", "*"),
                            })
            except ClientError:
                continue

        if user_dangerous:
            escalation_paths.append({
                "username": user["username"],
                "dangerous_permissions": user_dangerous,
                "escalation_risk": "HIGH" if any(
                    d["action"] == "*" for d in user_dangerous
                ) else "MEDIUM",
            })

    return escalation_paths


def check_role_chaining(roles: list[dict], account_id: str) -> list[dict]:
    """Identify role chaining opportunities for privilege escalation."""
    chains = []

    for role in roles:
        trust = role.get("trust_policy", {})
        for statement in trust.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue
            principal = statement.get("Principal", {})
            aws_principal = principal.get("AWS", [])
            if isinstance(aws_principal, str):
                aws_principal = [aws_principal]

            for p in aws_principal:
                if p == f"arn:aws:iam::{account_id}:root" or p == "*":
                    chains.append({
                        "role": role["role_name"],
                        "trust_principal": p,
                        "risk": "HIGH" if p == "*" else "MEDIUM",
                        "policies": role["attached_policies"],
                    })

    return chains


def generate_report(identity: dict, users: list, escalation: list, chains: list) -> str:
    """Generate privilege escalation assessment report."""
    lines = [
        "AWS PRIVILEGE ESCALATION ASSESSMENT — AUTHORIZED TESTING ONLY",
        "=" * 65,
        f"Account: {identity['account']}",
        f"Assessed As: {identity['arn']}",
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"IAM Users Enumerated: {len(users)}",
        f"Escalation Paths Found: {len(escalation)}",
        f"Role Chaining Risks: {len(chains)}",
        "",
        "PRIVILEGE ESCALATION PATHS:",
        "-" * 40,
    ]
    for path in escalation:
        lines.append(f"  [{path['escalation_risk']}] {path['username']}")
        for perm in path["dangerous_permissions"][:5]:
            lines.append(f"    - {perm['action']} on {perm['resource']}")

    if chains:
        lines.extend(["", "ROLE CHAINING RISKS:", "-" * 40])
        for chain in chains:
            lines.append(f"  [{chain['risk']}] {chain['role']} trusts {chain['trust_principal']}")

    return "\n".join(lines)


if __name__ == "__main__":
    print("[!] AWS PRIVILEGE ESCALATION ASSESSMENT — AUTHORIZED TESTING ONLY\n")

    identity = get_caller_identity()
    print(f"[*] Account: {identity['account']}, Identity: {identity['arn']}")

    users = enumerate_iam_users()
    print(f"[*] Enumerated {len(users)} IAM users")

    roles = enumerate_iam_roles()
    print(f"[*] Enumerated {len(roles)} IAM roles")

    escalation = check_dangerous_permissions(users)
    chains = check_role_chaining(roles, identity["account"])

    report = generate_report(identity, users, escalation, chains)
    print(report)

    output = f"aws_privesc_{identity['account']}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
    with open(output, "w") as f:
        json.dump({"identity": identity, "users": users, "escalation_paths": escalation,
                    "role_chains": chains}, f, indent=2, default=str)
    print(f"\n[*] Results saved to {output}")
