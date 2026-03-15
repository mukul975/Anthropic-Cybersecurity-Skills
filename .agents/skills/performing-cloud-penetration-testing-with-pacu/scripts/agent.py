#!/usr/bin/env python3
"""
AWS Penetration Testing with Pacu Agent — AUTHORIZED TESTING ONLY
Automates Pacu module execution for AWS security assessment including
IAM enumeration, privilege escalation scanning, and credential testing.

WARNING: Only use with explicit written authorization on approved AWS accounts.
"""

import json
import subprocess
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError


def run_pacu_module(module_name: str, session_name: str = "pentest", args: str = "") -> dict:
    """Execute a Pacu module via subprocess."""
    cmd = ["pacu", "--session", session_name, "--module-name", module_name]
    if args:
        cmd.extend(["--module-args", args])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {
            "module": module_name,
            "success": result.returncode == 0,
            "output": result.stdout[-2000:] if result.stdout else "",
            "error": result.stderr[-500:] if result.stderr else "",
        }
    except subprocess.TimeoutExpired:
        return {"module": module_name, "success": False, "error": "Module timed out (300s)"}
    except FileNotFoundError:
        return {"module": module_name, "success": False, "error": "Pacu not installed. Install with: pip install pacu"}


def enumerate_iam_with_boto(profile: str = None) -> dict:
    """Fallback IAM enumeration using boto3 when Pacu is unavailable."""
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    iam = session.client("iam")
    sts = session.client("sts")

    identity = sts.get_caller_identity()
    result = {
        "identity": {
            "account": identity["Account"],
            "arn": identity["Arn"],
        },
        "users": [],
        "roles": [],
        "policies": [],
    }

    try:
        for page in iam.get_paginator("list_users").paginate():
            for user in page["Users"]:
                attached = iam.list_attached_user_policies(UserName=user["UserName"])
                result["users"].append({
                    "username": user["UserName"],
                    "arn": user["Arn"],
                    "policies": [p["PolicyArn"] for p in attached["AttachedPolicies"]],
                })
    except ClientError as e:
        result["users_error"] = str(e)

    try:
        for page in iam.get_paginator("list_roles").paginate():
            for role in page["Roles"]:
                result["roles"].append({
                    "name": role["RoleName"],
                    "arn": role["Arn"],
                    "trust_policy": role.get("AssumeRolePolicyDocument", {}),
                })
    except ClientError as e:
        result["roles_error"] = str(e)

    return result


def scan_privilege_escalation(iam_data: dict) -> list[dict]:
    """Identify privilege escalation paths from IAM enumeration data."""
    escalation_vectors = []
    dangerous_actions = {
        "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
        "iam:AttachUserPolicy", "iam:AttachRolePolicy",
        "iam:PutUserPolicy", "iam:PutRolePolicy",
        "iam:AddUserToGroup", "iam:UpdateAssumeRolePolicy",
        "iam:PassRole", "iam:CreateLoginProfile",
        "lambda:CreateFunction", "lambda:UpdateFunctionCode",
    }

    iam_client = boto3.client("iam")

    for user in iam_data.get("users", []):
        user_dangerous = []
        for policy_arn in user.get("policies", []):
            try:
                policy = iam_client.get_policy(PolicyArn=policy_arn)
                version = iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy["Policy"]["DefaultVersionId"],
                )
                doc = version["PolicyVersion"]["Document"]
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") != "Allow":
                        continue
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    for action in actions:
                        if action == "*" or action in dangerous_actions:
                            user_dangerous.append({"action": action, "policy": policy_arn})
            except ClientError:
                continue

        if user_dangerous:
            escalation_vectors.append({
                "principal": user["username"],
                "type": "user",
                "vectors": user_dangerous,
                "risk": "CRITICAL" if any(v["action"] == "*" for v in user_dangerous) else "HIGH",
            })

    return escalation_vectors


def test_credential_access(region: str = "us-east-1") -> dict:
    """Test what services the current credentials can access."""
    services_to_test = [
        ("sts", "get_caller_identity", {}),
        ("s3", "list_buckets", {}),
        ("ec2", "describe_instances", {}),
        ("iam", "list_users", {}),
        ("lambda", "list_functions", {}),
        ("secretsmanager", "list_secrets", {}),
        ("ssm", "describe_parameters", {}),
    ]

    accessible = []
    denied = []

    for service, method, kwargs in services_to_test:
        try:
            client = boto3.client(service, region_name=region)
            getattr(client, method)(**kwargs)
            accessible.append(service)
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AccessDenied", "AccessDeniedException", "UnauthorizedAccess"):
                denied.append(service)
            else:
                accessible.append(service)
        except Exception:
            denied.append(service)

    return {"accessible_services": accessible, "denied_services": denied}


def generate_report(iam_data: dict, escalation: list, access: dict, pacu_results: list) -> str:
    """Generate Pacu penetration testing report."""
    lines = [
        "AWS PENETRATION TESTING (PACU) REPORT — AUTHORIZED TESTING ONLY",
        "=" * 65,
        f"Account: {iam_data.get('identity', {}).get('account', 'N/A')}",
        f"Identity: {iam_data.get('identity', {}).get('arn', 'N/A')}",
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "SERVICE ACCESS:",
        f"  Accessible: {', '.join(access.get('accessible_services', []))}",
        f"  Denied: {', '.join(access.get('denied_services', []))}",
        "",
        f"IAM ENUMERATION:",
        f"  Users Found: {len(iam_data.get('users', []))}",
        f"  Roles Found: {len(iam_data.get('roles', []))}",
        "",
        f"PRIVILEGE ESCALATION VECTORS: {len(escalation)}",
        "-" * 40,
    ]

    for esc in escalation:
        lines.append(f"  [{esc['risk']}] {esc['principal']} ({esc['type']})")
        for v in esc["vectors"][:5]:
            lines.append(f"    - {v['action']} via {v['policy']}")

    if pacu_results:
        lines.extend(["", "PACU MODULE RESULTS:"])
        for pr in pacu_results:
            status = "OK" if pr["success"] else "FAIL"
            lines.append(f"  [{status}] {pr['module']}")

    return "\n".join(lines)


if __name__ == "__main__":
    print("[!] AWS PENTEST WITH PACU — AUTHORIZED TESTING ONLY\n")

    region = sys.argv[1] if len(sys.argv) > 1 else "us-east-1"
    session_name = sys.argv[2] if len(sys.argv) > 2 else "pentest"

    print("[*] Testing credential access scope...")
    access = test_credential_access(region)

    print("[*] Enumerating IAM...")
    iam_data = enumerate_iam_with_boto()

    print("[*] Scanning for privilege escalation vectors...")
    escalation = scan_privilege_escalation(iam_data)

    pacu_results = []
    pacu_modules = [
        "iam__enum_users_roles_policies_groups",
        "iam__privesc_scan",
        "ec2__enum",
        "s3__enum",
        "lambda__enum",
    ]
    for module in pacu_modules:
        print(f"[*] Running Pacu module: {module}")
        result = run_pacu_module(module, session_name)
        pacu_results.append(result)

    report = generate_report(iam_data, escalation, access, pacu_results)
    print(report)

    output = f"pacu_pentest_{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
    with open(output, "w") as f:
        json.dump({"iam": iam_data, "escalation": escalation, "access": access,
                    "pacu_results": pacu_results}, f, indent=2, default=str)
    print(f"\n[*] Results saved to {output}")
