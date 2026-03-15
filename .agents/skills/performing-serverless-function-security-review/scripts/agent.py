#!/usr/bin/env python3
"""Serverless function security review agent using boto3."""

import json
import re
import boto3
from botocore.exceptions import ClientError


def get_lambda_client(region="us-east-1"):
    return boto3.client("lambda", region_name=region)


def get_iam_client(region="us-east-1"):
    return boto3.client("iam", region_name=region)


def list_all_functions(client):
    functions = []
    paginator = client.get_paginator("list_functions")
    for page in paginator.paginate():
        functions.extend(page["Functions"])
    return functions


def check_deprecated_runtime(runtime):
    deprecated = [
        "python2.7", "python3.6", "python3.7", "nodejs10.x",
        "nodejs12.x", "nodejs14.x", "dotnetcore2.1", "dotnetcore3.1",
        "ruby2.5", "java8", "go1.x",
    ]
    return runtime in deprecated


def audit_execution_role(iam, role_arn):
    findings = []
    role_name = role_arn.split("/")[-1]
    try:
        attached = iam.list_attached_role_policies(RoleName=role_name)
        for policy in attached["AttachedPolicies"]:
            if policy["PolicyName"] == "AdministratorAccess":
                findings.append(f"CRITICAL: Role {role_name} has AdministratorAccess")
            version_id = iam.get_policy(PolicyArn=policy["PolicyArn"])["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(
                PolicyArn=policy["PolicyArn"], VersionId=version_id
            )["PolicyVersion"]["Document"]
            for stmt in doc.get("Statement", []):
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                if "*" in actions or any(a.endswith(":*") for a in actions):
                    findings.append(
                        f"WARNING: {role_name} has wildcard action: {actions} "
                        f"on {stmt.get('Resource', '*')}"
                    )
    except ClientError as e:
        findings.append(f"ERROR auditing role {role_name}: {e}")
    return findings


SENSITIVE_PATTERNS = [
    re.compile(r"(?i)(password|secret|key|token|credential|api.?key)"),
    re.compile(r"(?i)(aws.?access|aws.?secret)"),
    re.compile(r"(?i)(database.?url|connection.?string|db.?pass)"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
]


def check_env_secrets(env_vars):
    findings = []
    if not env_vars:
        return findings
    for key, value in env_vars.items():
        for pattern in SENSITIVE_PATTERNS:
            if pattern.search(key) or pattern.search(str(value)):
                masked = value[:4] + "****" + value[-4:] if len(value) > 8 else "****"
                findings.append(f"SENSITIVE: {key} = {masked}")
                break
    return findings


def check_public_access(client, function_name):
    findings = []
    try:
        policy = client.get_policy(FunctionName=function_name)
        doc = json.loads(policy["Policy"])
        for stmt in doc.get("Statement", []):
            principal = stmt.get("Principal", {})
            if principal == "*" or principal == {"AWS": "*"}:
                findings.append(
                    f"PUBLIC ACCESS: {function_name} allows public invocation "
                    f"(statement: {stmt.get('Sid', 'unnamed')})"
                )
    except ClientError:
        pass
    try:
        urls = client.list_function_url_configs(FunctionName=function_name)
        for url_cfg in urls.get("FunctionUrlConfigs", []):
            if url_cfg.get("AuthType") == "NONE":
                findings.append(
                    f"UNAUTHENTICATED URL: {function_name} -> {url_cfg['FunctionUrl']}"
                )
    except ClientError:
        pass
    return findings


def run_review(region="us-east-1"):
    lam = get_lambda_client(region)
    iam = get_iam_client(region)
    functions = list_all_functions(lam)
    report = {
        "total_functions": len(functions),
        "deprecated_runtimes": [],
        "role_findings": [],
        "secret_findings": [],
        "public_access_findings": [],
    }
    for func in functions:
        name = func["FunctionName"]
        runtime = func.get("Runtime", "unknown")
        if check_deprecated_runtime(runtime):
            report["deprecated_runtimes"].append({"function": name, "runtime": runtime})
        report["role_findings"].extend(audit_execution_role(iam, func["Role"]))
        env = func.get("Environment", {}).get("Variables", {})
        secrets = check_env_secrets(env)
        if secrets:
            report["secret_findings"].extend(
                [{"function": name, "finding": s} for s in secrets]
            )
        report["public_access_findings"].extend(check_public_access(lam, name))
    return report


def print_report(report):
    print("Serverless Function Security Review")
    print("=" * 40)
    print(f"Functions Reviewed: {report['total_functions']}")
    for section, label in [
        ("deprecated_runtimes", "Deprecated Runtimes"),
        ("role_findings", "Role Issues"),
        ("secret_findings", "Secrets in Env Vars"),
        ("public_access_findings", "Public Access"),
    ]:
        items = report[section]
        print(f"\n{label}: {len(items)} finding(s)")
        for item in items:
            print(f"  - {item}")


if __name__ == "__main__":
    result = run_review()
    print_report(result)
