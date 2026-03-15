#!/usr/bin/env python3
"""Agent for auditing serverless function security across AWS Lambda."""

import boto3
import json
import sys
import argparse
from datetime import datetime


def list_functions(region="us-east-1"):
    """List all Lambda functions with security-relevant configuration."""
    lam = boto3.client("lambda", region_name=region)
    functions = []
    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        for f in page["Functions"]:
            functions.append({
                "name": f["FunctionName"],
                "runtime": f.get("Runtime", "N/A"),
                "role": f["Role"].split("/")[-1],
                "timeout": f.get("Timeout", 3),
                "memory": f.get("MemorySize", 128),
                "kms_key": f.get("KMSKeyArn", "None (default)"),
                "vpc": bool(f.get("VpcConfig", {}).get("SubnetIds")),
            })
    print(f"[*] Found {len(functions)} Lambda functions")
    for fn in functions:
        print(f"  {fn['name']} | {fn['runtime']} | role={fn['role']} | VPC={fn['vpc']}")
    return functions


def check_function_urls(region="us-east-1"):
    """Check for Lambda function URLs with insecure authentication."""
    lam = boto3.client("lambda", region_name=region)
    findings = []
    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        for f in page["Functions"]:
            try:
                url_config = lam.get_function_url_config(FunctionName=f["FunctionName"])
                auth_type = url_config.get("AuthType", "NONE")
                if auth_type == "NONE":
                    findings.append({
                        "function": f["FunctionName"],
                        "url": url_config.get("FunctionUrl", ""),
                        "auth_type": auth_type,
                        "severity": "CRITICAL",
                    })
                    print(f"  [!] CRITICAL: {f['FunctionName']} has unauthenticated URL: "
                          f"{url_config.get('FunctionUrl', '')}")
                else:
                    print(f"  [+] {f['FunctionName']}: URL auth={auth_type}")
            except lam.exceptions.ResourceNotFoundException:
                continue
    print(f"[*] {len(findings)} functions with unauthenticated URLs")
    return findings


def check_env_variables(region="us-east-1"):
    """Scan Lambda environment variables for potential hardcoded secrets."""
    lam = boto3.client("lambda", region_name=region)
    findings = []
    secret_patterns = ["password", "secret", "api_key", "apikey", "token", "private_key",
                       "access_key", "db_pass", "database_url", "smtp"]
    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        for f in page["Functions"]:
            env_vars = f.get("Environment", {}).get("Variables", {})
            kms_key = f.get("KMSKeyArn")
            for key, value in env_vars.items():
                key_lower = key.lower()
                if any(p in key_lower for p in secret_patterns):
                    has_kms = bool(kms_key)
                    findings.append({
                        "function": f["FunctionName"],
                        "variable": key,
                        "encrypted": has_kms,
                        "severity": "HIGH" if not has_kms else "MEDIUM",
                    })
                    enc_status = "KMS-encrypted" if has_kms else "PLAINTEXT"
                    print(f"  [!] {f['FunctionName']}: {key} ({enc_status})")
    print(f"[*] {len(findings)} potential secrets in environment variables")
    return findings


def check_shared_roles(region="us-east-1"):
    """Identify Lambda functions sharing the same execution role."""
    lam = boto3.client("lambda", region_name=region)
    role_map = {}
    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        for f in page["Functions"]:
            role = f["Role"]
            role_name = role.split("/")[-1]
            if role_name not in role_map:
                role_map[role_name] = []
            role_map[role_name].append(f["FunctionName"])
    findings = []
    print("\n[*] Checking for shared execution roles...")
    for role, funcs in role_map.items():
        if len(funcs) > 1:
            findings.append({"role": role, "functions": funcs, "count": len(funcs)})
            print(f"  [!] Role '{role}' shared by {len(funcs)} functions: {', '.join(funcs[:5])}")
    print(f"[*] {len(findings)} shared roles found")
    return findings


def check_reserved_concurrency(region="us-east-1"):
    """Check if functions have reserved concurrency set to prevent resource exhaustion."""
    lam = boto3.client("lambda", region_name=region)
    no_concurrency = []
    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        for f in page["Functions"]:
            try:
                conc = lam.get_function_concurrency(FunctionName=f["FunctionName"])
                reserved = conc.get("ReservedConcurrentExecutions")
                if reserved is None:
                    no_concurrency.append(f["FunctionName"])
            except Exception:
                no_concurrency.append(f["FunctionName"])
    if no_concurrency:
        print(f"\n[*] {len(no_concurrency)} functions without reserved concurrency")
    return no_concurrency


def full_audit(region="us-east-1", output_path="serverless_audit.json"):
    """Run comprehensive serverless security audit."""
    print("[*] Starting serverless security audit...\n")
    report = {
        "audit_date": datetime.now().isoformat(),
        "region": region,
        "functions": list_functions(region),
        "unauthenticated_urls": check_function_urls(region),
        "env_secrets": check_env_variables(region),
        "shared_roles": check_shared_roles(region),
        "no_concurrency_limit": check_reserved_concurrency(region),
    }
    total_findings = (len(report["unauthenticated_urls"]) + len(report["env_secrets"]) +
                      len(report["shared_roles"]))
    report["total_findings"] = total_findings
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[*] Audit complete: {total_findings} findings")
    print(f"[*] Report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Serverless Function Security Agent")
    parser.add_argument("action", choices=["list", "urls", "env-secrets", "shared-roles",
                                           "concurrency", "full-audit"])
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("-o", "--output", default="serverless_audit.json")
    args = parser.parse_args()

    if args.action == "list":
        list_functions(args.region)
    elif args.action == "urls":
        check_function_urls(args.region)
    elif args.action == "env-secrets":
        check_env_variables(args.region)
    elif args.action == "shared-roles":
        check_shared_roles(args.region)
    elif args.action == "concurrency":
        check_reserved_concurrency(args.region)
    elif args.action == "full-audit":
        full_audit(args.region, args.output)


if __name__ == "__main__":
    main()
