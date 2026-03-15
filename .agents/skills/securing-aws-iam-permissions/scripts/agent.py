#!/usr/bin/env python3
"""Agent for auditing and hardening AWS IAM permissions using least-privilege principles."""

import boto3
import json
import csv
import sys
import argparse
from datetime import datetime, timedelta, timezone
from base64 import b64decode


def get_credential_report():
    """Generate and parse the IAM credential report."""
    iam = boto3.client("iam")
    iam.generate_credential_report()
    import time
    for _ in range(10):
        try:
            response = iam.get_credential_report()
            content = b64decode(response["Content"]).decode("utf-8")
            lines = content.strip().split("\n")
            reader = csv.DictReader(lines)
            report = list(reader)
            print(f"[*] Credential report: {len(report)} users")
            return report
        except iam.exceptions.CredentialReportNotReadyException:
            time.sleep(2)
    return []


def find_stale_access_keys(max_age_days=90):
    """Find access keys older than the specified threshold."""
    iam = boto3.client("iam")
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    stale_keys = []
    users = iam.list_users()["Users"]
    for user in users:
        keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
        for key in keys:
            if key["CreateDate"] < cutoff and key["Status"] == "Active":
                last_used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                last_used_date = last_used["AccessKeyLastUsed"].get("LastUsedDate", "Never")
                stale_keys.append({
                    "user": user["UserName"], "key_id": key["AccessKeyId"],
                    "created": key["CreateDate"].isoformat(), "last_used": str(last_used_date),
                })
                print(f"  [!] Stale key: {user['UserName']} - {key['AccessKeyId']} "
                      f"(created: {key['CreateDate'].strftime('%Y-%m-%d')})")
    print(f"[*] Found {len(stale_keys)} stale access keys (>{max_age_days} days)")
    return stale_keys


def find_overprivileged_roles():
    """Identify roles with AdministratorAccess or wildcard policies."""
    iam = boto3.client("iam")
    findings = []
    roles = iam.list_roles()["Roles"]
    for role in roles:
        if role["Path"].startswith("/aws-service-role/"):
            continue
        attached = iam.list_attached_role_policies(RoleName=role["RoleName"])["AttachedPolicies"]
        for policy in attached:
            if policy["PolicyName"] in ("AdministratorAccess", "PowerUserAccess"):
                findings.append({
                    "role": role["RoleName"], "policy": policy["PolicyName"],
                    "severity": "CRITICAL" if policy["PolicyName"] == "AdministratorAccess" else "HIGH",
                })
                print(f"  [!] {role['RoleName']} has {policy['PolicyName']}")
        inline_policies = iam.list_role_policies(RoleName=role["RoleName"])["PolicyNames"]
        for pol_name in inline_policies:
            pol_doc = iam.get_role_policy(RoleName=role["RoleName"], PolicyName=pol_name)["PolicyDocument"]
            for stmt in pol_doc.get("Statement", []):
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]
                if "*" in actions and "*" in resources and stmt.get("Effect") == "Allow":
                    findings.append({
                        "role": role["RoleName"], "policy": f"inline:{pol_name}",
                        "severity": "CRITICAL",
                    })
                    print(f"  [!] {role['RoleName']} inline policy '{pol_name}' has *:* Allow")
    print(f"[*] Found {len(findings)} overprivileged roles")
    return findings


def check_mfa_status():
    """Check which IAM users have MFA enabled."""
    iam = boto3.client("iam")
    users_without_mfa = []
    users = iam.list_users()["Users"]
    for user in users:
        mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
        if not mfa_devices:
            login_profile = None
            try:
                iam.get_login_profile(UserName=user["UserName"])
                login_profile = True
            except iam.exceptions.NoSuchEntityException:
                login_profile = False
            if login_profile:
                users_without_mfa.append(user["UserName"])
                print(f"  [!] {user['UserName']} has console access but NO MFA")
    print(f"[*] {len(users_without_mfa)} console users without MFA")
    return users_without_mfa


def check_access_analyzer(region="us-east-1"):
    """Check IAM Access Analyzer findings for external access."""
    aa = boto3.client("accessanalyzer", region_name=region)
    analyzers = aa.list_analyzers(Type="ACCOUNT")["analyzers"]
    if not analyzers:
        print("  [-] No Access Analyzer configured. Creating one...")
        aa.create_analyzer(analyzerName="account-analyzer", type="ACCOUNT")
        return []
    analyzer_arn = analyzers[0]["arn"]
    findings = aa.list_findings(analyzerArn=analyzer_arn,
                                 filter={"status": {"eq": ["ACTIVE"]}})["findings"]
    print(f"[*] Access Analyzer active findings: {len(findings)}")
    for f in findings[:10]:
        print(f"  [!] {f['resourceType']}: {f['resource']} - {f.get('condition', {})}")
    return findings


def generate_audit_report(stale_keys, overpriv_roles, no_mfa, aa_findings, output_path):
    """Generate a consolidated IAM audit report."""
    report = {
        "audit_date": datetime.now().isoformat(),
        "summary": {
            "stale_access_keys": len(stale_keys),
            "overprivileged_roles": len(overpriv_roles),
            "users_without_mfa": len(no_mfa),
            "access_analyzer_findings": len(aa_findings),
        },
        "stale_access_keys": stale_keys,
        "overprivileged_roles": overpriv_roles,
        "users_without_mfa": no_mfa,
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[*] Audit report saved to {output_path}")
    total = len(stale_keys) + len(overpriv_roles) + len(no_mfa) + len(aa_findings)
    print(f"[*] Total findings: {total}")


def main():
    parser = argparse.ArgumentParser(description="AWS IAM Security Audit Agent")
    parser.add_argument("action", choices=["full-audit", "stale-keys", "overpriv-roles", "mfa-check",
                                           "access-analyzer", "credential-report"])
    parser.add_argument("--max-key-age", type=int, default=90, help="Max access key age in days")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("-o", "--output", default="iam_audit_report.json")
    args = parser.parse_args()

    if args.action == "credential-report":
        get_credential_report()
    elif args.action == "stale-keys":
        find_stale_access_keys(args.max_key_age)
    elif args.action == "overpriv-roles":
        find_overprivileged_roles()
    elif args.action == "mfa-check":
        check_mfa_status()
    elif args.action == "access-analyzer":
        check_access_analyzer(args.region)
    elif args.action == "full-audit":
        print("[*] Running full IAM security audit...")
        stale = find_stale_access_keys(args.max_key_age)
        overpriv = find_overprivileged_roles()
        no_mfa = check_mfa_status()
        aa = check_access_analyzer(args.region)
        generate_audit_report(stale, overpriv, no_mfa, aa, args.output)


if __name__ == "__main__":
    main()
