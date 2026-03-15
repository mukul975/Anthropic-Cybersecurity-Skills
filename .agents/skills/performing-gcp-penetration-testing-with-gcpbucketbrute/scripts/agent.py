#!/usr/bin/env python3
"""GCP penetration testing agent: bucket enumeration, IAM audit, privilege escalation analysis.
# For authorized testing only
"""

import json
import subprocess
import argparse
import itertools
from datetime import datetime

BUCKET_PERMUTATIONS = [
    "{keyword}", "{keyword}-dev", "{keyword}-staging", "{keyword}-prod",
    "{keyword}-backup", "{keyword}-data", "{keyword}-logs", "{keyword}-assets",
    "{keyword}-uploads", "{keyword}-internal", "{keyword}-private", "{keyword}-public",
    "dev-{keyword}", "staging-{keyword}", "prod-{keyword}", "backup-{keyword}",
]

PRIV_ESC_PERMISSIONS = [
    "iam.serviceAccounts.actAs",
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.implicitDelegation",
    "iam.serviceAccounts.signBlob",
    "iam.serviceAccounts.signJwt",
    "iam.serviceAccountKeys.create",
    "resourcemanager.projects.setIamPolicy",
    "deploymentmanager.deployments.create",
    "cloudfunctions.functions.create",
    "cloudfunctions.functions.update",
    "compute.instances.create",
    "run.services.create",
]


def generate_bucket_names(keyword):
    """Generate bucket name permutations from a keyword."""
    return [perm.format(keyword=keyword) for perm in BUCKET_PERMUTATIONS]


def check_bucket_exists(bucket_name):
    """Check if a GCS bucket exists and test access permissions."""
    result = subprocess.run(
        ["gsutil", "ls", f"gs://{bucket_name}/"],
        capture_output=True, text=True, timeout=15
    )
    if result.returncode == 0:
        return {"exists": True, "accessible": True, "listing": result.stdout[:500]}
    if "AccessDeniedException" in result.stderr:
        return {"exists": True, "accessible": False, "error": "Access denied"}
    return {"exists": False, "accessible": False}


def test_bucket_permissions(bucket_name):
    """Test IAM permissions on a discovered bucket using gsutil."""
    permissions_to_test = [
        "storage.objects.list", "storage.objects.get", "storage.objects.create",
        "storage.objects.delete", "storage.buckets.getIamPolicy",
        "storage.buckets.setIamPolicy",
    ]
    result = subprocess.run(
        ["gcloud", "storage", "buckets", "get-iam-policy", f"gs://{bucket_name}",
         "--format=json"],
        capture_output=True, text=True, timeout=15
    )
    granted = []
    if result.returncode == 0:
        try:
            policy = json.loads(result.stdout)
            for binding in policy.get("bindings", []):
                if "allUsers" in binding.get("members", []) or "allAuthenticatedUsers" in binding.get("members", []):
                    granted.append({
                        "role": binding["role"],
                        "members": binding["members"],
                        "severity": "critical",
                    })
        except json.JSONDecodeError:
            pass
    return {"bucket": bucket_name, "public_bindings": granted}


def enumerate_iam_bindings(project_id):
    """Enumerate project-level IAM bindings for overly permissive roles."""
    result = subprocess.run(
        ["gcloud", "projects", "get-iam-policy", project_id, "--format=json"],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
        return {"error": result.stderr[:200]}
    policy = json.loads(result.stdout)
    findings = []
    risky_roles = {"roles/owner", "roles/editor", "roles/iam.securityAdmin",
                   "roles/iam.serviceAccountAdmin", "roles/storage.admin"}
    for binding in policy.get("bindings", []):
        if binding["role"] in risky_roles:
            findings.append({
                "role": binding["role"],
                "members": binding["members"],
                "member_count": len(binding["members"]),
                "severity": "high",
                "finding": "Overly permissive role binding",
            })
    return {"project": project_id, "risky_bindings": findings}


def check_service_account_keys(project_id):
    """Check for user-managed service account keys."""
    result = subprocess.run(
        ["gcloud", "iam", "service-accounts", "list",
         "--project", project_id, "--format=json"],
        capture_output=True, text=True, timeout=20
    )
    if result.returncode != 0:
        return {"error": result.stderr[:200]}
    accounts = json.loads(result.stdout)
    findings = []
    for sa in accounts:
        email = sa.get("email", "")
        keys_result = subprocess.run(
            ["gcloud", "iam", "service-accounts", "keys", "list",
             "--iam-account", email, "--format=json", "--managed-by=user"],
            capture_output=True, text=True, timeout=15
        )
        if keys_result.returncode == 0:
            keys = json.loads(keys_result.stdout)
            if keys:
                findings.append({
                    "service_account": email,
                    "user_managed_keys": len(keys),
                    "severity": "high",
                    "finding": "User-managed keys found (potential for key theft)",
                })
    return {"service_account_findings": findings}


def check_priv_esc_paths(project_id):
    """Check testable IAM permissions for privilege escalation vectors."""
    result = subprocess.run(
        ["gcloud", "projects", "get-iam-policy", project_id, "--format=json"],
        capture_output=True, text=True, timeout=20
    )
    if result.returncode != 0:
        return []
    policy = json.loads(result.stdout)
    esc_findings = []
    for binding in policy.get("bindings", []):
        role = binding["role"]
        role_result = subprocess.run(
            ["gcloud", "iam", "roles", "describe", role, "--format=json"],
            capture_output=True, text=True, timeout=10
        )
        if role_result.returncode == 0:
            role_info = json.loads(role_result.stdout)
            perms = set(role_info.get("includedPermissions", []))
            esc_perms = perms.intersection(PRIV_ESC_PERMISSIONS)
            if esc_perms:
                esc_findings.append({
                    "role": role,
                    "members": binding["members"],
                    "escalation_permissions": list(esc_perms),
                    "severity": "critical",
                })
    return esc_findings


def generate_report(buckets, iam_findings, sa_findings, esc_paths, keyword, project_id):
    """Generate GCP penetration test findings report."""
    return {
        "report_time": datetime.utcnow().isoformat(),
        "target_keyword": keyword,
        "target_project": project_id,
        "bucket_enumeration": buckets,
        "iam_audit": iam_findings,
        "service_account_audit": sa_findings,
        "privilege_escalation_paths": esc_paths,
        "total_findings": (
            len([b for b in buckets if b.get("exists")]) +
            len(iam_findings.get("risky_bindings", [])) +
            len(sa_findings.get("service_account_findings", [])) +
            len(esc_paths)
        ),
    }


def main():
    parser = argparse.ArgumentParser(description="GCP Penetration Testing Agent")
    parser.add_argument("--keyword", required=True, help="Keyword for bucket name permutation")
    parser.add_argument("--project", help="GCP project ID for IAM audit")
    parser.add_argument("--output", default="gcp_pentest_report.json")
    parser.add_argument("--skip-buckets", action="store_true", help="Skip bucket enumeration")
    args = parser.parse_args()

    buckets = []
    if not args.skip_buckets:
        names = generate_bucket_names(args.keyword)
        print(f"[*] Testing {len(names)} bucket permutations for '{args.keyword}'")
        for name in names:
            status = check_bucket_exists(name)
            if status["exists"]:
                perms = test_bucket_permissions(name)
                status.update(perms)
                buckets.append({"name": name, **status})
                print(f"  [!] Found: gs://{name} (accessible={status['accessible']})")

    iam_findings, sa_findings, esc_paths = {}, {}, []
    if args.project:
        print(f"[*] Auditing IAM for project: {args.project}")
        iam_findings = enumerate_iam_bindings(args.project)
        sa_findings = check_service_account_keys(args.project)
        esc_paths = check_priv_esc_paths(args.project)

    report = generate_report(buckets, iam_findings, sa_findings, esc_paths, args.keyword, args.project)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output} ({report['total_findings']} findings)")


if __name__ == "__main__":
    main()
