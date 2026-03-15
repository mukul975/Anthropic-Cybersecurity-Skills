#!/usr/bin/env python3
"""Agent for auditing GCP IAM permissions using google-cloud libraries."""

import os
import json
import argparse
from datetime import datetime

from google.cloud import asset_v1
from google.cloud import resourcemanager_v3
from google.iam.v1 import iam_policy_pb2


def search_iam_policies(scope, query=""):
    """Search IAM policies across the GCP organization."""
    client = asset_v1.AssetServiceClient()
    request = asset_v1.SearchAllIamPoliciesRequest(scope=scope, query=query, page_size=500)
    results = []
    for result in client.search_all_iam_policies(request=request):
        for binding in result.policy.bindings:
            results.append({
                "resource": result.resource,
                "role": binding.role,
                "members": list(binding.members),
            })
    return results


def find_primitive_roles(scope):
    """Find all IAM bindings using primitive roles (Owner, Editor)."""
    query = "policy:roles/owner OR policy:roles/editor"
    return search_iam_policies(scope, query)


def find_public_bindings(scope):
    """Find resources accessible to allUsers or allAuthenticatedUsers."""
    query = "policy:allUsers OR policy:allAuthenticatedUsers"
    return search_iam_policies(scope, query)


def list_service_accounts(project_id):
    """List all service accounts in a project with key info."""
    from google.cloud import iam_admin_v1
    client = iam_admin_v1.IAMClient()
    request = iam_admin_v1.ListServiceAccountsRequest(name=f"projects/{project_id}")
    accounts = []
    for sa in client.list_service_accounts(request=request):
        sa_info = {
            "email": sa.email,
            "display_name": sa.display_name,
            "disabled": sa.disabled,
            "user_managed_keys": [],
        }
        key_request = iam_admin_v1.ListServiceAccountKeysRequest(
            name=sa.name,
            key_types=[iam_admin_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED],
        )
        keys = client.list_service_account_keys(request=key_request)
        for key in keys.keys:
            sa_info["user_managed_keys"].append({
                "name": key.name.split("/")[-1],
                "valid_after": str(key.valid_after_time),
                "valid_before": str(key.valid_before_time),
            })
        accounts.append(sa_info)
    return accounts


def get_project_iam_policy(project_id):
    """Get IAM policy for a specific project."""
    client = resourcemanager_v3.ProjectsClient()
    request = {"resource": f"projects/{project_id}"}
    policy = client.get_iam_policy(request=request)
    bindings = []
    for binding in policy.bindings:
        bindings.append({"role": binding.role, "members": list(binding.members)})
    return bindings


def analyze_permissions(scope, identity):
    """Analyze what resources an identity can access."""
    client = asset_v1.AssetServiceClient()
    request = asset_v1.AnalyzeIamPolicyRequest(
        analysis_query=asset_v1.IamPolicyAnalysisQuery(
            scope=scope,
            identity_selector=asset_v1.IamPolicyAnalysisQuery.IdentitySelector(
                identity=identity
            ),
        )
    )
    response = client.analyze_iam_policy(request=request)
    results = []
    for entry in response.main_analysis.analysis_results:
        for acl in entry.access_control_lists:
            resources = [r.full_resource_name for r in acl.resources]
            accesses = [a.role for a in acl.accesses]
            results.append({"resources": resources, "roles": accesses})
    return results


def classify_risk(bindings):
    """Classify risk for IAM bindings."""
    critical = []
    high = []
    for b in bindings:
        role = b.get("role", "")
        members = b.get("members", [])
        if "allUsers" in members or "allAuthenticatedUsers" in members:
            critical.append(b)
        elif role in ("roles/owner", "roles/editor"):
            for m in members:
                if "serviceAccount" in m:
                    critical.append(b)
                    break
            else:
                high.append(b)
    return {"critical": critical, "high": high}


def main():
    parser = argparse.ArgumentParser(description="GCP IAM Permissions Audit Agent")
    parser.add_argument("--org-id", help="GCP Organization ID")
    parser.add_argument("--project-id", help="GCP Project ID")
    parser.add_argument("--identity", help="Identity to analyze (user:email or serviceAccount:email)")
    parser.add_argument("--output", default="gcp_iam_audit.json")
    parser.add_argument("--action", choices=[
        "primitive_roles", "public_access", "service_accounts",
        "analyze_identity", "full_audit"
    ], default="full_audit")
    args = parser.parse_args()

    scope = f"organizations/{args.org_id}" if args.org_id else f"projects/{args.project_id}"
    report = {"audit_date": datetime.utcnow().isoformat(), "scope": scope, "findings": {}}

    if args.action in ("primitive_roles", "full_audit"):
        primitives = find_primitive_roles(scope)
        report["findings"]["primitive_roles"] = primitives
        print(f"[+] Primitive role bindings: {len(primitives)}")

    if args.action in ("public_access", "full_audit"):
        public = find_public_bindings(scope)
        report["findings"]["public_access"] = public
        print(f"[+] Public access bindings: {len(public)}")

    if args.action in ("service_accounts", "full_audit") and args.project_id:
        sas = list_service_accounts(args.project_id)
        report["findings"]["service_accounts"] = sas
        keys_count = sum(len(sa["user_managed_keys"]) for sa in sas)
        print(f"[+] Service accounts: {len(sas)}, user-managed keys: {keys_count}")

    if args.action == "analyze_identity" and args.identity:
        access = analyze_permissions(scope, args.identity)
        report["findings"]["identity_access"] = access
        print(f"[+] Resources accessible by {args.identity}: {len(access)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
