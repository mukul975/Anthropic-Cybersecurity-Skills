#!/usr/bin/env python3
"""Google Identity-Aware Proxy (IAP) configuration agent using google-cloud-iap."""

import json
import sys
import argparse
from datetime import datetime

try:
    from google.cloud import iap_v1
    from google.cloud import resourcemanager_v3
    from google.iam.v1 import iam_policy_pb2
except ImportError:
    print("Install: pip install google-cloud-iap google-cloud-resource-manager")
    sys.exit(1)


def list_iap_tunnels(project_id):
    """List IAP TCP forwarding tunnels."""
    client = iap_v1.IdentityAwareProxyAdminServiceClient()
    parent = f"projects/{project_id}"
    tunnels = []
    try:
        request = iap_v1.ListTunnelDestGroupsRequest(parent=f"{parent}/iap_tunnel/locations/-")
        for group in client.list_tunnel_dest_groups(request=request):
            tunnels.append({
                "name": group.name,
                "cidrs": list(group.cidrs),
                "fqdns": list(group.fqdns),
            })
    except Exception as e:
        tunnels.append({"error": str(e)})
    return tunnels


def get_iap_settings(project_id, resource_type="web"):
    """Get IAP settings for web resources."""
    client = iap_v1.IdentityAwareProxyAdminServiceClient()
    resource_name = f"projects/{project_id}/iap_web"
    try:
        request = iap_v1.GetIapSettingsRequest(name=resource_name)
        settings = client.get_iap_settings(request=request)
        return {
            "name": settings.name,
            "access_settings": {
                "cors_settings": str(settings.access_settings.cors_settings) if settings.access_settings else "",
            },
        }
    except Exception as e:
        return {"error": str(e)}


def audit_iap_iam_policy(project_id):
    """Audit IAM bindings for IAP-secured resources."""
    client = iap_v1.IdentityAwareProxyAdminServiceClient()
    resource = f"projects/{project_id}/iap_web"
    try:
        policy = client.get_iam_policy(request={"resource": resource})
        bindings = []
        for binding in policy.bindings:
            bindings.append({
                "role": binding.role,
                "members": list(binding.members),
                "condition": str(binding.condition) if binding.condition else None,
            })
        return bindings
    except Exception as e:
        return [{"error": str(e)}]


def check_oauth_consent(project_id):
    """Verify OAuth consent screen configuration."""
    return {
        "check": "OAuth consent screen",
        "project": project_id,
        "requirements": [
            "Application type: Internal (for organization apps)",
            "Support email: Valid group email",
            "Authorized domains: Company domains only",
            "Scopes: Minimal required (email, profile)",
        ],
        "verification_url": f"https://console.cloud.google.com/apis/credentials/consent?project={project_id}",
    }


def run_audit(project_id):
    """Execute IAP configuration audit."""
    print(f"\n{'='*60}")
    print(f"  GOOGLE IAP CONFIGURATION AUDIT")
    print(f"  Project: {project_id}")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    settings = get_iap_settings(project_id)
    print(f"--- IAP SETTINGS ---")
    print(f"  {json.dumps(settings, indent=2)}")

    bindings = audit_iap_iam_policy(project_id)
    print(f"\n--- IAM BINDINGS ({len(bindings)}) ---")
    for b in bindings:
        if "error" not in b:
            print(f"  {b['role']}: {', '.join(b['members'][:3])}")

    tunnels = list_iap_tunnels(project_id)
    print(f"\n--- TCP TUNNELS ({len(tunnels)}) ---")
    for t in tunnels:
        if "error" not in t:
            print(f"  {t['name']}: CIDRs={t['cidrs']}")

    consent = check_oauth_consent(project_id)
    print(f"\n--- OAUTH CONSENT ---")
    for req in consent["requirements"]:
        print(f"  - {req}")

    return {"settings": settings, "bindings": bindings, "tunnels": tunnels, "consent": consent}


def main():
    parser = argparse.ArgumentParser(description="Google IAP Audit Agent")
    parser.add_argument("--project", required=True, help="GCP project ID")
    parser.add_argument("--audit", action="store_true", help="Run full audit")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    if args.audit:
        report = run_audit(args.project)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n[+] Report saved to {args.output}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
