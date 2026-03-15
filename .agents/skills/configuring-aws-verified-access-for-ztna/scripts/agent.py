#!/usr/bin/env python3
"""AWS Verified Access ZTNA configuration agent using boto3."""

import json
import sys
import argparse
from datetime import datetime

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("Install: pip install boto3")
    sys.exit(1)


def list_verified_access_instances(session):
    """List all Verified Access instances."""
    ec2 = session.client("ec2")
    response = ec2.describe_verified_access_instances()
    instances = []
    for inst in response.get("VerifiedAccessInstances", []):
        instances.append({
            "id": inst["VerifiedAccessInstanceId"],
            "description": inst.get("Description", ""),
            "creation_time": str(inst.get("CreationTime", "")),
            "trust_providers": [tp["VerifiedAccessTrustProviderId"]
                                for tp in inst.get("VerifiedAccessTrustProviders", [])],
        })
    return instances


def list_verified_access_groups(session):
    """List Verified Access groups and their policies."""
    ec2 = session.client("ec2")
    response = ec2.describe_verified_access_groups()
    groups = []
    for grp in response.get("VerifiedAccessGroups", []):
        groups.append({
            "id": grp["VerifiedAccessGroupId"],
            "instance_id": grp.get("VerifiedAccessInstanceId", ""),
            "description": grp.get("Description", ""),
            "policy_enabled": grp.get("PolicyEnabled", False),
            "policy_document": grp.get("PolicyDocument", ""),
        })
    return groups


def list_verified_access_endpoints(session):
    """List Verified Access endpoints."""
    ec2 = session.client("ec2")
    response = ec2.describe_verified_access_endpoints()
    endpoints = []
    for ep in response.get("VerifiedAccessEndpoints", []):
        endpoints.append({
            "id": ep["VerifiedAccessEndpointId"],
            "group_id": ep.get("VerifiedAccessGroupId", ""),
            "type": ep.get("EndpointType", ""),
            "domain": ep.get("DomainCertificateArn", ""),
            "status": ep.get("Status", {}).get("Code", ""),
            "application_domain": ep.get("ApplicationDomain", ""),
        })
    return endpoints


def audit_trust_providers(session):
    """Audit Verified Access trust providers."""
    ec2 = session.client("ec2")
    response = ec2.describe_verified_access_trust_providers()
    providers = []
    for tp in response.get("VerifiedAccessTrustProviders", []):
        providers.append({
            "id": tp["VerifiedAccessTrustProviderId"],
            "type": tp.get("TrustProviderType", ""),
            "user_trust_type": tp.get("UserTrustProviderType", ""),
            "device_trust_type": tp.get("DeviceTrustProviderType", ""),
            "policy_reference": tp.get("PolicyReferenceName", ""),
        })
    return providers


def run_audit(profile=None, region="us-east-1"):
    """Execute AWS Verified Access audit."""
    session = boto3.Session(profile_name=profile, region_name=region)
    print(f"\n{'='*60}")
    print(f"  AWS VERIFIED ACCESS ZTNA AUDIT")
    print(f"  Region: {region}")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    instances = list_verified_access_instances(session)
    print(f"--- INSTANCES ({len(instances)}) ---")
    for i in instances:
        print(f"  {i['id']}: {i['description']} (providers: {len(i['trust_providers'])})")

    providers = audit_trust_providers(session)
    print(f"\n--- TRUST PROVIDERS ({len(providers)}) ---")
    for p in providers:
        print(f"  {p['id']}: type={p['type']} user={p['user_trust_type']} device={p['device_trust_type']}")

    groups = list_verified_access_groups(session)
    print(f"\n--- GROUPS ({len(groups)}) ---")
    for g in groups:
        status = "ENABLED" if g["policy_enabled"] else "DISABLED"
        print(f"  {g['id']}: policy={status}")

    endpoints = list_verified_access_endpoints(session)
    print(f"\n--- ENDPOINTS ({len(endpoints)}) ---")
    for e in endpoints:
        print(f"  {e['id']}: {e['application_domain']} ({e['status']})")

    return {"instances": instances, "providers": providers, "groups": groups, "endpoints": endpoints}


def main():
    parser = argparse.ArgumentParser(description="AWS Verified Access ZTNA Agent")
    parser.add_argument("--profile", help="AWS CLI profile")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--audit", action="store_true", help="Run full audit")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    if args.audit:
        report = run_audit(args.profile, args.region)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n[+] Report saved to {args.output}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
