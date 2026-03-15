#!/usr/bin/env python3
"""Microsegmentation audit agent for zero trust network enforcement."""

import json
import sys
import argparse
from datetime import datetime

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


def audit_aws_security_groups(session):
    """Audit AWS security groups for microsegmentation compliance."""
    import boto3
    ec2 = session.client("ec2")
    findings = []
    for sg in ec2.describe_security_groups()["SecurityGroups"]:
        for rule in sg.get("IpPermissions", []):
            for ip_range in rule.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "")
                if cidr == "0.0.0.0/0":
                    findings.append({
                        "sg_id": sg["GroupId"],
                        "sg_name": sg.get("GroupName", ""),
                        "port": rule.get("FromPort", "all"),
                        "cidr": cidr,
                        "severity": "HIGH",
                        "recommendation": "Restrict to specific CIDR blocks",
                    })
                elif "/" in cidr:
                    prefix = int(cidr.split("/")[1])
                    if prefix < 24:
                        findings.append({
                            "sg_id": sg["GroupId"],
                            "sg_name": sg.get("GroupName", ""),
                            "port": rule.get("FromPort", "all"),
                            "cidr": cidr,
                            "severity": "MEDIUM",
                            "recommendation": f"Narrow CIDR from /{prefix} to /32 or workload-specific range",
                        })
    return findings


def check_illumio_workloads(base_url, api_key, org_id):
    """Check Illumio workload segmentation status."""
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        resp = requests.get(f"{base_url}/api/v2/orgs/{org_id}/workloads",
                            headers=headers, verify=False)
        resp.raise_for_status()
        workloads = resp.json()
        return [{
            "hostname": w.get("hostname", ""),
            "enforcement_mode": w.get("enforcement_mode", ""),
            "visibility_level": w.get("visibility_level", ""),
            "online": w.get("online", False),
        } for w in workloads[:20]]
    except Exception as e:
        return [{"error": str(e)}]


def generate_segmentation_policy(app_tiers):
    """Generate microsegmentation policy recommendations."""
    policies = []
    for tier in app_tiers:
        policies.append({
            "tier": tier["name"],
            "allowed_inbound": tier.get("inbound_from", []),
            "allowed_ports": tier.get("ports", []),
            "deny_default": True,
            "enforcement": "block",
        })
    return {
        "principle": "Zero Trust — deny all, allow by exception",
        "policies": policies,
        "example_tiers": [
            {"name": "web", "inbound_from": ["load-balancer"], "ports": [443]},
            {"name": "app", "inbound_from": ["web"], "ports": [8080]},
            {"name": "db", "inbound_from": ["app"], "ports": [5432]},
        ],
    }


def run_audit(profile=None, region="us-east-1"):
    """Execute microsegmentation audit."""
    import boto3
    session = boto3.Session(profile_name=profile, region_name=region)
    print(f"\n{'='*60}")
    print(f"  MICROSEGMENTATION ZERO TRUST AUDIT")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    sg_findings = audit_aws_security_groups(session)
    print(f"--- SECURITY GROUP FINDINGS ({len(sg_findings)}) ---")
    for f in sg_findings[:15]:
        print(f"  [{f['severity']}] {f['sg_id']} ({f['sg_name']}): port {f['port']} from {f['cidr']}")

    policy = generate_segmentation_policy([])
    print(f"\n--- RECOMMENDED SEGMENTATION MODEL ---")
    print(f"  Principle: {policy['principle']}")
    for tier in policy["example_tiers"]:
        print(f"  {tier['name']}: allow from {tier['inbound_from']} on ports {tier['ports']}")

    return {"sg_findings": sg_findings, "policy": policy}


def main():
    parser = argparse.ArgumentParser(description="Microsegmentation Audit Agent")
    parser.add_argument("--profile", help="AWS CLI profile")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--audit", action="store_true", help="Run audit")
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
