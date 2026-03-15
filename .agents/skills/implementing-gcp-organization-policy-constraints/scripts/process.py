#!/usr/bin/env python3
"""
GCP Organization Policy Constraints Management Script

Automates auditing, deploying, and monitoring organization policies
across a GCP organization hierarchy.
"""

import json
import subprocess
import sys
from datetime import datetime


SECURITY_CONSTRAINTS = {
    "compute.vmExternalIpAccess": {
        "type": "list",
        "action": "deny_all",
        "description": "Deny external IP addresses on VMs"
    },
    "compute.requireOsLogin": {
        "type": "boolean",
        "enforced": True,
        "description": "Require OS Login for SSH access"
    },
    "compute.disableSerialPortAccess": {
        "type": "boolean",
        "enforced": True,
        "description": "Disable serial port access on VMs"
    },
    "iam.disableServiceAccountKeyCreation": {
        "type": "boolean",
        "enforced": True,
        "description": "Disable service account key creation"
    },
    "storage.uniformBucketLevelAccess": {
        "type": "boolean",
        "enforced": True,
        "description": "Enforce uniform bucket-level access"
    },
    "sql.restrictPublicIp": {
        "type": "boolean",
        "enforced": True,
        "description": "Restrict public IP on Cloud SQL"
    },
    "gcp.resourceLocations": {
        "type": "list",
        "action": "allow",
        "values": ["in:us-locations", "in:eu-locations"],
        "description": "Restrict resource locations to US and EU"
    },
    "compute.disableNestedVirtualization": {
        "type": "boolean",
        "enforced": True,
        "description": "Disable nested virtualization"
    }
}


def run_gcloud(args):
    """Execute a gcloud command and return output."""
    cmd = ["gcloud"] + args + ["--format=json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None, result.stderr
    try:
        return json.loads(result.stdout) if result.stdout.strip() else {}, None
    except json.JSONDecodeError:
        return result.stdout, None


def audit_org_policies(org_id):
    """Audit current organization policies and identify gaps."""
    print(f"[*] Auditing organization policies for org: {org_id}")

    results, err = run_gcloud([
        "org-policies", "list",
        f"--organization={org_id}"
    ])

    if err:
        print(f"[!] Error listing policies: {err}")
        return None

    active_constraints = set()
    if isinstance(results, list):
        for policy in results:
            constraint = policy.get("constraint", "")
            active_constraints.add(constraint.replace("constraints/", ""))

    print(f"\n[+] Active organization policies: {len(active_constraints)}")

    # Check against recommended baseline
    missing = []
    present = []
    for constraint in SECURITY_CONSTRAINTS:
        if constraint in active_constraints:
            present.append(constraint)
            print(f"  [OK] {constraint}: {SECURITY_CONSTRAINTS[constraint]['description']}")
        else:
            missing.append(constraint)
            print(f"  [MISSING] {constraint}: {SECURITY_CONSTRAINTS[constraint]['description']}")

    return {
        "active": list(active_constraints),
        "baseline_present": present,
        "baseline_missing": missing,
        "compliance_score": len(present) / len(SECURITY_CONSTRAINTS) * 100
    }


def generate_policy_yaml(constraint_name, config, dry_run=False):
    """Generate YAML policy definition for a constraint."""
    import yaml

    policy = {"constraint": f"constraints/{constraint_name}"}

    if config["type"] == "boolean":
        policy["booleanPolicy"] = {"enforced": config["enforced"]}
    elif config["type"] == "list":
        if config.get("action") == "deny_all":
            policy["listPolicy"] = {"allValues": "DENY"}
        elif config.get("action") == "allow":
            policy["listPolicy"] = {"allowedValues": config["values"]}

    if dry_run:
        policy["dryRunSpec"] = True

    return yaml.dump(policy, default_flow_style=False)


def deploy_baseline_policies(org_id, dry_run=True):
    """Deploy baseline organization policies."""
    mode = "dry-run" if dry_run else "enforced"
    print(f"\n[*] Deploying baseline policies in {mode} mode for org: {org_id}")

    for constraint, config in SECURITY_CONSTRAINTS.items():
        print(f"\n  Deploying: {constraint}")
        print(f"  Description: {config['description']}")

        # Generate policy file
        import tempfile
        policy_yaml = generate_policy_yaml(constraint, config, dry_run)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, prefix=f"policy_{constraint}_"
        ) as f:
            f.write(policy_yaml)
            policy_file = f.name

        # Apply policy
        _, err = run_gcloud([
            "org-policies", "set-policy",
            f"--organization={org_id}",
            policy_file
        ])

        if err:
            print(f"  [FAIL] Error applying {constraint}: {err}")
        else:
            print(f"  [OK] Successfully applied {constraint}")


def check_policy_violations(org_id, constraint_name):
    """Check for resources violating a specific policy."""
    print(f"\n[*] Checking violations for: {constraint_name}")

    results, err = run_gcloud([
        "asset", "search-all-resources",
        f"--scope=organizations/{org_id}",
        f"--query=policy:constraints/{constraint_name}"
    ])

    if err:
        print(f"[!] Error checking violations: {err}")
        return []

    if isinstance(results, list):
        print(f"[+] Found {len(results)} potentially affected resources")
        for resource in results[:10]:
            print(f"  - {resource.get('name', 'unknown')}")
        return results

    return []


def generate_compliance_report(audit_results, org_id):
    """Generate a compliance report for organization policies."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = f"""
{'='*60}
GCP Organization Policy Compliance Report
Organization: {org_id}
Generated: {timestamp}
{'='*60}

Compliance Score: {audit_results['compliance_score']:.1f}%

Baseline Policies Present ({len(audit_results['baseline_present'])}):
"""
    for p in audit_results['baseline_present']:
        report += f"  [PASS] {p}\n"

    report += f"\nBaseline Policies Missing ({len(audit_results['baseline_missing'])}):\n"
    for m in audit_results['baseline_missing']:
        report += f"  [FAIL] {m} - {SECURITY_CONSTRAINTS[m]['description']}\n"

    report += f"\nTotal Active Policies: {len(audit_results['active'])}\n"
    report += f"\nRecommendation: {'Compliant' if audit_results['compliance_score'] >= 80 else 'Remediation Required'}\n"

    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="GCP Organization Policy Management")
    parser.add_argument("--org-id", required=True, help="GCP Organization ID")
    parser.add_argument("--audit", action="store_true", help="Audit existing policies")
    parser.add_argument("--deploy", action="store_true", help="Deploy baseline policies")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Deploy in dry-run mode")
    parser.add_argument("--enforce", action="store_true", help="Deploy in enforced mode")
    parser.add_argument("--check-violations", type=str, help="Check violations for a constraint")

    args = parser.parse_args()

    if args.audit:
        results = audit_org_policies(args.org_id)
        if results:
            report = generate_compliance_report(results, args.org_id)
            print(report)

    if args.deploy:
        dry_run = not args.enforce
        deploy_baseline_policies(args.org_id, dry_run=dry_run)

    if args.check_violations:
        check_policy_violations(args.org_id, args.check_violations)
