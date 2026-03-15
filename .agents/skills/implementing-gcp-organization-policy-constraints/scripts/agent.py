#!/usr/bin/env python3
"""Agent for auditing and managing GCP Organization Policy constraints."""

import json
import argparse
import subprocess
from datetime import datetime


BASELINE_BOOLEAN_CONSTRAINTS = {
    "constraints/compute.vmExternalIpAccess": {"type": "list", "expected": "DENY_ALL"},
    "constraints/compute.requireOsLogin": {"type": "boolean", "expected": True},
    "constraints/compute.disableSerialPortAccess": {"type": "boolean", "expected": True},
    "constraints/compute.disableNestedVirtualization": {"type": "boolean", "expected": True},
    "constraints/storage.uniformBucketLevelAccess": {"type": "boolean", "expected": True},
    "constraints/sql.restrictPublicIp": {"type": "boolean", "expected": True},
    "constraints/iam.disableServiceAccountKeyCreation": {"type": "boolean", "expected": True},
    "constraints/iam.automaticIamGrantsForDefaultServiceAccounts": {"type": "boolean", "expected": True},
}


def run_gcloud(args_list):
    """Run a gcloud command and return parsed JSON."""
    cmd = ["gcloud"] + args_list + ["--format=json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        return {"error": result.stderr.strip()}
    try:
        return json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        return {"raw": result.stdout.strip()}


def list_org_policies(org_id):
    """List all active organization policies."""
    return run_gcloud(["org-policies", "list", f"--organization={org_id}"])


def describe_policy(org_id, constraint):
    """Get details of a specific org policy constraint."""
    return run_gcloud(["org-policies", "describe", constraint,
                       f"--organization={org_id}"])


def audit_baseline_compliance(org_id):
    """Audit organization against security baseline constraints."""
    findings = []
    for constraint, expected in BASELINE_BOOLEAN_CONSTRAINTS.items():
        policy = describe_policy(org_id, constraint)
        if isinstance(policy, dict) and "error" in policy:
            findings.append({
                "constraint": constraint,
                "status": "NOT_SET",
                "severity": "HIGH",
                "recommendation": f"Enable {constraint}",
            })
            continue
        if expected["type"] == "boolean":
            enforced = False
            if isinstance(policy, dict):
                bp = policy.get("booleanPolicy", {})
                enforced = bp.get("enforced", False)
            findings.append({
                "constraint": constraint,
                "status": "COMPLIANT" if enforced else "NON_COMPLIANT",
                "severity": "INFO" if enforced else "HIGH",
                "current": enforced,
                "expected": expected["expected"],
            })
        elif expected["type"] == "list":
            lp = policy.get("listPolicy", {}) if isinstance(policy, dict) else {}
            all_denied = lp.get("allValues") == "DENY" or lp.get("deniedValues") == ["*"]
            findings.append({
                "constraint": constraint,
                "status": "COMPLIANT" if all_denied else "NON_COMPLIANT",
                "severity": "INFO" if all_denied else "HIGH",
            })
    return findings


def audit_project_policies(project_id):
    """Audit organization policies effective on a specific project."""
    policies = run_gcloud(["org-policies", "list", f"--project={project_id}"])
    if isinstance(policies, dict) and "error" in policies:
        return [{"error": policies["error"]}]
    return policies if isinstance(policies, list) else []


def check_resource_location_constraint(org_id):
    """Check if resource location constraint is configured."""
    policy = describe_policy(org_id, "constraints/gcp.resourceLocations")
    if isinstance(policy, dict) and "error" not in policy:
        lp = policy.get("listPolicy", {})
        allowed = lp.get("allowedValues", [])
        if allowed:
            return {"status": "CONFIGURED", "allowed_locations": allowed}
    return {"status": "NOT_CONFIGURED", "severity": "MEDIUM",
            "recommendation": "Restrict resource locations to approved regions"}


def generate_terraform_policies(org_id, constraints=None):
    """Generate Terraform HCL for baseline org policies."""
    constraints = constraints or list(BASELINE_BOOLEAN_CONSTRAINTS.keys())
    tf_blocks = []
    for c in constraints:
        info = BASELINE_BOOLEAN_CONSTRAINTS.get(c, {"type": "boolean", "expected": True})
        resource_name = c.split("/")[1].replace(".", "_")
        if info["type"] == "boolean":
            tf_blocks.append(f'''resource "google_organization_policy" "{resource_name}" {{
  org_id     = "{org_id}"
  constraint = "{c}"
  boolean_policy {{
    enforced = true
  }}
}}''')
        elif info["type"] == "list":
            tf_blocks.append(f'''resource "google_organization_policy" "{resource_name}" {{
  org_id     = "{org_id}"
  constraint = "{c}"
  list_policy {{
    deny {{
      all = true
    }}
  }}
}}''')
    return "\n\n".join(tf_blocks)


def generate_compliance_report(findings):
    """Generate a compliance summary from audit findings."""
    total = len(findings)
    compliant = sum(1 for f in findings if f.get("status") == "COMPLIANT")
    non_compliant = sum(1 for f in findings if f.get("status") == "NON_COMPLIANT")
    not_set = sum(1 for f in findings if f.get("status") == "NOT_SET")
    return {
        "total_constraints": total,
        "compliant": compliant,
        "non_compliant": non_compliant,
        "not_set": not_set,
        "compliance_percentage": round(compliant / total * 100, 1) if total else 0,
        "high_severity_gaps": [f for f in findings if f.get("severity") == "HIGH"],
    }


def main():
    parser = argparse.ArgumentParser(description="GCP Organization Policy Agent")
    parser.add_argument("--org-id", help="GCP organization ID")
    parser.add_argument("--project", help="GCP project ID for project-level audit")
    parser.add_argument("--action", choices=["audit", "list", "terraform", "locations"],
                        default="audit")
    parser.add_argument("--output", default="gcp_orgpolicy_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}

    if args.action == "audit" and args.org_id:
        findings = audit_baseline_compliance(args.org_id)
        summary = generate_compliance_report(findings)
        report["results"]["findings"] = findings
        report["results"]["summary"] = summary
        print(f"[+] Compliance: {summary['compliance_percentage']}%"
              f" ({summary['compliant']}/{summary['total_constraints']})")

    elif args.action == "list" and args.org_id:
        policies = list_org_policies(args.org_id)
        report["results"]["policies"] = policies
        count = len(policies) if isinstance(policies, list) else 0
        print(f"[+] Active policies: {count}")

    elif args.action == "terraform" and args.org_id:
        tf = generate_terraform_policies(args.org_id)
        report["results"]["terraform"] = tf
        print("[+] Terraform configuration generated")

    elif args.action == "locations" and args.org_id:
        result = check_resource_location_constraint(args.org_id)
        report["results"]["location_constraint"] = result
        print(f"[+] Location constraint: {result['status']}")

    if args.project:
        project_policies = audit_project_policies(args.project)
        report["results"]["project_policies"] = project_policies
        print(f"[+] Project {args.project}: {len(project_policies)} policies")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
