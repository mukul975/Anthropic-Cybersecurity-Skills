#!/usr/bin/env python3
"""
Kubernetes RBAC Audit and Hardening Tool

Audits RBAC configurations to identify overprivileged accounts,
cluster-admin sprawl, default service account usage, and
generates hardening recommendations.
"""

import json
import subprocess
import sys
import argparse
from datetime import datetime
from collections import defaultdict


DANGEROUS_VERBS = {"*", "create", "update", "patch", "delete"}
DANGEROUS_RESOURCES = {
    "secrets", "pods/exec", "clusterroles", "clusterrolebindings",
    "roles", "rolebindings", "serviceaccounts/token", "nodes/proxy"
}
DANGEROUS_API_GROUPS = {"*"}


def run_kubectl(args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["kubectl"] + args, capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def get_cluster_role_bindings() -> list[dict]:
    output = run_kubectl(["get", "clusterrolebindings", "-o", "json"])
    if not output:
        return []
    try:
        return json.loads(output).get("items", [])
    except json.JSONDecodeError:
        return []


def get_role_bindings() -> list[dict]:
    output = run_kubectl(["get", "rolebindings", "--all-namespaces", "-o", "json"])
    if not output:
        return []
    try:
        return json.loads(output).get("items", [])
    except json.JSONDecodeError:
        return []


def get_cluster_roles() -> dict:
    output = run_kubectl(["get", "clusterroles", "-o", "json"])
    if not output:
        return {}
    try:
        items = json.loads(output).get("items", [])
        return {item["metadata"]["name"]: item.get("rules", []) for item in items}
    except json.JSONDecodeError:
        return {}


def audit_cluster_admin_bindings(crbs: list[dict]) -> list[dict]:
    findings = []
    for crb in crbs:
        if crb.get("roleRef", {}).get("name") == "cluster-admin":
            for subject in crb.get("subjects", []):
                findings.append({
                    "severity": "CRITICAL",
                    "type": "cluster_admin_binding",
                    "binding": crb["metadata"]["name"],
                    "subject_kind": subject.get("kind", ""),
                    "subject_name": subject.get("name", ""),
                    "subject_namespace": subject.get("namespace", ""),
                    "description": f"cluster-admin bound to {subject.get('kind', '')}/{subject.get('name', '')}"
                })
    return findings


def audit_wildcard_permissions(roles: dict) -> list[dict]:
    findings = []
    for role_name, rules in roles.items():
        for rule in rules:
            verbs = rule.get("verbs", [])
            resources = rule.get("resources", [])
            api_groups = rule.get("apiGroups", [])

            if "*" in verbs and "*" in resources:
                findings.append({
                    "severity": "HIGH",
                    "type": "wildcard_permissions",
                    "role": role_name,
                    "description": f"ClusterRole {role_name} has wildcard verbs and resources"
                })
            elif "*" in verbs:
                findings.append({
                    "severity": "MEDIUM",
                    "type": "wildcard_verbs",
                    "role": role_name,
                    "resources": resources,
                    "description": f"ClusterRole {role_name} has wildcard verbs on {resources}"
                })
    return findings


def audit_dangerous_permissions(roles: dict) -> list[dict]:
    findings = []
    for role_name, rules in roles.items():
        for rule in rules:
            verbs = set(rule.get("verbs", []))
            resources = set(rule.get("resources", []))
            dangerous_matches = resources.intersection(DANGEROUS_RESOURCES)
            has_dangerous_verbs = verbs.intersection(DANGEROUS_VERBS)

            if dangerous_matches and has_dangerous_verbs:
                findings.append({
                    "severity": "HIGH",
                    "type": "dangerous_permission",
                    "role": role_name,
                    "resources": list(dangerous_matches),
                    "verbs": list(has_dangerous_verbs),
                    "description": f"ClusterRole {role_name} grants {list(has_dangerous_verbs)} on {list(dangerous_matches)}"
                })
    return findings


def audit_default_service_accounts(rbs: list[dict], crbs: list[dict]) -> list[dict]:
    findings = []
    for binding in rbs + crbs:
        for subject in binding.get("subjects", []):
            if subject.get("kind") == "ServiceAccount" and subject.get("name") == "default":
                findings.append({
                    "severity": "MEDIUM",
                    "type": "default_sa_binding",
                    "binding": binding["metadata"]["name"],
                    "namespace": subject.get("namespace", "N/A"),
                    "role": binding.get("roleRef", {}).get("name", ""),
                    "description": f"Default service account in {subject.get('namespace', 'N/A')} has role binding"
                })
    return findings


def generate_report(all_findings: list[dict], output_format: str = "text") -> str:
    critical = [f for f in all_findings if f["severity"] == "CRITICAL"]
    high = [f for f in all_findings if f["severity"] == "HIGH"]
    medium = [f for f in all_findings if f["severity"] == "MEDIUM"]

    if output_format == "json":
        return json.dumps({
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {"critical": len(critical), "high": len(high), "medium": len(medium)},
            "findings": all_findings
        }, indent=2)

    lines = ["=" * 70, "KUBERNETES RBAC HARDENING AUDIT REPORT",
             f"Generated: {datetime.utcnow().isoformat()}", "=" * 70]
    lines.append(f"\nFindings: {len(critical)} Critical, {len(high)} High, {len(medium)} Medium")

    for sev, items in [("CRITICAL", critical), ("HIGH", high), ("MEDIUM", medium)]:
        if items:
            lines.append(f"\n## {sev}")
            for f in items:
                lines.append(f"  [{f['type']}] {f['description']}")

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Kubernetes RBAC Audit Tool")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args()

    crbs = get_cluster_role_bindings()
    rbs = get_role_bindings()
    roles = get_cluster_roles()

    all_findings = []
    all_findings.extend(audit_cluster_admin_bindings(crbs))
    all_findings.extend(audit_wildcard_permissions(roles))
    all_findings.extend(audit_dangerous_permissions(roles))
    all_findings.extend(audit_default_service_accounts(rbs, crbs))

    print(generate_report(all_findings, args.format))
    sys.exit(1 if any(f["severity"] == "CRITICAL" for f in all_findings) else 0)


if __name__ == "__main__":
    main()
