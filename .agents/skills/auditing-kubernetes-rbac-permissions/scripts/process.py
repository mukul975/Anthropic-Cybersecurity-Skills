#!/usr/bin/env python3
"""
Kubernetes RBAC Permissions Auditor

Audits RBAC configurations for overly permissive roles,
dangerous permission combinations, and privilege escalation paths.
"""

import subprocess
import json
import sys
from dataclasses import dataclass, field

DANGEROUS_VERBS = {"*", "escalate", "bind", "impersonate"}
DANGEROUS_RESOURCES = {"*", "secrets", "pods", "clusterroles", "clusterrolebindings", "roles", "rolebindings"}
HIGH_RISK_COMBINATIONS = [
    ({"*"}, {"*"}, "CRITICAL", "Wildcard access on all resources (cluster-admin equivalent)"),
    ({"create", "update", "patch"}, {"clusterrolebindings", "rolebindings"}, "CRITICAL", "Can create role bindings for privilege escalation"),
    ({"escalate"}, {"clusterroles", "roles"}, "CRITICAL", "Can escalate role permissions beyond own level"),
    ({"impersonate"}, {"users", "groups", "serviceaccounts"}, "CRITICAL", "Can impersonate any identity"),
    ({"get", "list", "watch"}, {"secrets"}, "HIGH", "Can read all secrets in scope"),
    ({"create"}, {"pods"}, "HIGH", "Can create pods (deploy workloads)"),
    ({"create"}, {"pods/exec"}, "HIGH", "Can exec into pods (command execution)"),
    ({"delete"}, {"pods", "nodes", "namespaces"}, "HIGH", "Can delete critical resources"),
]


@dataclass
class RBACFinding:
    resource_type: str
    resource_name: str
    namespace: str
    severity: str
    issue: str
    details: str
    remediation: str


@dataclass
class RBACAuditReport:
    findings: list = field(default_factory=list)
    cluster_roles: int = 0
    roles: int = 0
    cluster_role_bindings: int = 0
    role_bindings: int = 0
    service_accounts: int = 0


def run_kubectl_json(args: list):
    cmd = ["kubectl"] + args + ["-o", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return None


def check_role_rules(rules: list, role_name: str, role_type: str, namespace: str, report: RBACAuditReport):
    """Analyze role rules for dangerous permissions."""
    for rule in rules:
        verbs = set(rule.get("verbs", []))
        resources = set(rule.get("resources", []))
        api_groups = rule.get("apiGroups", [])

        for req_verbs, req_resources, severity, description in HIGH_RISK_COMBINATIONS:
            verb_match = "*" in verbs or bool(verbs & req_verbs)
            resource_match = "*" in resources or bool(resources & req_resources)

            if verb_match and resource_match:
                report.findings.append(RBACFinding(
                    resource_type=role_type,
                    resource_name=role_name,
                    namespace=namespace,
                    severity=severity,
                    issue=description,
                    details=f"verbs={list(verbs)}, resources={list(resources)}, apiGroups={api_groups}",
                    remediation=f"Restrict {role_type} '{role_name}' to minimum required permissions"
                ))
                break


def audit_cluster_roles(report: RBACAuditReport):
    """Audit all ClusterRoles."""
    print("[*] Auditing ClusterRoles...")
    data = run_kubectl_json(["get", "clusterroles"])
    if not data:
        return

    items = data.get("items", [])
    report.cluster_roles = len(items)

    for cr in items:
        name = cr["metadata"]["name"]
        # Skip well-known system roles
        if name.startswith("system:") and name not in ("system:aggregate-to-admin", "system:aggregate-to-edit"):
            continue

        rules = cr.get("rules", [])
        check_role_rules(rules, name, "ClusterRole", "cluster-wide", report)


def audit_roles(report: RBACAuditReport):
    """Audit all namespace Roles."""
    print("[*] Auditing Roles...")
    data = run_kubectl_json(["get", "roles", "-A"])
    if not data:
        return

    items = data.get("items", [])
    report.roles = len(items)

    for role in items:
        name = role["metadata"]["name"]
        namespace = role["metadata"]["namespace"]
        rules = role.get("rules", [])
        check_role_rules(rules, name, "Role", namespace, report)


def audit_bindings(report: RBACAuditReport):
    """Audit ClusterRoleBindings for dangerous subject assignments."""
    print("[*] Auditing ClusterRoleBindings...")

    data = run_kubectl_json(["get", "clusterrolebindings"])
    if not data:
        return

    items = data.get("items", [])
    report.cluster_role_bindings = len(items)

    dangerous_subjects = {"system:anonymous", "system:unauthenticated"}
    admin_roles = {"cluster-admin", "admin", "edit"}

    for crb in items:
        name = crb["metadata"]["name"]
        role_ref = crb.get("roleRef", {}).get("name", "")
        subjects = crb.get("subjects", []) or []

        for subject in subjects:
            s_name = subject.get("name", "")
            s_kind = subject.get("kind", "")

            if s_name in dangerous_subjects and role_ref in admin_roles:
                report.findings.append(RBACFinding(
                    resource_type="ClusterRoleBinding",
                    resource_name=name,
                    namespace="cluster-wide",
                    severity="CRITICAL",
                    issue=f"Dangerous subject '{s_name}' bound to '{role_ref}'",
                    details=f"Subject {s_kind}/{s_name} has {role_ref} access",
                    remediation=f"Remove or restrict ClusterRoleBinding '{name}'"
                ))

            # Check for system:authenticated bound to admin roles
            if s_name == "system:authenticated" and role_ref in admin_roles:
                report.findings.append(RBACFinding(
                    resource_type="ClusterRoleBinding",
                    resource_name=name,
                    namespace="cluster-wide",
                    severity="CRITICAL",
                    issue=f"All authenticated users have '{role_ref}' access",
                    details=f"Group system:authenticated bound to {role_ref}",
                    remediation=f"Remove binding, use specific user/group bindings"
                ))


def audit_service_accounts(report: RBACAuditReport):
    """Audit service accounts for over-permissioning."""
    print("[*] Auditing Service Accounts...")

    data = run_kubectl_json(["get", "serviceaccounts", "-A"])
    if not data:
        return

    items = data.get("items", [])
    report.service_accounts = len(items)

    # Check default SAs that have non-default bindings
    crbs = run_kubectl_json(["get", "clusterrolebindings"])
    rbs = run_kubectl_json(["get", "rolebindings", "-A"])

    if crbs:
        for crb in crbs.get("items", []):
            for subject in crb.get("subjects", []) or []:
                if subject.get("kind") == "ServiceAccount" and subject.get("name") == "default":
                    report.findings.append(RBACFinding(
                        resource_type="ServiceAccount",
                        resource_name=f"default ({subject.get('namespace', 'unknown')})",
                        namespace=subject.get("namespace", "unknown"),
                        severity="HIGH",
                        issue=f"Default SA bound to ClusterRole '{crb['roleRef']['name']}'",
                        details="Default service account should not have additional permissions",
                        remediation="Create dedicated service account, remove default SA binding"
                    ))


def print_report(report: RBACAuditReport):
    print("\n" + "=" * 70)
    print("KUBERNETES RBAC AUDIT REPORT")
    print("=" * 70)
    print(f"ClusterRoles:        {report.cluster_roles}")
    print(f"Roles:               {report.roles}")
    print(f"ClusterRoleBindings: {report.cluster_role_bindings}")
    print(f"RoleBindings:        {report.role_bindings}")
    print(f"ServiceAccounts:     {report.service_accounts}")
    print(f"Total Findings:      {len(report.findings)}")
    print("=" * 70)

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        findings = [f for f in report.findings if f.severity == severity]
        if findings:
            print(f"\n{severity} ({len(findings)}):")
            print("-" * 70)
            for f in findings:
                print(f"  [{f.resource_type}] {f.resource_name}")
                print(f"    Issue: {f.issue}")
                print(f"    Details: {f.details}")
                print(f"    Fix: {f.remediation}")
                print()


def main():
    print("[*] Kubernetes RBAC Permissions Auditor\n")

    report = RBACAuditReport()
    audit_cluster_roles(report)
    audit_roles(report)
    audit_bindings(report)
    audit_service_accounts(report)
    print_report(report)

    output = {
        "summary": {
            "cluster_roles": report.cluster_roles,
            "roles": report.roles,
            "findings": len(report.findings),
        },
        "findings": [
            {"type": f.resource_type, "name": f.resource_name, "namespace": f.namespace,
             "severity": f.severity, "issue": f.issue, "remediation": f.remediation}
            for f in report.findings
        ],
    }

    with open("rbac_audit_report.json", "w") as f:
        json.dump(output, f, indent=2)
    print("[*] Report saved to rbac_audit_report.json")

    critical = sum(1 for f in report.findings if f.severity == "CRITICAL")
    if critical > 0:
        print(f"\n[!] {critical} CRITICAL findings found")
        sys.exit(1)


if __name__ == "__main__":
    main()
