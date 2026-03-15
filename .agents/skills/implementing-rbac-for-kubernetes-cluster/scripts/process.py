#!/usr/bin/env python3
"""
Kubernetes RBAC Auditor

Analyzes Kubernetes RBAC configurations to identify overly permissive
roles, dangerous permissions, unnecessary ClusterRoleBindings, and
service account security issues.
"""

import json
import datetime
from typing import Dict, List, Set
from dataclasses import dataclass, field


@dataclass
class K8sRole:
    """Kubernetes Role or ClusterRole."""
    name: str
    namespace: str  # empty for ClusterRole
    is_cluster_role: bool
    rules: List[Dict] = field(default_factory=list)
    # Each rule: {"apiGroups": [...], "resources": [...], "verbs": [...]}


@dataclass
class K8sBinding:
    """Kubernetes RoleBinding or ClusterRoleBinding."""
    name: str
    namespace: str
    is_cluster_binding: bool
    role_ref: str
    role_ref_kind: str  # Role or ClusterRole
    subjects: List[Dict] = field(default_factory=list)
    # Each subject: {"kind": "User/Group/ServiceAccount", "name": "...", "namespace": "..."}


@dataclass
class RBACFinding:
    severity: str
    category: str
    title: str
    description: str
    recommendation: str = ""
    affected_resources: List[str] = field(default_factory=list)


class KubernetesRBACAuditor:
    """Audits Kubernetes RBAC for security issues."""

    DANGEROUS_VERBS = {"*", "escalate", "bind", "impersonate"}
    SENSITIVE_RESOURCES = {"secrets", "roles", "clusterroles", "rolebindings",
                           "clusterrolebindings", "nodes", "persistentvolumes"}
    EXEC_RESOURCES = {"pods/exec", "pods/attach"}

    def __init__(self):
        self.roles: List[K8sRole] = []
        self.bindings: List[K8sBinding] = []
        self.findings: List[RBACFinding] = []

    def load_roles(self, roles: List[Dict]):
        for r in roles:
            self.roles.append(K8sRole(**r))

    def load_bindings(self, bindings: List[Dict]):
        for b in bindings:
            self.bindings.append(K8sBinding(**b))

    def audit_all(self) -> List[RBACFinding]:
        self.findings = []
        self._audit_wildcard_permissions()
        self._audit_dangerous_verbs()
        self._audit_cluster_admin_bindings()
        self._audit_service_account_bindings()
        self._audit_exec_permissions()
        self._audit_secret_access()
        self._audit_rbac_modification_permissions()
        return self.findings

    def _audit_wildcard_permissions(self):
        for role in self.roles:
            for rule in role.rules:
                if "*" in rule.get("resources", []) or "*" in rule.get("verbs", []):
                    scope = "ClusterRole" if role.is_cluster_role else f"Role in {role.namespace}"
                    self.findings.append(RBACFinding(
                        severity="critical",
                        category="Wildcard Permissions",
                        title=f"Wildcard permissions in {scope} '{role.name}'",
                        description=f"Resources: {rule.get('resources')}, Verbs: {rule.get('verbs')}. "
                                    "Wildcard grants excessive access violating least privilege.",
                        recommendation="Replace wildcards with explicit resource and verb lists.",
                        affected_resources=[role.name]
                    ))

    def _audit_dangerous_verbs(self):
        for role in self.roles:
            for rule in role.rules:
                dangerous = set(rule.get("verbs", [])) & self.DANGEROUS_VERBS
                if dangerous and "*" not in dangerous:  # wildcard already caught
                    self.findings.append(RBACFinding(
                        severity="critical",
                        category="Dangerous Verbs",
                        title=f"Dangerous verbs in '{role.name}': {', '.join(dangerous)}",
                        description="escalate/bind allow privilege escalation. "
                                    "impersonate allows identity spoofing.",
                        recommendation="Remove dangerous verbs. Only cluster-admin should have these.",
                        affected_resources=[role.name]
                    ))

    def _audit_cluster_admin_bindings(self):
        cluster_admin_bindings = [
            b for b in self.bindings
            if b.role_ref == "cluster-admin" and b.is_cluster_binding
        ]
        for binding in cluster_admin_bindings:
            for subject in binding.subjects:
                if subject.get("kind") == "ServiceAccount":
                    self.findings.append(RBACFinding(
                        severity="critical",
                        category="Cluster Admin",
                        title=f"ServiceAccount bound to cluster-admin: {subject.get('name')}",
                        description=f"Service account '{subject.get('name')}' in namespace "
                                    f"'{subject.get('namespace', 'default')}' has full cluster admin access.",
                        recommendation="Create a dedicated ClusterRole with minimum required permissions.",
                        affected_resources=[binding.name]
                    ))
                elif subject.get("kind") == "Group" and subject.get("name") not in (
                    "system:masters",
                ):
                    self.findings.append(RBACFinding(
                        severity="high",
                        category="Cluster Admin",
                        title=f"Group bound to cluster-admin: {subject.get('name')}",
                        description=f"All members of group '{subject.get('name')}' have full cluster admin.",
                        recommendation="Review group membership. Use namespace-scoped roles instead.",
                        affected_resources=[binding.name]
                    ))

    def _audit_service_account_bindings(self):
        default_sa_bindings = []
        for binding in self.bindings:
            for subject in binding.subjects:
                if (subject.get("kind") == "ServiceAccount" and
                        subject.get("name") == "default"):
                    default_sa_bindings.append(binding)

        if default_sa_bindings:
            self.findings.append(RBACFinding(
                severity="high",
                category="Service Account",
                title=f"Default service account has {len(default_sa_bindings)} custom bindings",
                description="Default service account should not have additional permissions. "
                            "All pods without explicit SA use the default SA.",
                recommendation="Create dedicated service accounts per application. "
                               "Remove bindings from default SA.",
                affected_resources=[b.name for b in default_sa_bindings]
            ))

    def _audit_exec_permissions(self):
        for role in self.roles:
            for rule in role.rules:
                resources = set(rule.get("resources", []))
                exec_resources = resources & self.EXEC_RESOURCES
                if exec_resources:
                    self.findings.append(RBACFinding(
                        severity="high",
                        category="Pod Exec",
                        title=f"Pod exec/attach permission in '{role.name}'",
                        description="pods/exec allows running commands inside containers. "
                                    "This can be used for lateral movement.",
                        recommendation="Restrict exec access to debugging roles. "
                                       "Monitor exec usage in audit logs.",
                        affected_resources=[role.name]
                    ))

    def _audit_secret_access(self):
        for role in self.roles:
            for rule in role.rules:
                resources = set(rule.get("resources", []))
                verbs = set(rule.get("verbs", []))
                if "secrets" in resources:
                    write_verbs = verbs & {"create", "update", "patch", "delete", "*"}
                    if write_verbs:
                        self.findings.append(RBACFinding(
                            severity="high",
                            category="Secret Access",
                            title=f"Secret write access in '{role.name}'",
                            description=f"Write verbs on secrets: {', '.join(write_verbs)}. "
                                        "This allows creating/modifying secrets.",
                            recommendation="Limit secret write access to operators and CI/CD only.",
                            affected_resources=[role.name]
                        ))

    def _audit_rbac_modification_permissions(self):
        rbac_resources = {"roles", "clusterroles", "rolebindings", "clusterrolebindings"}
        for role in self.roles:
            if role.name in ("cluster-admin", "admin"):
                continue  # Skip built-in roles
            for rule in role.rules:
                resources = set(rule.get("resources", []))
                if resources & rbac_resources:
                    verbs = set(rule.get("verbs", []))
                    write_verbs = verbs & {"create", "update", "patch", "delete", "*"}
                    if write_verbs:
                        self.findings.append(RBACFinding(
                            severity="critical",
                            category="RBAC Modification",
                            title=f"RBAC modification permissions in '{role.name}'",
                            description=f"Can modify RBAC objects: {resources & rbac_resources}. "
                                        "This enables privilege escalation.",
                            recommendation="Remove RBAC modification permissions from non-admin roles.",
                            affected_resources=[role.name]
                        ))

    def generate_report(self) -> str:
        if not self.findings:
            self.audit_all()

        lines = [
            "=" * 70,
            "KUBERNETES RBAC AUDIT REPORT",
            "=" * 70,
            f"Report Date: {datetime.datetime.now().isoformat()}",
            f"Roles/ClusterRoles Audited: {len(self.roles)}",
            f"Bindings Audited: {len(self.bindings)}",
            f"Findings: {len(self.findings)}",
            "-" * 70, ""
        ]

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for f in sorted(self.findings, key=lambda x: severity_order.get(x.severity, 5)):
            lines.append(f"[{f.severity.upper()}] {f.title}")
            lines.append(f"  Category: {f.category}")
            lines.append(f"  {f.description}")
            if f.recommendation:
                lines.append(f"  Fix: {f.recommendation}")
            if f.affected_resources:
                lines.append(f"  Affected: {', '.join(f.affected_resources)}")
            lines.append("")

        critical = sum(1 for f in self.findings if f.severity == "critical")
        lines.append("=" * 70)
        lines.append(f"OVERALL: {'FAIL' if critical else 'PASS'}")
        lines.append("=" * 70)
        return "\n".join(lines)


def main():
    auditor = KubernetesRBACAuditor()

    auditor.load_roles([
        {"name": "developer", "namespace": "app-team", "is_cluster_role": False,
         "rules": [
             {"apiGroups": ["", "apps"], "resources": ["pods", "deployments", "services"], "verbs": ["get", "list", "create", "update", "delete"]},
             {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]},
             {"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]}
         ]},
        {"name": "ci-deployer", "namespace": "", "is_cluster_role": True,
         "rules": [
             {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}
         ]},
        {"name": "custom-admin", "namespace": "production", "is_cluster_role": False,
         "rules": [
             {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles", "rolebindings"], "verbs": ["create", "update", "delete"]},
             {"apiGroups": [""], "resources": ["secrets"], "verbs": ["create", "update", "delete"]}
         ]},
    ])

    auditor.load_bindings([
        {"name": "ci-deployer-binding", "namespace": "", "is_cluster_binding": True,
         "role_ref": "cluster-admin", "role_ref_kind": "ClusterRole",
         "subjects": [{"kind": "ServiceAccount", "name": "ci-deployer", "namespace": "ci-cd"}]},
        {"name": "dev-binding", "namespace": "app-team", "is_cluster_binding": False,
         "role_ref": "developer", "role_ref_kind": "Role",
         "subjects": [{"kind": "Group", "name": "dev-team"}]},
        {"name": "default-elevated", "namespace": "app-team", "is_cluster_binding": False,
         "role_ref": "developer", "role_ref_kind": "Role",
         "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "app-team"}]},
    ])

    print(auditor.generate_report())


if __name__ == "__main__":
    main()
