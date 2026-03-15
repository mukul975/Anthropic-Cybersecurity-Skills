#!/usr/bin/env python3
"""Kubernetes RBAC Audit Agent - Audits cluster RBAC permissions for security misconfigurations."""

import json
import logging
import argparse
from datetime import datetime

from kubernetes import client, config

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DANGEROUS_VERBS = {"*", "create", "delete", "patch", "update", "escalate", "bind", "impersonate"}
DANGEROUS_RESOURCES = {"secrets", "pods/exec", "pods/attach", "serviceaccounts", "clusterroles", "clusterrolebindings", "roles", "rolebindings", "*"}


def load_kube_config(kubeconfig=None):
    """Load Kubernetes configuration."""
    if kubeconfig:
        config.load_kube_config(config_file=kubeconfig)
    else:
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
    return client.RbacAuthorizationV1Api(), client.CoreV1Api()


def audit_cluster_roles(rbac_api):
    """Audit ClusterRoles for overly permissive rules."""
    findings = []
    roles = rbac_api.list_cluster_role()
    for role in roles.items:
        if role.metadata.name.startswith("system:"):
            continue
        for rule in (role.rules or []):
            verbs = set(rule.verbs or [])
            resources = set(rule.resources or [])
            api_groups = rule.api_groups or [""]
            if "*" in verbs and "*" in resources:
                findings.append({"role": role.metadata.name, "type": "ClusterRole", "issue": "Full wildcard access (*/*)", "severity": "critical", "rule": {"verbs": list(verbs), "resources": list(resources)}})
            elif verbs & DANGEROUS_VERBS and resources & DANGEROUS_RESOURCES:
                findings.append({"role": role.metadata.name, "type": "ClusterRole", "issue": f"Dangerous permission: {verbs & DANGEROUS_VERBS} on {resources & DANGEROUS_RESOURCES}", "severity": "high", "rule": {"verbs": list(verbs), "resources": list(resources)}})
    logger.info("Audited %d ClusterRoles, %d findings", len(roles.items), len(findings))
    return findings


def audit_role_bindings(rbac_api):
    """Audit ClusterRoleBindings for excessive privilege grants."""
    findings = []
    bindings = rbac_api.list_cluster_role_binding()
    for binding in bindings.items:
        if binding.metadata.name.startswith("system:"):
            continue
        role_ref = binding.role_ref
        subjects = binding.subjects or []
        for subject in subjects:
            if role_ref.name in ("cluster-admin", "admin") and subject.kind != "ServiceAccount":
                findings.append({"binding": binding.metadata.name, "role": role_ref.name, "subject": f"{subject.kind}/{subject.name}", "severity": "critical" if role_ref.name == "cluster-admin" else "high", "issue": f"{subject.kind} bound to {role_ref.name}"})
            if subject.kind == "Group" and subject.name in ("system:unauthenticated", "system:authenticated"):
                findings.append({"binding": binding.metadata.name, "role": role_ref.name, "subject": subject.name, "severity": "critical", "issue": f"Broad group {subject.name} bound to {role_ref.name}"})
    return findings


def audit_service_accounts(core_api, rbac_api):
    """Audit service accounts for default token mounting and elevated permissions."""
    findings = []
    sas = core_api.list_service_account_for_all_namespaces()
    for sa in sas.items:
        if sa.metadata.name == "default":
            if sa.automount_service_account_token is not False:
                findings.append({"namespace": sa.metadata.namespace, "service_account": "default", "issue": "Default SA auto-mounts token", "severity": "medium"})
    return findings


def generate_report(role_findings, binding_findings, sa_findings):
    """Generate RBAC audit report."""
    all_findings = role_findings + binding_findings + sa_findings
    critical = [f for f in all_findings if f.get("severity") == "critical"]
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_findings": len(all_findings),
        "critical": len(critical),
        "role_findings": role_findings,
        "binding_findings": binding_findings,
        "service_account_findings": sa_findings,
    }
    print(f"RBAC REPORT: {len(all_findings)} findings ({len(critical)} critical)")
    return report


def main():
    parser = argparse.ArgumentParser(description="Kubernetes RBAC Audit Agent")
    parser.add_argument("--kubeconfig", help="Path to kubeconfig file")
    parser.add_argument("--output", default="rbac_report.json")
    args = parser.parse_args()

    rbac_api, core_api = load_kube_config(args.kubeconfig)
    role_findings = audit_cluster_roles(rbac_api)
    binding_findings = audit_role_bindings(rbac_api)
    sa_findings = audit_service_accounts(core_api, rbac_api)
    report = generate_report(role_findings, binding_findings, sa_findings)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
