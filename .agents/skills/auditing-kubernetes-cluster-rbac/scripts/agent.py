#!/usr/bin/env python3
"""Agent for auditing Kubernetes cluster RBAC configurations."""

import os
import json
import argparse
from datetime import datetime

from kubernetes import client, config


def load_kube_config(kubeconfig=None, context=None):
    """Load Kubernetes configuration."""
    if kubeconfig:
        config.load_kube_config(config_file=kubeconfig, context=context)
    else:
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config(context=context)


def list_cluster_roles_with_wildcards():
    """Find ClusterRoles with wildcard verb or resource permissions."""
    rbac = client.RbacAuthorizationV1Api()
    roles = rbac.list_cluster_role()
    risky = []
    for role in roles.items:
        for rule in role.rules or []:
            verbs = rule.verbs or []
            resources = rule.resources or []
            if "*" in verbs or "*" in resources:
                risky.append({
                    "name": role.metadata.name,
                    "verbs": verbs,
                    "resources": resources,
                    "api_groups": rule.api_groups or [],
                })
    return risky


def list_secret_access_roles():
    """Find ClusterRoles that can read secrets."""
    rbac = client.RbacAuthorizationV1Api()
    roles = rbac.list_cluster_role()
    results = []
    for role in roles.items:
        for rule in role.rules or []:
            resources = rule.resources or []
            verbs = rule.verbs or []
            if ("secrets" in resources or "*" in resources) and \
               ("get" in verbs or "list" in verbs or "*" in verbs):
                if not role.metadata.name.startswith("system:"):
                    results.append({
                        "role": role.metadata.name,
                        "verbs": verbs,
                        "resources": resources,
                    })
    return results


def list_cluster_admin_bindings():
    """Find all ClusterRoleBindings that grant cluster-admin."""
    rbac = client.RbacAuthorizationV1Api()
    bindings = rbac.list_cluster_role_binding()
    results = []
    for binding in bindings.items:
        if binding.role_ref.name == "cluster-admin":
            subjects = []
            for s in binding.subjects or []:
                subjects.append({
                    "kind": s.kind,
                    "name": s.name,
                    "namespace": s.namespace or "cluster-wide",
                })
            results.append({
                "binding": binding.metadata.name,
                "subjects": subjects,
            })
    return results


def find_dangerous_bindings():
    """Find bindings granting access to system:authenticated or system:unauthenticated."""
    rbac = client.RbacAuthorizationV1Api()
    bindings = rbac.list_cluster_role_binding()
    dangerous = []
    for binding in bindings.items:
        for s in binding.subjects or []:
            if s.name in ("system:authenticated", "system:unauthenticated"):
                dangerous.append({
                    "binding": binding.metadata.name,
                    "role": binding.role_ref.name,
                    "subject": s.name,
                })
    return dangerous


def audit_service_account_tokens():
    """Find pods with automounted service account tokens."""
    v1 = client.CoreV1Api()
    pods = v1.list_pod_for_all_namespaces()
    risky_pods = []
    for pod in pods.items:
        spec = pod.spec
        sa = spec.service_account_name or "default"
        automount = spec.automount_service_account_token
        if automount is not False and sa != "default":
            risky_pods.append({
                "namespace": pod.metadata.namespace,
                "pod": pod.metadata.name,
                "service_account": sa,
                "automount": True,
            })
    return risky_pods


def find_privileged_containers():
    """Find containers running as privileged or root."""
    v1 = client.CoreV1Api()
    pods = v1.list_pod_for_all_namespaces()
    privileged = []
    for pod in pods.items:
        for container in pod.spec.containers or []:
            sc = container.security_context
            if sc:
                is_privileged = getattr(sc, "privileged", False)
                run_as_root = getattr(sc, "run_as_user", None) == 0
                if is_privileged or run_as_root:
                    privileged.append({
                        "namespace": pod.metadata.namespace,
                        "pod": pod.metadata.name,
                        "container": container.name,
                        "privileged": is_privileged,
                        "run_as_root": run_as_root,
                    })
    return privileged


def main():
    parser = argparse.ArgumentParser(description="Kubernetes RBAC Audit Agent")
    parser.add_argument("--kubeconfig", default=os.getenv("KUBECONFIG"))
    parser.add_argument("--context", help="Kubernetes context to use")
    parser.add_argument("--output", default="k8s_rbac_audit.json")
    parser.add_argument("--action", choices=[
        "wildcards", "secrets", "cluster_admin", "dangerous",
        "tokens", "privileged", "full_audit"
    ], default="full_audit")
    args = parser.parse_args()

    load_kube_config(args.kubeconfig, args.context)
    report = {"audit_date": datetime.utcnow().isoformat(), "findings": {}}

    if args.action in ("wildcards", "full_audit"):
        wildcards = list_cluster_roles_with_wildcards()
        report["findings"]["wildcard_roles"] = wildcards
        print(f"[+] Wildcard ClusterRoles: {len(wildcards)}")

    if args.action in ("secrets", "full_audit"):
        secret_roles = list_secret_access_roles()
        report["findings"]["secret_access_roles"] = secret_roles
        print(f"[+] Roles with secret access: {len(secret_roles)}")

    if args.action in ("cluster_admin", "full_audit"):
        admins = list_cluster_admin_bindings()
        report["findings"]["cluster_admin_bindings"] = admins
        total_subjects = sum(len(a["subjects"]) for a in admins)
        print(f"[+] cluster-admin bindings: {len(admins)} ({total_subjects} subjects)")

    if args.action in ("dangerous", "full_audit"):
        danger = find_dangerous_bindings()
        report["findings"]["dangerous_bindings"] = danger
        print(f"[+] Dangerous bindings: {len(danger)}")

    if args.action in ("tokens", "full_audit"):
        tokens = audit_service_account_tokens()
        report["findings"]["automounted_tokens"] = tokens
        print(f"[+] Pods with automounted tokens: {len(tokens)}")

    if args.action in ("privileged", "full_audit"):
        priv = find_privileged_containers()
        report["findings"]["privileged_containers"] = priv
        print(f"[+] Privileged containers: {len(priv)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
