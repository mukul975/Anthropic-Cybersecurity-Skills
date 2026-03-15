#!/usr/bin/env python3
"""Agent for auditing Kubernetes cluster security posture on managed cloud platforms."""

from kubernetes import client, config
import json
import sys
import argparse
from datetime import datetime


def load_kube_config(context=None):
    """Load kubeconfig for cluster access."""
    try:
        config.load_kube_config(context=context)
        print("[*] Kubeconfig loaded successfully")
    except Exception as e:
        print(f"[-] Failed to load kubeconfig: {e}")
        sys.exit(1)


def check_pod_security_standards():
    """Audit namespaces for Pod Security Standards enforcement labels."""
    v1 = client.CoreV1Api()
    namespaces = v1.list_namespace().items
    findings = []
    print("\n[*] Checking Pod Security Standards enforcement...")
    for ns in namespaces:
        name = ns.metadata.name
        labels = ns.metadata.labels or {}
        enforce = labels.get("pod-security.kubernetes.io/enforce", "NOT SET")
        audit = labels.get("pod-security.kubernetes.io/audit", "NOT SET")
        warn = labels.get("pod-security.kubernetes.io/warn", "NOT SET")
        if enforce == "NOT SET" and name not in ("kube-system", "kube-public", "kube-node-lease"):
            findings.append({"namespace": name, "issue": "No PSA enforcement", "severity": "HIGH"})
            print(f"  [!] {name}: enforce={enforce}")
        elif enforce in ("baseline", "restricted"):
            print(f"  [+] {name}: enforce={enforce}, audit={audit}, warn={warn}")
    print(f"[*] {len(findings)} namespaces without PSA enforcement")
    return findings


def check_rbac_clusterroles():
    """Audit ClusterRoleBindings for overly permissive access."""
    rbac = client.RbacAuthorizationV1Api()
    findings = []
    print("\n[*] Checking RBAC ClusterRoleBindings...")
    bindings = rbac.list_cluster_role_binding().items
    for binding in bindings:
        role_ref = binding.role_ref.name
        subjects = binding.subjects or []
        if role_ref in ("cluster-admin", "admin"):
            for subj in subjects:
                if subj.kind in ("User", "Group") and subj.name not in ("system:masters",):
                    findings.append({
                        "binding": binding.metadata.name, "role": role_ref,
                        "subject": f"{subj.kind}/{subj.name}", "severity": "CRITICAL",
                    })
                    print(f"  [!] CRITICAL: {subj.kind}/{subj.name} -> {role_ref}")
    print(f"[*] {len(findings)} overprivileged ClusterRoleBindings found")
    return findings


def check_service_account_tokens():
    """Find pods with auto-mounted service account tokens."""
    v1 = client.CoreV1Api()
    findings = []
    print("\n[*] Checking for auto-mounted service account tokens...")
    pods = v1.list_pod_for_all_namespaces().items
    for pod in pods:
        ns = pod.metadata.namespace
        if ns in ("kube-system", "kube-public"):
            continue
        auto_mount = pod.spec.automount_service_account_token
        if auto_mount is None or auto_mount is True:
            sa = pod.spec.service_account_name or "default"
            if sa == "default":
                findings.append({
                    "pod": pod.metadata.name, "namespace": ns,
                    "service_account": sa, "severity": "MEDIUM",
                })
    if findings:
        print(f"  [!] {len(findings)} pods with default SA token auto-mounted")
        for f in findings[:10]:
            print(f"    {f['namespace']}/{f['pod']} (SA: {f['service_account']})")
    return findings


def check_privileged_pods():
    """Find pods running with privileged security context."""
    v1 = client.CoreV1Api()
    findings = []
    print("\n[*] Checking for privileged containers...")
    pods = v1.list_pod_for_all_namespaces().items
    for pod in pods:
        ns = pod.metadata.namespace
        if ns in ("kube-system",):
            continue
        for container in pod.spec.containers:
            sc = container.security_context
            if sc:
                if sc.privileged:
                    findings.append({
                        "pod": pod.metadata.name, "namespace": ns,
                        "container": container.name, "issue": "privileged=true",
                        "severity": "CRITICAL",
                    })
                    print(f"  [!] CRITICAL: {ns}/{pod.metadata.name}/{container.name} is PRIVILEGED")
                if sc.run_as_user == 0:
                    findings.append({
                        "pod": pod.metadata.name, "namespace": ns,
                        "container": container.name, "issue": "running as root (UID 0)",
                        "severity": "HIGH",
                    })
    print(f"[*] {len(findings)} privileged/root container findings")
    return findings


def check_network_policies():
    """Check if namespaces have network policies applied."""
    v1 = client.CoreV1Api()
    net_v1 = client.NetworkingV1Api()
    findings = []
    print("\n[*] Checking network policy coverage...")
    namespaces = v1.list_namespace().items
    for ns in namespaces:
        name = ns.metadata.name
        if name in ("kube-system", "kube-public", "kube-node-lease"):
            continue
        policies = net_v1.list_namespaced_network_policy(name).items
        if not policies:
            findings.append({"namespace": name, "issue": "No network policies", "severity": "HIGH"})
            print(f"  [!] {name}: NO network policies")
        else:
            deny_all = any(not p.spec.pod_selector.match_labels for p in policies
                          if p.spec.pod_selector)
            print(f"  [+] {name}: {len(policies)} policies (default-deny: {'Yes' if deny_all else 'No'})")
    return findings


def check_image_registries():
    """Audit images to ensure they come from approved registries."""
    v1 = client.CoreV1Api()
    print("\n[*] Checking container image sources...")
    pods = v1.list_pod_for_all_namespaces().items
    registries = {}
    issues = []
    for pod in pods:
        for container in pod.spec.containers:
            image = container.image or ""
            registry = image.split("/")[0] if "/" in image else "docker.io"
            registries[registry] = registries.get(registry, 0) + 1
            if "@sha256:" not in image and ":latest" in image:
                issues.append({
                    "pod": pod.metadata.name, "namespace": pod.metadata.namespace,
                    "image": image, "issue": "Using :latest tag",
                })
    print("  Image registries in use:")
    for reg, count in sorted(registries.items(), key=lambda x: -x[1]):
        print(f"    {reg}: {count} containers")
    if issues:
        print(f"  [!] {len(issues)} containers using :latest tag")
    return issues


def full_audit(output_path="k8s_security_audit.json"):
    """Run a complete Kubernetes security audit."""
    print("[*] Starting Kubernetes security audit...\n")
    report = {
        "audit_date": datetime.now().isoformat(),
        "psa_findings": check_pod_security_standards(),
        "rbac_findings": check_rbac_clusterroles(),
        "sa_token_findings": check_service_account_tokens(),
        "privileged_findings": check_privileged_pods(),
        "network_policy_findings": check_network_policies(),
        "image_findings": check_image_registries(),
    }
    total = sum(len(v) for v in report.values() if isinstance(v, list))
    report["total_findings"] = total
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[*] Audit complete: {total} total findings")
    print(f"[*] Report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Kubernetes Cloud Security Audit Agent")
    parser.add_argument("action", choices=["full-audit", "psa", "rbac", "privileged",
                                           "network-policies", "images", "sa-tokens"])
    parser.add_argument("--context", help="Kubeconfig context name")
    parser.add_argument("-o", "--output", default="k8s_security_audit.json")
    args = parser.parse_args()

    load_kube_config(args.context)
    if args.action == "full-audit":
        full_audit(args.output)
    elif args.action == "psa":
        check_pod_security_standards()
    elif args.action == "rbac":
        check_rbac_clusterroles()
    elif args.action == "privileged":
        check_privileged_pods()
    elif args.action == "network-policies":
        check_network_policies()
    elif args.action == "images":
        check_image_registries()
    elif args.action == "sa-tokens":
        check_service_account_tokens()


if __name__ == "__main__":
    main()
