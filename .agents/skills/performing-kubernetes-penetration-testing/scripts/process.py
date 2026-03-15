#!/usr/bin/env python3
"""
Kubernetes Penetration Testing Automation Tool

Performs automated security checks against Kubernetes clusters
including RBAC enumeration, secret exposure, network policy gaps,
and misconfiguration detection.
"""

import subprocess
import json
import sys
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PentestFinding:
    category: str
    title: str
    severity: str
    details: str
    impact: str
    remediation: str
    mitre_id: str = ""


@dataclass
class PentestReport:
    findings: list = field(default_factory=list)
    cluster_info: dict = field(default_factory=dict)


def run_kubectl(args: list, timeout: int = 30) -> tuple:
    cmd = ["kubectl"] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return -1, "", str(e)


def run_kubectl_json(args: list) -> Optional[dict]:
    rc, out, _ = run_kubectl(args + ["-o", "json"])
    if rc != 0 or not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def get_cluster_info(report: PentestReport):
    """Gather basic cluster information."""
    rc, version_out, _ = run_kubectl(["version", "--short"])
    if rc == 0:
        report.cluster_info["version"] = version_out

    rc, nodes_out, _ = run_kubectl(["get", "nodes", "-o", "wide", "--no-headers"])
    if rc == 0:
        report.cluster_info["nodes"] = len(nodes_out.split("\n"))

    rc, ns_out, _ = run_kubectl(["get", "namespaces", "--no-headers"])
    if rc == 0:
        report.cluster_info["namespaces"] = len(ns_out.split("\n"))


def test_anonymous_access(report: PentestReport):
    """Test for anonymous API server access."""
    print("[*] Testing anonymous API access...")

    test_commands = [
        (["get", "namespaces"], "List namespaces"),
        (["get", "pods", "-A"], "List all pods"),
        (["get", "secrets", "-A"], "List all secrets"),
        (["get", "nodes"], "List nodes"),
    ]

    for cmd, description in test_commands:
        rc, out, err = run_kubectl(["--as=system:anonymous"] + cmd)
        if rc == 0 and "Forbidden" not in err:
            report.findings.append(PentestFinding(
                category="Authentication",
                title=f"Anonymous access allowed: {description}",
                severity="CRITICAL",
                details=f"Anonymous user can: {description}",
                impact="Unauthenticated users can access cluster resources",
                remediation="Disable anonymous authentication: --anonymous-auth=false",
                mitre_id="T1078"
            ))


def test_rbac_misconfigurations(report: PentestReport):
    """Check for overly permissive RBAC configurations."""
    print("[*] Testing RBAC configurations...")

    # Check cluster role bindings for dangerous subjects
    crbs = run_kubectl_json(["get", "clusterrolebindings"])
    if crbs:
        for crb in crbs.get("items", []):
            name = crb["metadata"]["name"]
            role_ref = crb.get("roleRef", {}).get("name", "")
            subjects = crb.get("subjects", [])

            for subject in subjects:
                subject_name = subject.get("name", "")
                subject_kind = subject.get("kind", "")

                # Check for dangerous bindings
                dangerous_subjects = [
                    "system:anonymous",
                    "system:unauthenticated",
                    "system:authenticated",
                ]

                if subject_name in dangerous_subjects and role_ref in ("cluster-admin", "admin", "edit"):
                    report.findings.append(PentestFinding(
                        category="RBAC",
                        title=f"Dangerous ClusterRoleBinding: {name}",
                        severity="CRITICAL",
                        details=f"Subject '{subject_name}' bound to role '{role_ref}'",
                        impact="Broad access granted to anonymous or all authenticated users",
                        remediation=f"Remove or restrict ClusterRoleBinding '{name}'",
                        mitre_id="T1078.004"
                    ))

    # Check for wildcard permissions in ClusterRoles
    cluster_roles = run_kubectl_json(["get", "clusterroles"])
    if cluster_roles:
        for cr in cluster_roles.get("items", []):
            name = cr["metadata"]["name"]
            if name.startswith("system:"):
                continue

            for rule in cr.get("rules", []):
                verbs = rule.get("verbs", [])
                resources = rule.get("resources", [])
                api_groups = rule.get("apiGroups", [])

                if "*" in verbs and "*" in resources:
                    report.findings.append(PentestFinding(
                        category="RBAC",
                        title=f"Wildcard ClusterRole: {name}",
                        severity="HIGH",
                        details=f"Role grants all verbs on all resources (apiGroups: {api_groups})",
                        impact="Effectively cluster-admin level access",
                        remediation="Apply least privilege - specify exact verbs and resources",
                        mitre_id="T1078.004"
                    ))


def test_secret_exposure(report: PentestReport):
    """Check for exposed or poorly protected secrets."""
    print("[*] Testing secret exposure...")

    secrets = run_kubectl_json(["get", "secrets", "-A"])
    if not secrets:
        return

    sa_token_count = 0
    opaque_count = 0

    for secret in secrets.get("items", []):
        secret_type = secret.get("type", "")
        name = secret["metadata"]["name"]
        namespace = secret["metadata"]["namespace"]

        if secret_type == "kubernetes.io/service-account-token":
            sa_token_count += 1

    # Check for secrets in environment variables
    pods = run_kubectl_json(["get", "pods", "-A"])
    if pods:
        for pod in pods.get("items", []):
            pod_name = pod["metadata"]["name"]
            pod_ns = pod["metadata"]["namespace"]

            for container in pod.get("spec", {}).get("containers", []):
                for env in container.get("env", []):
                    value = env.get("value", "")
                    name_env = env.get("name", "").upper()

                    # Check for hardcoded sensitive values
                    sensitive_names = ["PASSWORD", "SECRET", "API_KEY", "TOKEN", "PRIVATE_KEY"]
                    if any(s in name_env for s in sensitive_names) and value and not env.get("valueFrom"):
                        report.findings.append(PentestFinding(
                            category="Secrets",
                            title=f"Hardcoded secret in pod env: {pod_ns}/{pod_name}",
                            severity="HIGH",
                            details=f"Container '{container.get('name')}' has hardcoded '{name_env}'",
                            impact="Secrets visible in pod spec, accessible via API",
                            remediation="Use Kubernetes Secrets or external secret store",
                            mitre_id="T1552.007"
                        ))


def test_network_policies(report: PentestReport):
    """Check for missing or insufficient network policies."""
    print("[*] Testing network policies...")

    namespaces = run_kubectl_json(["get", "namespaces"])
    if not namespaces:
        return

    for ns in namespaces.get("items", []):
        ns_name = ns["metadata"]["name"]
        if ns_name in ("kube-system", "kube-public", "kube-node-lease"):
            continue

        netpols = run_kubectl_json(["get", "networkpolicies", "-n", ns_name])
        if not netpols or not netpols.get("items"):
            report.findings.append(PentestFinding(
                category="Network",
                title=f"No NetworkPolicies in namespace: {ns_name}",
                severity="MEDIUM",
                details=f"Namespace '{ns_name}' has no network policies",
                impact="All pod-to-pod traffic is allowed (flat network)",
                remediation=f"Create default-deny NetworkPolicy in namespace '{ns_name}'",
                mitre_id="T1046"
            ))


def test_pod_security(report: PentestReport):
    """Check for insecure pod configurations."""
    print("[*] Testing pod security configurations...")

    pods = run_kubectl_json(["get", "pods", "-A"])
    if not pods:
        return

    for pod in pods.get("items", []):
        pod_name = pod["metadata"]["name"]
        pod_ns = pod["metadata"]["namespace"]
        spec = pod.get("spec", {})

        # Skip system namespaces
        if pod_ns in ("kube-system", "kube-public", "falco-system"):
            continue

        # Check hostPID, hostNetwork, hostIPC
        if spec.get("hostPID"):
            report.findings.append(PentestFinding(
                category="Pod Security",
                title=f"hostPID enabled: {pod_ns}/{pod_name}",
                severity="CRITICAL",
                details="Pod shares host PID namespace",
                impact="Can see and potentially interact with host processes",
                remediation="Set hostPID: false",
                mitre_id="T1611"
            ))

        if spec.get("hostNetwork"):
            report.findings.append(PentestFinding(
                category="Pod Security",
                title=f"hostNetwork enabled: {pod_ns}/{pod_name}",
                severity="HIGH",
                details="Pod shares host network namespace",
                impact="Can access host network interfaces and services",
                remediation="Set hostNetwork: false",
                mitre_id="T1611"
            ))

        for container in spec.get("containers", []):
            sc = container.get("securityContext", {})
            c_name = container.get("name", "")

            if sc.get("privileged"):
                report.findings.append(PentestFinding(
                    category="Pod Security",
                    title=f"Privileged container: {pod_ns}/{pod_name}/{c_name}",
                    severity="CRITICAL",
                    details="Container runs with full host privileges",
                    impact="Trivial container escape to host",
                    remediation="Set privileged: false, use specific capabilities",
                    mitre_id="T1611"
                ))

        # Check automountServiceAccountToken
        if spec.get("automountServiceAccountToken", True):
            sa = spec.get("serviceAccountName", "default")
            if sa == "default":
                report.findings.append(PentestFinding(
                    category="Pod Security",
                    title=f"Default SA token mounted: {pod_ns}/{pod_name}",
                    severity="LOW",
                    details="Default service account token auto-mounted",
                    impact="Token accessible at /var/run/secrets/kubernetes.io/serviceaccount/token",
                    remediation="Set automountServiceAccountToken: false",
                    mitre_id="T1552.007"
                ))


def test_pss_enforcement(report: PentestReport):
    """Check Pod Security Standards enforcement on namespaces."""
    print("[*] Testing PSS enforcement...")

    namespaces = run_kubectl_json(["get", "namespaces"])
    if not namespaces:
        return

    for ns in namespaces.get("items", []):
        ns_name = ns["metadata"]["name"]
        labels = ns["metadata"].get("labels", {})

        if ns_name in ("kube-system", "kube-public", "kube-node-lease"):
            continue

        enforce = labels.get("pod-security.kubernetes.io/enforce")
        if not enforce:
            report.findings.append(PentestFinding(
                category="PSS",
                title=f"No PSS enforcement on namespace: {ns_name}",
                severity="MEDIUM",
                details=f"Namespace '{ns_name}' lacks PSA enforce label",
                impact="No built-in restrictions on pod security contexts",
                remediation=f"Label namespace with pod-security.kubernetes.io/enforce=baseline or restricted"
            ))
        elif enforce == "privileged":
            report.findings.append(PentestFinding(
                category="PSS",
                title=f"Privileged PSS on non-system namespace: {ns_name}",
                severity="HIGH",
                details=f"Namespace '{ns_name}' allows privileged pods",
                impact="No restrictions on pod configurations",
                remediation="Change PSS enforce level to baseline or restricted"
            ))


def print_report(report: PentestReport):
    """Print pentest results."""
    print("\n" + "=" * 70)
    print("KUBERNETES PENETRATION TEST REPORT")
    print("=" * 70)

    if report.cluster_info:
        print(f"\nCluster Info:")
        for k, v in report.cluster_info.items():
            print(f"  {k}: {v}")

    print(f"\nTotal Findings: {len(report.findings)}")
    severity_counts = {}
    for f in report.findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"  {sev}: {severity_counts.get(sev, 0)}")

    print("=" * 70)

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        findings = [f for f in report.findings if f.severity == severity]
        if findings:
            print(f"\n{severity} FINDINGS:")
            print("-" * 70)
            for f in findings:
                print(f"  [{f.category}] {f.title}")
                print(f"    Details: {f.details}")
                print(f"    Impact: {f.impact}")
                print(f"    Fix: {f.remediation}")
                if f.mitre_id:
                    print(f"    MITRE: {f.mitre_id}")
                print()


def main():
    print("[*] Kubernetes Penetration Testing Tool")
    print("[*] Authorized testing only\n")

    report = PentestReport()

    get_cluster_info(report)
    test_anonymous_access(report)
    test_rbac_misconfigurations(report)
    test_secret_exposure(report)
    test_network_policies(report)
    test_pod_security(report)
    test_pss_enforcement(report)

    print_report(report)

    output = {
        "cluster_info": report.cluster_info,
        "summary": {
            "total_findings": len(report.findings),
            "critical": sum(1 for f in report.findings if f.severity == "CRITICAL"),
            "high": sum(1 for f in report.findings if f.severity == "HIGH"),
            "medium": sum(1 for f in report.findings if f.severity == "MEDIUM"),
            "low": sum(1 for f in report.findings if f.severity == "LOW"),
        },
        "findings": [
            {
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "details": f.details,
                "impact": f.impact,
                "remediation": f.remediation,
                "mitre_id": f.mitre_id,
            }
            for f in report.findings
        ],
    }

    with open("k8s_pentest_report.json", "w") as f:
        json.dump(output, f, indent=2)
    print("[*] Report saved to k8s_pentest_report.json")

    critical_count = output["summary"]["critical"]
    if critical_count > 0:
        print(f"\n[!] {critical_count} CRITICAL findings require immediate attention")
        sys.exit(1)


if __name__ == "__main__":
    main()
