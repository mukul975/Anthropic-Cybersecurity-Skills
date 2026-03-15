#!/usr/bin/env python3
"""
Kubernetes Pod Security Standards Compliance Checker

Audits namespaces and workloads for PSS enforcement levels
and identifies non-compliant pods.
"""

import subprocess
import json
import sys
from dataclasses import dataclass, field


@dataclass
class PSSFinding:
    namespace: str
    resource: str
    level: str  # baseline, restricted
    violation: str
    severity: str  # CRITICAL, HIGH, MEDIUM
    remediation: str


@dataclass
class PSSReport:
    findings: list = field(default_factory=list)
    namespaces_audited: int = 0
    pods_audited: int = 0
    compliant_pods: int = 0
    non_compliant_pods: int = 0


def run_kubectl(args: list) -> tuple:
    """Execute kubectl command and return parsed JSON."""
    cmd = ["kubectl"] + args + ["-o", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return None, result.stderr
        return json.loads(result.stdout), None
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        return None, str(e)


def get_namespace_pss_labels(ns_data: dict) -> dict:
    """Extract PSS labels from namespace metadata."""
    labels = ns_data.get("metadata", {}).get("labels", {})
    return {
        "enforce": labels.get("pod-security.kubernetes.io/enforce", "not-set"),
        "audit": labels.get("pod-security.kubernetes.io/audit", "not-set"),
        "warn": labels.get("pod-security.kubernetes.io/warn", "not-set"),
        "enforce-version": labels.get("pod-security.kubernetes.io/enforce-version", "not-set"),
    }


def check_restricted_compliance(pod_spec: dict, pod_name: str, namespace: str) -> list:
    """Check pod spec against restricted PSS profile."""
    findings = []
    containers = pod_spec.get("containers", []) + pod_spec.get("initContainers", [])
    pod_security_context = pod_spec.get("securityContext", {})

    # Check pod-level runAsNonRoot
    pod_run_as_non_root = pod_security_context.get("runAsNonRoot", False)
    pod_run_as_user = pod_security_context.get("runAsUser")

    # Check pod-level seccomp
    pod_seccomp = pod_security_context.get("seccompProfile", {})
    pod_seccomp_type = pod_seccomp.get("type", "")

    # Check hostNetwork, hostPID, hostIPC
    for host_ns in ["hostNetwork", "hostPID", "hostIPC"]:
        if pod_spec.get(host_ns, False):
            findings.append(PSSFinding(
                namespace=namespace,
                resource=pod_name,
                level="baseline",
                violation=f"{host_ns} is enabled",
                severity="CRITICAL",
                remediation=f"Set {host_ns}: false in pod spec"
            ))

    # Check hostPath volumes
    for vol in pod_spec.get("volumes", []):
        if "hostPath" in vol:
            findings.append(PSSFinding(
                namespace=namespace,
                resource=pod_name,
                level="baseline",
                violation=f"hostPath volume '{vol.get('name')}' detected",
                severity="HIGH",
                remediation="Replace hostPath with emptyDir, PVC, or configMap"
            ))

    for container in containers:
        c_name = container.get("name", "unknown")
        sc = container.get("securityContext", {})

        # Check privileged
        if sc.get("privileged", False):
            findings.append(PSSFinding(
                namespace=namespace,
                resource=f"{pod_name}/{c_name}",
                level="baseline",
                violation="Container runs in privileged mode",
                severity="CRITICAL",
                remediation="Set privileged: false and use specific capabilities"
            ))

        # Check allowPrivilegeEscalation
        if sc.get("allowPrivilegeEscalation", True):
            findings.append(PSSFinding(
                namespace=namespace,
                resource=f"{pod_name}/{c_name}",
                level="restricted",
                violation="allowPrivilegeEscalation is not explicitly false",
                severity="HIGH",
                remediation="Set allowPrivilegeEscalation: false"
            ))

        # Check runAsNonRoot
        c_run_as_non_root = sc.get("runAsNonRoot")
        c_run_as_user = sc.get("runAsUser")
        if not (c_run_as_non_root or pod_run_as_non_root):
            if not (c_run_as_user and c_run_as_user > 0) and not (pod_run_as_user and pod_run_as_user > 0):
                findings.append(PSSFinding(
                    namespace=namespace,
                    resource=f"{pod_name}/{c_name}",
                    level="restricted",
                    violation="Container may run as root (runAsNonRoot not set)",
                    severity="HIGH",
                    remediation="Set runAsNonRoot: true and runAsUser to non-zero value"
                ))

        # Check capabilities
        caps = sc.get("capabilities", {})
        drop_caps = [c.upper() for c in (caps.get("drop") or [])]
        add_caps = [c.upper() for c in (caps.get("add") or [])]

        if "ALL" not in drop_caps:
            findings.append(PSSFinding(
                namespace=namespace,
                resource=f"{pod_name}/{c_name}",
                level="restricted",
                violation="Capabilities not dropped (missing drop: ALL)",
                severity="HIGH",
                remediation="Add capabilities: drop: ['ALL'] to security context"
            ))

        allowed_add = {"NET_BIND_SERVICE"}
        extra_caps = set(add_caps) - allowed_add
        if extra_caps:
            findings.append(PSSFinding(
                namespace=namespace,
                resource=f"{pod_name}/{c_name}",
                level="restricted",
                violation=f"Disallowed capabilities added: {extra_caps}",
                severity="HIGH",
                remediation="Only NET_BIND_SERVICE may be added in restricted profile"
            ))

        # Check seccomp
        c_seccomp = sc.get("seccompProfile", {})
        c_seccomp_type = c_seccomp.get("type", pod_seccomp_type)
        if c_seccomp_type not in ("RuntimeDefault", "Localhost"):
            findings.append(PSSFinding(
                namespace=namespace,
                resource=f"{pod_name}/{c_name}",
                level="restricted",
                violation=f"Seccomp profile not set or is '{c_seccomp_type}'",
                severity="MEDIUM",
                remediation="Set seccompProfile.type to RuntimeDefault or Localhost"
            ))

        # Check readOnlyRootFilesystem (recommended, not required by PSS)
        if not sc.get("readOnlyRootFilesystem", False):
            findings.append(PSSFinding(
                namespace=namespace,
                resource=f"{pod_name}/{c_name}",
                level="restricted",
                violation="Root filesystem is not read-only (recommended)",
                severity="MEDIUM",
                remediation="Set readOnlyRootFilesystem: true and use emptyDir for writable paths"
            ))

    return findings


def audit_cluster(report: PSSReport):
    """Audit all namespaces and pods for PSS compliance."""
    # Get all namespaces
    ns_data, err = run_kubectl(["get", "namespaces"])
    if ns_data is None:
        print(f"[!] Failed to get namespaces: {err}")
        return

    namespaces = ns_data.get("items", [])
    print(f"[*] Found {len(namespaces)} namespaces")

    for ns in namespaces:
        ns_name = ns["metadata"]["name"]
        pss_labels = get_namespace_pss_labels(ns)
        report.namespaces_audited += 1

        enforce_level = pss_labels["enforce"]
        print(f"\n[*] Namespace: {ns_name} (enforce={enforce_level})")

        # Flag namespaces without PSS enforcement
        if enforce_level == "not-set":
            report.findings.append(PSSFinding(
                namespace=ns_name,
                resource="namespace",
                level="baseline",
                violation="No PSS enforcement label set",
                severity="HIGH" if ns_name not in ("kube-system", "kube-public", "kube-node-lease") else "MEDIUM",
                remediation=f"kubectl label namespace {ns_name} pod-security.kubernetes.io/enforce=baseline"
            ))

        # Get pods in namespace
        pods_data, err = run_kubectl(["get", "pods", "-n", ns_name])
        if pods_data is None:
            continue

        pods = pods_data.get("items", [])
        for pod in pods:
            pod_name = pod["metadata"]["name"]
            pod_spec = pod.get("spec", {})
            report.pods_audited += 1

            pod_findings = check_restricted_compliance(pod_spec, pod_name, ns_name)
            if pod_findings:
                report.non_compliant_pods += 1
                report.findings.extend(pod_findings)
            else:
                report.compliant_pods += 1


def print_report(report: PSSReport):
    """Print audit results."""
    print("\n" + "=" * 70)
    print("KUBERNETES POD SECURITY STANDARDS AUDIT REPORT")
    print("=" * 70)
    print(f"Namespaces audited:    {report.namespaces_audited}")
    print(f"Pods audited:          {report.pods_audited}")
    print(f"Compliant pods:        {report.compliant_pods}")
    print(f"Non-compliant pods:    {report.non_compliant_pods}")
    print(f"Total findings:        {len(report.findings)}")

    if report.pods_audited > 0:
        compliance_rate = (report.compliant_pods / report.pods_audited) * 100
        print(f"Compliance rate:       {compliance_rate:.1f}%")

    print("=" * 70)

    # Group by severity
    for severity in ["CRITICAL", "HIGH", "MEDIUM"]:
        severity_findings = [f for f in report.findings if f.severity == severity]
        if severity_findings:
            print(f"\n{severity} FINDINGS ({len(severity_findings)}):")
            print("-" * 70)
            for f in severity_findings:
                print(f"  [{f.namespace}] {f.resource}")
                print(f"    Level: {f.level} | Violation: {f.violation}")
                print(f"    Fix: {f.remediation}")
                print()


def main():
    print("[*] Kubernetes Pod Security Standards Compliance Checker")
    print("[*] Checking against restricted profile\n")

    report = PSSReport()
    audit_cluster(report)
    print_report(report)

    # Save JSON report
    output = {
        "summary": {
            "namespaces": report.namespaces_audited,
            "pods_audited": report.pods_audited,
            "compliant": report.compliant_pods,
            "non_compliant": report.non_compliant_pods,
        },
        "findings": [
            {
                "namespace": f.namespace,
                "resource": f.resource,
                "level": f.level,
                "violation": f.violation,
                "severity": f.severity,
                "remediation": f.remediation,
            }
            for f in report.findings
        ],
    }

    with open("pss_audit_report.json", "w") as f:
        json.dump(output, f, indent=2)
    print("[*] Report saved to pss_audit_report.json")

    critical_high = [f for f in report.findings if f.severity in ("CRITICAL", "HIGH")]
    if critical_high:
        print(f"\n[!] {len(critical_high)} CRITICAL/HIGH findings require attention")
        sys.exit(1)


if __name__ == "__main__":
    main()
