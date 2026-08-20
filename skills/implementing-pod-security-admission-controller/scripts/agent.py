#!/usr/bin/env python3
"""Kubernetes Pod Security Admission audit agent.

Audits Kubernetes namespaces and workloads for Pod Security Standards (PSS)
compliance using kubectl. Checks namespace labels for enforce/audit/warn
modes, analyzes pod specs against Baseline and Restricted profiles, and
reports violations.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone


def run_kubectl(args_list, timeout=60):
    """Execute a kubectl command and return parsed JSON output."""
    cmd = ["kubectl"] + args_list + ["-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        print(f"[!] kubectl error: {result.stderr[:200]}", file=sys.stderr)
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def get_namespaces():
    """Get all namespaces with their PSA labels."""
    print("[*] Fetching namespaces...")
    data = run_kubectl(["get", "namespaces"])
    if not data:
        return []
    namespaces = []
    for ns in data.get("items", []):
        name = ns.get("metadata", {}).get("name", "")
        labels = ns.get("metadata", {}).get("labels", {})
        psa_enforce = labels.get("pod-security.kubernetes.io/enforce", "")
        psa_audit = labels.get("pod-security.kubernetes.io/audit", "")
        psa_warn = labels.get("pod-security.kubernetes.io/warn", "")
        psa_enforce_version = labels.get("pod-security.kubernetes.io/enforce-version", "")
        namespaces.append({
            "name": name,
            "enforce": psa_enforce,
            "audit": psa_audit,
            "warn": psa_warn,
            "enforce_version": psa_enforce_version,
            "has_psa": bool(psa_enforce or psa_audit or psa_warn),
        })
    print(f"[+] Found {len(namespaces)} namespaces")
    return namespaces


def audit_namespace_psa(namespaces):
    """Audit PSA label configuration across namespaces."""
    findings = []
    system_ns = {"kube-system", "kube-public", "kube-node-lease", "default"}

    for ns in namespaces:
        name = ns["name"]
        if name in system_ns:
            continue

        if not ns["has_psa"]:
            findings.append({
                "namespace": name,
                "check": "No PSA labels configured",
                "severity": "HIGH",
                "recommendation": (
                    f"Apply PSA labels: kubectl label namespace {name} "
                    f"pod-security.kubernetes.io/enforce=baseline "
                    f"pod-security.kubernetes.io/warn=restricted"
                ),
            })
        elif ns["enforce"] == "privileged":
            findings.append({
                "namespace": name,
                "check": "PSA enforce set to privileged (permissive)",
                "severity": "HIGH",
                "recommendation": "Upgrade to baseline or restricted enforcement",
            })
        elif ns["enforce"] == "baseline" and not ns["warn"]:
            findings.append({
                "namespace": name,
                "check": "Enforce baseline but no warn=restricted",
                "severity": "MEDIUM",
                "recommendation": (
                    f"Add warn label: kubectl label namespace {name} "
                    f"pod-security.kubernetes.io/warn=restricted"
                ),
            })
        elif ns["enforce"] == "restricted":
            findings.append({
                "namespace": name,
                "check": "PSA enforce=restricted (most secure)",
                "severity": "INFO",
            })

    return findings


def audit_pod_security(namespace=None):
    """Audit pods for security spec violations against PSS profiles."""
    findings = []
    cmd = ["get", "pods", "--all-namespaces"] if not namespace else ["get", "pods", "-n", namespace]
    data = run_kubectl(cmd)
    if not data:
        return findings

    for pod in data.get("items", []):
        pod_name = pod.get("metadata", {}).get("name", "")
        pod_ns = pod.get("metadata", {}).get("namespace", "")
        spec = pod.get("spec", {})

        # Check host namespaces
        if spec.get("hostNetwork"):
            findings.append({
                "namespace": pod_ns, "pod": pod_name,
                "check": "hostNetwork enabled",
                "severity": "CRITICAL", "profile": "baseline",
            })
        if spec.get("hostPID"):
            findings.append({
                "namespace": pod_ns, "pod": pod_name,
                "check": "hostPID enabled",
                "severity": "CRITICAL", "profile": "baseline",
            })
        if spec.get("hostIPC"):
            findings.append({
                "namespace": pod_ns, "pod": pod_name,
                "check": "hostIPC enabled",
                "severity": "HIGH", "profile": "baseline",
            })

        containers = spec.get("containers", []) + spec.get("initContainers", [])
        for container in containers:
            c_name = container.get("name", "")
            sec_ctx = container.get("securityContext", {})

            # Privileged container
            if sec_ctx.get("privileged"):
                findings.append({
                    "namespace": pod_ns, "pod": pod_name, "container": c_name,
                    "check": "Privileged container",
                    "severity": "CRITICAL", "profile": "baseline",
                })

            # Run as root
            if sec_ctx.get("runAsUser") == 0:
                findings.append({
                    "namespace": pod_ns, "pod": pod_name, "container": c_name,
                    "check": "Running as root (UID 0)",
                    "severity": "HIGH", "profile": "restricted",
                })

            # Missing runAsNonRoot
            if not sec_ctx.get("runAsNonRoot"):
                findings.append({
                    "namespace": pod_ns, "pod": pod_name, "container": c_name,
                    "check": "runAsNonRoot not set",
                    "severity": "MEDIUM", "profile": "restricted",
                })

            # Writable root filesystem
            if not sec_ctx.get("readOnlyRootFilesystem"):
                findings.append({
                    "namespace": pod_ns, "pod": pod_name, "container": c_name,
                    "check": "Root filesystem not read-only",
                    "severity": "MEDIUM", "profile": "restricted",
                })

            # Privilege escalation
            if sec_ctx.get("allowPrivilegeEscalation", True):
                findings.append({
                    "namespace": pod_ns, "pod": pod_name, "container": c_name,
                    "check": "allowPrivilegeEscalation not disabled",
                    "severity": "MEDIUM", "profile": "restricted",
                })

            # Dangerous capabilities
            caps = sec_ctx.get("capabilities", {})
            added = caps.get("add", [])
            dangerous_caps = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL",
                              "NET_RAW", "SYS_RAWIO", "SYS_MODULE"}
            for cap in added:
                if cap.upper() in dangerous_caps:
                    findings.append({
                        "namespace": pod_ns, "pod": pod_name, "container": c_name,
                        "check": f"Dangerous capability added: {cap}",
                        "severity": "CRITICAL" if cap.upper() in ("SYS_ADMIN", "ALL") else "HIGH",
                        "profile": "baseline",
                    })

            # Drop ALL capabilities check (restricted)
            dropped = [c.upper() for c in caps.get("drop", [])]
            if "ALL" not in dropped:
                findings.append({
                    "namespace": pod_ns, "pod": pod_name, "container": c_name,
                    "check": "Capabilities not dropping ALL",
                    "severity": "LOW", "profile": "restricted",
                })

            # Host ports
            for port in container.get("ports", []):
                if port.get("hostPort"):
                    findings.append({
                        "namespace": pod_ns, "pod": pod_name, "container": c_name,
                        "check": f"hostPort exposed: {port['hostPort']}",
                        "severity": "HIGH", "profile": "baseline",
                    })

    return findings


def format_summary(ns_findings, pod_findings, namespaces):
    """Print audit summary."""
    print(f"\n{'='*60}")
    print("  Pod Security Admission Audit Report")
    print(f"{'='*60}")
    print(f"  Namespaces      : {len(namespaces)}")
    psa_configured = sum(1 for ns in namespaces if ns["has_psa"])
    print(f"  PSA Configured  : {psa_configured}/{len(namespaces)}")
    print(f"  NS Findings     : {len(ns_findings)}")
    print(f"  Pod Findings    : {len(pod_findings)}")

    all_findings = ns_findings + pod_findings
    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\n  By Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            print(f"    {sev:10s}: {count}")

    print("\n  Namespace PSA Status:")
    for ns in namespaces:
        if ns["name"] in ("kube-system", "kube-public", "kube-node-lease"):
            continue
        status = ns["enforce"] or "none"
        print(f"    {ns['name']:30s}: enforce={status:12s} audit={ns['audit'] or 'none':12s}")

    if pod_findings:
        print("\n  Top Pod Violations:")
        for f in pod_findings[:15]:
            if f["severity"] in ("CRITICAL", "HIGH"):
                print(f"    [{f['severity']:8s}] {f.get('namespace', '')}/"
                      f"{f.get('pod', '')}: {f['check']}")

    return severity_counts


def main():
    parser = argparse.ArgumentParser(
        description="Kubernetes Pod Security Admission audit agent"
    )
    parser.add_argument("--namespace", "-n", help="Specific namespace to audit (default: all)")
    parser.add_argument("--skip-pods", action="store_true", help="Only audit namespace labels")
    parser.add_argument("--kubeconfig", help="Path to kubeconfig file")
    parser.add_argument("--context", help="Kubernetes context to use")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.kubeconfig:
        os.environ["KUBECONFIG"] = args.kubeconfig

    namespaces = get_namespaces()
    ns_findings = audit_namespace_psa(namespaces)

    pod_findings = []
    if not args.skip_pods:
        pod_findings = audit_pod_security(args.namespace)

    severity_counts = format_summary(ns_findings, pod_findings, namespaces)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "PSA Audit",
        "namespaces": namespaces,
        "namespace_findings": ns_findings,
        "pod_findings": pod_findings,
        "severity_counts": severity_counts,
        "risk_level": (
            "CRITICAL" if severity_counts.get("CRITICAL", 0) > 0
            else "HIGH" if severity_counts.get("HIGH", 0) > 0
            else "MEDIUM" if severity_counts.get("MEDIUM", 0) > 0
            else "LOW"
        ),
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
