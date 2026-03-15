#!/usr/bin/env python3
"""
Kubernetes Privilege Escalation Scanner - Scan cluster for pods with
dangerous security configurations that enable privilege escalation.
"""

import json
import subprocess
import sys
import argparse


DANGEROUS_CAPS = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE",
                  "NET_ADMIN", "NET_RAW", "SYS_RAWIO", "SYS_BOOT"}


def get_pods(namespace: str = None) -> list:
    """Get all pods from cluster."""
    cmd = ["kubectl", "get", "pods", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}", file=sys.stderr)
        return []
    return json.loads(result.stdout).get("items", [])


def check_pod_privesc(pod: dict) -> list:
    """Check a pod for privilege escalation risks."""
    findings = []
    name = pod["metadata"]["name"]
    ns = pod["metadata"].get("namespace", "default")
    spec = pod.get("spec", {})

    # Host-level checks
    if spec.get("hostPID"):
        findings.append({"pod": name, "namespace": ns, "severity": "CRITICAL",
                        "finding": "hostPID enabled", "vector": "host-pid"})
    if spec.get("hostNetwork"):
        findings.append({"pod": name, "namespace": ns, "severity": "HIGH",
                        "finding": "hostNetwork enabled", "vector": "host-network"})
    if spec.get("hostIPC"):
        findings.append({"pod": name, "namespace": ns, "severity": "HIGH",
                        "finding": "hostIPC enabled", "vector": "host-ipc"})

    # Volume checks
    for vol in spec.get("volumes", []):
        if vol.get("hostPath"):
            path = vol["hostPath"].get("path", "")
            findings.append({"pod": name, "namespace": ns, "severity": "HIGH",
                           "finding": f"hostPath volume: {path}", "vector": "host-path"})

    # Container checks
    for container in spec.get("containers", []) + spec.get("initContainers", []):
        cname = container.get("name", "unknown")
        sc = container.get("securityContext", {})

        if sc.get("privileged"):
            findings.append({"pod": name, "namespace": ns, "severity": "CRITICAL",
                           "finding": f"Container '{cname}' is privileged", "vector": "privileged"})

        if sc.get("allowPrivilegeEscalation", True):
            findings.append({"pod": name, "namespace": ns, "severity": "MEDIUM",
                           "finding": f"Container '{cname}' allows privilege escalation",
                           "vector": "allow-privesc"})

        if sc.get("runAsUser") == 0:
            findings.append({"pod": name, "namespace": ns, "severity": "HIGH",
                           "finding": f"Container '{cname}' runs as root (UID 0)",
                           "vector": "run-as-root"})

        caps = sc.get("capabilities", {})
        for cap in caps.get("add", []):
            if cap in DANGEROUS_CAPS or cap == "ALL":
                findings.append({"pod": name, "namespace": ns, "severity": "CRITICAL",
                               "finding": f"Container '{cname}' has dangerous cap: {cap}",
                               "vector": "dangerous-capability"})

    return findings


def scan_cluster(namespace: str = None) -> list:
    """Scan entire cluster for privilege escalation risks."""
    pods = get_pods(namespace)
    all_findings = []
    for pod in pods:
        findings = check_pod_privesc(pod)
        all_findings.extend(findings)
    return all_findings


def print_report(findings: list):
    """Print scan report."""
    if not findings:
        print("No privilege escalation risks found.")
        return

    print(f"\n=== Kubernetes Privilege Escalation Scan ===")
    print(f"Total findings: {len(findings)}\n")

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

    print(f"{'Severity':<10} {'Namespace':<20} {'Pod':<35} {'Finding'}")
    print("-" * 100)
    for f in findings:
        print(f"{f['severity']:<10} {f['namespace']:<20} {f['pod']:<35} {f['finding']}")

    # Summary
    from collections import Counter
    by_sev = Counter(f["severity"] for f in findings)
    print(f"\nSummary: CRITICAL={by_sev.get('CRITICAL',0)} HIGH={by_sev.get('HIGH',0)} "
          f"MEDIUM={by_sev.get('MEDIUM',0)} LOW={by_sev.get('LOW',0)}")


def main():
    parser = argparse.ArgumentParser(description="Kubernetes Privilege Escalation Scanner")
    parser.add_argument("--namespace", "-n", help="Scan specific namespace")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium"],
                       help="Exit non-zero if findings at threshold")

    args = parser.parse_args()
    findings = scan_cluster(args.namespace)

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        print_report(findings)

    if args.fail_on:
        threshold = {"critical": ["CRITICAL"], "high": ["CRITICAL", "HIGH"],
                    "medium": ["CRITICAL", "HIGH", "MEDIUM"]}
        blocking = [f for f in findings if f["severity"] in threshold[args.fail_on]]
        sys.exit(1 if blocking else 0)


if __name__ == "__main__":
    main()
