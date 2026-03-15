#!/usr/bin/env python3
"""Agent for detecting container escape vectors in Kubernetes."""

import json
import argparse
from datetime import datetime

from kubernetes import client, config


DANGEROUS_CAPS = [
    "SYS_ADMIN", "SYS_PTRACE", "SYS_RAWIO", "SYS_MODULE",
    "DAC_READ_SEARCH", "NET_ADMIN", "NET_RAW",
]

DANGEROUS_HOST_PATHS = ["/", "/etc", "/root", "/var/run/docker.sock",
                        "/var/run/crio", "/proc", "/sys"]


def load_kube_config():
    """Load Kubernetes configuration."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()


def check_privileged_containers(v1):
    """Find pods running privileged containers."""
    findings = []
    pods = v1.list_pod_for_all_namespaces()
    for pod in pods.items:
        for container in pod.spec.containers or []:
            sc = container.security_context
            if sc and sc.privileged:
                findings.append({
                    "namespace": pod.metadata.namespace,
                    "pod": pod.metadata.name,
                    "container": container.name,
                    "issue": "privileged container",
                    "severity": "CRITICAL",
                })
    return findings


def check_dangerous_capabilities(v1):
    """Find containers with dangerous Linux capabilities."""
    findings = []
    pods = v1.list_pod_for_all_namespaces()
    for pod in pods.items:
        for container in pod.spec.containers or []:
            sc = container.security_context
            if not sc or not sc.capabilities or not sc.capabilities.add:
                continue
            for cap in sc.capabilities.add:
                if cap in DANGEROUS_CAPS:
                    findings.append({
                        "namespace": pod.metadata.namespace,
                        "pod": pod.metadata.name,
                        "container": container.name,
                        "capability": cap,
                        "severity": "HIGH",
                    })
    return findings


def check_host_namespaces(v1):
    """Find pods sharing host PID, network, or IPC namespaces."""
    findings = []
    pods = v1.list_pod_for_all_namespaces()
    for pod in pods.items:
        spec = pod.spec
        ns_issues = []
        if spec.host_pid:
            ns_issues.append("hostPID")
        if spec.host_network:
            ns_issues.append("hostNetwork")
        if spec.host_ipc:
            ns_issues.append("hostIPC")
        if ns_issues:
            findings.append({
                "namespace": pod.metadata.namespace,
                "pod": pod.metadata.name,
                "host_namespaces": ns_issues,
                "severity": "HIGH",
            })
    return findings


def check_dangerous_mounts(v1):
    """Find pods with dangerous hostPath volume mounts."""
    findings = []
    pods = v1.list_pod_for_all_namespaces()
    for pod in pods.items:
        for vol in pod.spec.volumes or []:
            if not vol.host_path:
                continue
            path = vol.host_path.path
            if any(path == dp or path.startswith(dp + "/") for dp in DANGEROUS_HOST_PATHS):
                findings.append({
                    "namespace": pod.metadata.namespace,
                    "pod": pod.metadata.name,
                    "volume": vol.name,
                    "host_path": path,
                    "severity": "CRITICAL" if path in ("/", "/var/run/docker.sock") else "HIGH",
                })
    return findings


def check_docker_socket(v1):
    """Specifically detect Docker/CRI socket mounts."""
    findings = []
    sockets = ["/var/run/docker.sock", "/var/run/crio/crio.sock",
               "/run/containerd/containerd.sock"]
    pods = v1.list_pod_for_all_namespaces()
    for pod in pods.items:
        for vol in pod.spec.volumes or []:
            if vol.host_path and vol.host_path.path in sockets:
                findings.append({
                    "namespace": pod.metadata.namespace,
                    "pod": pod.metadata.name,
                    "socket_path": vol.host_path.path,
                    "severity": "CRITICAL",
                })
    return findings


def check_root_containers(v1):
    """Find containers running as root."""
    findings = []
    pods = v1.list_pod_for_all_namespaces()
    for pod in pods.items:
        for container in pod.spec.containers or []:
            sc = container.security_context
            if sc and sc.run_as_user == 0:
                findings.append({
                    "namespace": pod.metadata.namespace,
                    "pod": pod.metadata.name,
                    "container": container.name,
                    "issue": "running as UID 0",
                    "severity": "MEDIUM",
                })
            elif not sc or sc.run_as_non_root is not True:
                findings.append({
                    "namespace": pod.metadata.namespace,
                    "pod": pod.metadata.name,
                    "container": container.name,
                    "issue": "runAsNonRoot not enforced",
                    "severity": "LOW",
                })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Container Escape Detection Agent")
    parser.add_argument("--output", default="container_escape_report.json")
    parser.add_argument("--action", choices=[
        "privileged", "capabilities", "namespaces", "mounts", "socket", "full_scan"
    ], default="full_scan")
    args = parser.parse_args()

    load_kube_config()
    v1 = client.CoreV1Api()
    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.action in ("privileged", "full_scan"):
        findings = check_privileged_containers(v1)
        report["findings"]["privileged"] = findings
        print(f"[+] Privileged containers: {len(findings)}")

    if args.action in ("capabilities", "full_scan"):
        findings = check_dangerous_capabilities(v1)
        report["findings"]["dangerous_caps"] = findings
        print(f"[+] Dangerous capabilities: {len(findings)}")

    if args.action in ("namespaces", "full_scan"):
        findings = check_host_namespaces(v1)
        report["findings"]["host_namespaces"] = findings
        print(f"[+] Host namespace sharing: {len(findings)}")

    if args.action in ("mounts", "full_scan"):
        findings = check_dangerous_mounts(v1)
        report["findings"]["dangerous_mounts"] = findings
        print(f"[+] Dangerous mounts: {len(findings)}")

    if args.action in ("socket", "full_scan"):
        findings = check_docker_socket(v1)
        report["findings"]["socket_mounts"] = findings
        print(f"[+] Container runtime socket mounts: {len(findings)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
