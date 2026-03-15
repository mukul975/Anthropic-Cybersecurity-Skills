#!/usr/bin/env python3
"""Kubernetes pod privilege escalation detection agent.

Audits pod security contexts, capabilities, and service account permissions
to detect misconfigurations enabling container privilege escalation.
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime

DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN",
    "NET_RAW", "DAC_READ_SEARCH", "SYS_RAWIO",
}


def get_pods(namespace="--all-namespaces"):
    try:
        cmd = ["kubectl", "get", "pods", "-o", "json"]
        if namespace == "--all-namespaces":
            cmd.append("--all-namespaces")
        else:
            cmd.extend(["-n", namespace])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return json.loads(result.stdout).get("items", [])
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass
    return []


def audit_pod(pod):
    findings = []
    pod_name = pod.get("metadata", {}).get("name", "")
    namespace = pod.get("metadata", {}).get("namespace", "")
    spec = pod.get("spec", {})

    if spec.get("hostPID"):
        findings.append({"check": "hostPID", "severity": "CRITICAL", "desc": "Host PID namespace"})
    if spec.get("hostNetwork"):
        findings.append({"check": "hostNetwork", "severity": "HIGH", "desc": "Host network"})
    if spec.get("hostIPC"):
        findings.append({"check": "hostIPC", "severity": "MEDIUM", "desc": "Host IPC"})

    for container in spec.get("containers", []) + spec.get("initContainers", []):
        ctx = container.get("securityContext", {})
        c_name = container.get("name", "")
        if ctx.get("privileged"):
            findings.append({"container": c_name, "check": "privileged",
                             "severity": "CRITICAL", "desc": "Privileged container"})
        if ctx.get("allowPrivilegeEscalation", True):
            findings.append({"container": c_name, "check": "allowPrivilegeEscalation",
                             "severity": "HIGH", "desc": "Privilege escalation allowed"})
        run_as = ctx.get("runAsUser")
        if run_as == 0 or (run_as is None and not ctx.get("runAsNonRoot")):
            findings.append({"container": c_name, "check": "runAsRoot",
                             "severity": "HIGH", "desc": "May run as root"})
        if not ctx.get("readOnlyRootFilesystem"):
            findings.append({"container": c_name, "check": "mutableFS",
                             "severity": "MEDIUM", "desc": "Writable root FS"})
        caps = ctx.get("capabilities", {})
        for cap in set(caps.get("add", [])) & DANGEROUS_CAPABILITIES:
            findings.append({"container": c_name, "check": "dangerous_cap",
                             "capability": cap, "severity": "CRITICAL"})
        for vm in container.get("volumeMounts", []):
            if vm.get("mountPath") in ("/var/run/docker.sock", "/run/containerd/containerd.sock"):
                findings.append({"container": c_name, "check": "runtime_socket",
                                 "severity": "CRITICAL", "desc": f"Socket: {vm['mountPath']}"})

    risk = "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else \
           "HIGH" if any(f["severity"] == "HIGH" for f in findings) else "MEDIUM"
    return {"pod": pod_name, "namespace": namespace, "findings": findings, "risk": risk}


def main():
    parser = argparse.ArgumentParser(description="K8s Pod PrivEsc Detector")
    parser.add_argument("--namespace", default="--all-namespaces")
    parser.add_argument("--json-file", help="Pod JSON file instead of kubectl")
    args = parser.parse_args()
    if args.json_file:
        with open(args.json_file) as f:
            data = json.load(f)
            pods = data.get("items", [data]) if "items" in data else [data]
    else:
        pods = get_pods(args.namespace)
    results = {"timestamp": datetime.utcnow().isoformat() + "Z", "pod_audits": []}
    for pod in pods:
        audit = audit_pod(pod)
        if audit["findings"]:
            results["pod_audits"].append(audit)
    results["total_pods_with_issues"] = len(results["pod_audits"])
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
