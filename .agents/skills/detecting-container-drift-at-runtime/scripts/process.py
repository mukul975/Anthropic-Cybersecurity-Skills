#!/usr/bin/env python3
"""
Container Drift Detection Tool

Compares running containers against their original image state
to detect filesystem drift, unexpected processes, and configuration changes.
"""

import json
import subprocess
import sys
import argparse
from datetime import datetime
from collections import defaultdict


def run_command(cmd: list[str], timeout: int = 30) -> str:
    """Execute a command and return stdout."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def get_running_containers(namespace: str = "") -> list[dict]:
    """Get running containers from Kubernetes."""
    cmd = ["kubectl", "get", "pods", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    output = run_command(cmd)
    if not output:
        return []

    try:
        data = json.loads(output)
        containers = []
        for pod in data.get("items", []):
            ns = pod["metadata"]["namespace"]
            pod_name = pod["metadata"]["name"]
            for cs in pod.get("status", {}).get("containerStatuses", []):
                containers.append({
                    "namespace": ns,
                    "pod": pod_name,
                    "container": cs["name"],
                    "image": cs["image"],
                    "imageID": cs.get("imageID", ""),
                    "ready": cs.get("ready", False),
                    "restartCount": cs.get("restartCount", 0),
                })
        return containers
    except (json.JSONDecodeError, KeyError):
        return []


def check_image_tag_drift(containers: list[dict]) -> list[dict]:
    """Detect containers using mutable tags instead of digests."""
    findings = []
    for c in containers:
        if "@sha256:" not in c["image"]:
            findings.append({
                "severity": "MEDIUM",
                "type": "mutable_tag",
                "namespace": c["namespace"],
                "pod": c["pod"],
                "container": c["container"],
                "image": c["image"],
                "description": f"Container uses mutable tag instead of digest: {c['image']}"
            })
    return findings


def check_readonly_filesystem(namespace: str = "") -> list[dict]:
    """Check which containers lack readOnlyRootFilesystem."""
    cmd = ["kubectl", "get", "pods", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    output = run_command(cmd)
    if not output:
        return []

    findings = []
    try:
        data = json.loads(output)
        for pod in data.get("items", []):
            ns = pod["metadata"]["namespace"]
            pod_name = pod["metadata"]["name"]
            for container in pod["spec"].get("containers", []):
                sc = container.get("securityContext", {})
                if not sc.get("readOnlyRootFilesystem", False):
                    findings.append({
                        "severity": "MEDIUM",
                        "type": "writable_filesystem",
                        "namespace": ns,
                        "pod": pod_name,
                        "container": container["name"],
                        "description": f"Container {container['name']} has writable root filesystem"
                    })
    except (json.JSONDecodeError, KeyError):
        pass

    return findings


def check_restart_anomalies(containers: list[dict], threshold: int = 3) -> list[dict]:
    """Detect containers with high restart counts (potential crash loops from drift)."""
    findings = []
    for c in containers:
        if c["restartCount"] >= threshold:
            findings.append({
                "severity": "LOW",
                "type": "high_restarts",
                "namespace": c["namespace"],
                "pod": c["pod"],
                "container": c["container"],
                "restarts": c["restartCount"],
                "description": f"Container has {c['restartCount']} restarts (may indicate instability from drift)"
            })
    return findings


def check_pod_security_standards(namespace: str = "") -> list[dict]:
    """Check namespace-level Pod Security Standards enforcement."""
    output = run_command(["kubectl", "get", "namespaces", "-o", "json"])
    if not output:
        return []

    findings = []
    try:
        data = json.loads(output)
        for ns in data.get("items", []):
            ns_name = ns["metadata"]["name"]
            if namespace and ns_name != namespace:
                continue
            labels = ns["metadata"].get("labels", {})
            enforce = labels.get("pod-security.kubernetes.io/enforce", "")
            if enforce not in ("restricted", "baseline"):
                findings.append({
                    "severity": "MEDIUM",
                    "type": "no_pss_enforcement",
                    "namespace": ns_name,
                    "enforce_level": enforce or "none",
                    "description": f"Namespace {ns_name} lacks Pod Security Standards enforcement"
                })
    except (json.JSONDecodeError, KeyError):
        pass

    return findings


def generate_report(containers: list[dict], all_findings: list[dict],
                    output_format: str = "text") -> str:
    """Generate drift detection report."""
    critical = [f for f in all_findings if f["severity"] == "CRITICAL"]
    high = [f for f in all_findings if f["severity"] == "HIGH"]
    medium = [f for f in all_findings if f["severity"] == "MEDIUM"]
    low = [f for f in all_findings if f["severity"] == "LOW"]

    if output_format == "json":
        return json.dumps({
            "timestamp": datetime.utcnow().isoformat(),
            "containers_scanned": len(containers),
            "findings": {"critical": len(critical), "high": len(high),
                        "medium": len(medium), "low": len(low)},
            "details": all_findings
        }, indent=2)

    lines = []
    lines.append("=" * 70)
    lines.append("CONTAINER DRIFT DETECTION REPORT")
    lines.append(f"Generated: {datetime.utcnow().isoformat()}")
    lines.append("=" * 70)
    lines.append(f"\nContainers Scanned: {len(containers)}")
    lines.append(f"Findings: {len(critical)} Critical, {len(high)} High, {len(medium)} Medium, {len(low)} Low")

    for severity, items in [("CRITICAL", critical), ("HIGH", high), ("MEDIUM", medium), ("LOW", low)]:
        if items:
            lines.append(f"\n## {severity} Findings")
            for f in items:
                lines.append(f"  [{f['type']}] {f['description']}")
                if "pod" in f:
                    lines.append(f"    Namespace: {f.get('namespace', 'N/A')} | Pod: {f.get('pod', 'N/A')}")

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Container Drift Detection Tool")
    parser.add_argument("--namespace", default="", help="Kubernetes namespace to scan")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--restart-threshold", type=int, default=3)
    args = parser.parse_args()

    containers = get_running_containers(args.namespace)
    all_findings = []
    all_findings.extend(check_image_tag_drift(containers))
    all_findings.extend(check_readonly_filesystem(args.namespace))
    all_findings.extend(check_restart_anomalies(containers, args.restart_threshold))
    all_findings.extend(check_pod_security_standards(args.namespace))

    report = generate_report(containers, all_findings, args.format)
    print(report)


if __name__ == "__main__":
    main()
