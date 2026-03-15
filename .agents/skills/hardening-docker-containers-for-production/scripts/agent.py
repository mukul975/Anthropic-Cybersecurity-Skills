#!/usr/bin/env python3
"""Agent for auditing Docker container security and applying CIS hardening."""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone


def get_running_containers():
    """List running Docker containers with details."""
    try:
        result = subprocess.check_output(
            ["docker", "ps", "--format", "{{json .}}"],
            text=True, errors="replace", timeout=10
        )
        containers = []
        for line in result.strip().splitlines():
            if line:
                containers.append(json.loads(line))
        return containers
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return []


def inspect_container(container_id):
    """Get detailed container configuration."""
    try:
        result = subprocess.check_output(
            ["docker", "inspect", container_id],
            text=True, errors="replace", timeout=10
        )
        return json.loads(result)[0]
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return {}


def audit_container(container_id):
    """Audit a container against CIS Docker Benchmark checks."""
    findings = []
    config = inspect_container(container_id)
    if not config:
        return findings
    host_config = config.get("HostConfig", {})
    name = config.get("Name", container_id)

    if host_config.get("Privileged"):
        findings.append({"check": "CIS 5.4", "issue": "Container runs privileged", "severity": "CRITICAL"})
    if host_config.get("NetworkMode") == "host":
        findings.append({"check": "CIS 5.10", "issue": "Uses host network", "severity": "HIGH"})
    if host_config.get("PidMode") == "host":
        findings.append({"check": "CIS 5.15", "issue": "Shares host PID namespace", "severity": "HIGH"})
    if host_config.get("IpcMode") == "host":
        findings.append({"check": "CIS 5.16", "issue": "Shares host IPC namespace", "severity": "HIGH"})

    user = config.get("Config", {}).get("User", "")
    if not user or user == "root" or user == "0":
        findings.append({"check": "CIS 4.1", "issue": "Container runs as root", "severity": "HIGH"})

    cap_add = host_config.get("CapAdd") or []
    if "SYS_ADMIN" in cap_add:
        findings.append({"check": "CIS 5.3", "issue": "SYS_ADMIN capability added", "severity": "CRITICAL"})
    if "NET_ADMIN" in cap_add:
        findings.append({"check": "CIS 5.3", "issue": "NET_ADMIN capability added", "severity": "HIGH"})

    if not host_config.get("ReadonlyRootfs"):
        findings.append({"check": "CIS 5.12", "issue": "Root filesystem not read-only", "severity": "MEDIUM"})

    memory = host_config.get("Memory", 0)
    if memory == 0:
        findings.append({"check": "CIS 5.14", "issue": "No memory limit set", "severity": "MEDIUM"})

    cpu_shares = host_config.get("CpuShares", 0)
    if cpu_shares == 0:
        findings.append({"check": "CIS 5.13", "issue": "No CPU limit set", "severity": "LOW"})

    restart = host_config.get("RestartPolicy", {}).get("Name", "")
    if restart == "always":
        findings.append({"check": "CIS 5.14", "issue": "RestartPolicy=always (use on-failure)", "severity": "LOW"})

    mounts = host_config.get("Binds") or []
    sensitive = ["/", "/etc", "/var/run/docker.sock", "/proc", "/sys"]
    for mount in mounts:
        src = mount.split(":")[0]
        if src in sensitive:
            findings.append({"check": "CIS 5.5", "issue": f"Sensitive host mount: {src}", "severity": "HIGH"})

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Audit Docker containers against CIS benchmarks"
    )
    parser.add_argument("--container", help="Specific container ID to audit")
    parser.add_argument("--all", action="store_true", help="Audit all running containers")
    parser.add_argument("--output", "-o", help="Output JSON report")
    args = parser.parse_args()

    print("[*] Docker Container Hardening Audit Agent")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "audits": []}

    if args.all:
        containers = get_running_containers()
        print(f"[*] Found {len(containers)} running containers")
        for c in containers:
            cid = c.get("ID", "")
            findings = audit_container(cid)
            report["audits"].append({"container": c.get("Names", cid), "findings": findings})
    elif args.container:
        findings = audit_container(args.container)
        report["audits"].append({"container": args.container, "findings": findings})

    total = sum(len(a["findings"]) for a in report["audits"])
    critical = sum(1 for a in report["audits"] for f in a["findings"] if f["severity"] == "CRITICAL")
    print(f"[*] Total findings: {total} (CRITICAL: {critical})")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
