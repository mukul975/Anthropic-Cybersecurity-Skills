#!/usr/bin/env python3
"""Agent for performing Docker CIS Benchmark security assessment."""

import json
import argparse
import subprocess
from datetime import datetime


def run_docker_bench():
    """Run docker-bench-security and parse results."""
    cmd = [
        "docker", "run", "--rm", "--net", "host", "--pid", "host",
        "--userns", "host", "--cap-add", "audit_control",
        "-e", "DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST",
        "-v", "/etc:/etc:ro", "-v", "/var/lib:/var/lib:ro",
        "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
        "-v", "/usr/lib/systemd:/usr/lib/systemd:ro",
        "--label", "docker_bench_security",
        "docker/docker-bench-security", "-l", "/dev/stdout"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return parse_bench_output(result.stdout)
    except subprocess.TimeoutExpired:
        return {"error": "docker-bench-security timed out after 600s"}
    except FileNotFoundError:
        return {"error": "docker command not found"}


def parse_bench_output(output):
    """Parse docker-bench-security output into structured findings."""
    findings = []
    current_section = ""
    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.startswith("[INFO]") and "- " in line and any(c.isdigit() for c in line[:20]):
            current_section = line.replace("[INFO]", "").strip()
        elif line.startswith("[WARN]"):
            findings.append({"level": "WARN", "section": current_section, "message": line.replace("[WARN]", "").strip()})
        elif line.startswith("[PASS]"):
            findings.append({"level": "PASS", "section": current_section, "message": line.replace("[PASS]", "").strip()})
        elif line.startswith("[NOTE]"):
            findings.append({"level": "NOTE", "section": current_section, "message": line.replace("[NOTE]", "").strip()})
    warn_count = sum(1 for f in findings if f["level"] == "WARN")
    pass_count = sum(1 for f in findings if f["level"] == "PASS")
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "total_checks": len(findings),
        "warnings": warn_count,
        "passed": pass_count,
        "score_pct": round(pass_count / max(len(findings), 1) * 100, 1),
        "findings": findings,
    }


def check_container_configs():
    """Check running container configurations against CIS benchmarks."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{json .}}"],
            capture_output=True, text=True, timeout=30
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"error": "docker not available"}
    containers = []
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        try:
            c = json.loads(line)
            containers.append(c)
        except json.JSONDecodeError:
            continue
    findings = []
    for container in containers:
        cid = container.get("ID", "")
        name = container.get("Names", "")
        inspect = _inspect_container(cid)
        if isinstance(inspect, dict) and "error" not in inspect:
            issues = _check_container_security(inspect, name)
            findings.append({"container": name, "id": cid, "issues": issues})
    return {"containers_checked": len(findings), "findings": findings}


def _inspect_container(container_id):
    try:
        result = subprocess.run(
            ["docker", "inspect", container_id], capture_output=True, text=True, timeout=10
        )
        data = json.loads(result.stdout)
        return data[0] if data else {}
    except Exception:
        return {"error": "inspect failed"}


def _check_container_security(inspect, name):
    issues = []
    host_config = inspect.get("HostConfig", {})
    if host_config.get("Privileged"):
        issues.append({"severity": "CRITICAL", "check": "5.4", "finding": "Container running in privileged mode"})
    if host_config.get("PidMode") == "host":
        issues.append({"severity": "HIGH", "check": "5.15", "finding": "Container shares host PID namespace"})
    if host_config.get("NetworkMode") == "host":
        issues.append({"severity": "HIGH", "check": "5.13", "finding": "Container shares host network namespace"})
    caps = host_config.get("CapAdd") or []
    dangerous_caps = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL"}
    added_dangerous = set(caps) & dangerous_caps
    if added_dangerous:
        issues.append({"severity": "HIGH", "check": "5.3", "finding": f"Dangerous capabilities added: {added_dangerous}"})
    config = inspect.get("Config", {})
    if config.get("User", "") in ("", "root", "0"):
        issues.append({"severity": "MEDIUM", "check": "4.1", "finding": "Container running as root user"})
    mounts = host_config.get("Binds") or []
    sensitive = ["/etc", "/var/run/docker.sock", "/proc", "/sys"]
    for mount in mounts:
        src = mount.split(":")[0]
        if any(src.startswith(s) for s in sensitive):
            issues.append({"severity": "HIGH", "check": "5.5", "finding": f"Sensitive host path mounted: {src}"})
    return issues


def main():
    parser = argparse.ArgumentParser(description="Docker CIS Benchmark Security Assessment")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("bench", help="Run docker-bench-security")
    sub.add_parser("containers", help="Check running container configurations")
    args = parser.parse_args()
    if args.command == "bench":
        result = run_docker_bench()
    elif args.command == "containers":
        result = check_container_configs()
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
