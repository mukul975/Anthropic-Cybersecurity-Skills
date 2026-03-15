#!/usr/bin/env python3
"""Container escape detection agent using Falco output parsing and audit log analysis.

Monitors for container escape indicators by parsing Falco JSON alerts,
auditd logs, and Docker inspect data for privileged/vulnerable containers.
"""

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ESCAPE_VECTORS = {
    "nsenter": {"severity": "CRITICAL", "mitre": "T1611", "desc": "Namespace escape via nsenter"},
    "unshare": {"severity": "CRITICAL", "mitre": "T1611", "desc": "Namespace manipulation"},
    "mount": {"severity": "HIGH", "mitre": "T1611", "desc": "Host filesystem mount"},
    "modprobe": {"severity": "CRITICAL", "mitre": "T1611", "desc": "Kernel module loading"},
    "insmod": {"severity": "CRITICAL", "mitre": "T1611", "desc": "Kernel module insertion"},
    "chroot": {"severity": "HIGH", "mitre": "T1611", "desc": "Chroot escape attempt"},
}

SENSITIVE_PATHS = [
    "/var/run/docker.sock", "/proc/sysrq-trigger", "/proc/kcore",
    "/proc/kmsg", "/proc/kallsyms", "/sys/kernel",
    "/etc/shadow", "/etc/kubernetes/admin.conf",
]


def parse_falco_json(filepath):
    alerts = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
                if any(tag in evt.get("tags", []) for tag in ["escape", "container"]):
                    alerts.append({
                        "time": evt.get("time", ""),
                        "rule": evt.get("rule", ""),
                        "priority": evt.get("priority", ""),
                        "output": evt.get("output", ""),
                        "output_fields": evt.get("output_fields", {}),
                    })
            except json.JSONDecodeError:
                continue
    return alerts


def parse_auditd_escape_events(filepath):
    findings = []
    escape_keys = {"container_escape", "container_mount", "kernel_module",
                   "docker_socket", "process_trace"}
    with open(filepath, "r") as f:
        for line in f:
            for key in escape_keys:
                if f'key="{key}"' in line or f"key={key}" in line:
                    timestamp = re.search(r'msg=audit\((\d+\.\d+):', line)
                    syscall = re.search(r'syscall=(\w+)', line)
                    exe = re.search(r'exe="([^"]+)"', line)
                    findings.append({
                        "timestamp": timestamp.group(1) if timestamp else "",
                        "key": key,
                        "syscall": syscall.group(1) if syscall else "",
                        "exe": exe.group(1) if exe else "",
                        "severity": "CRITICAL",
                        "raw": line.strip()[:200],
                    })
    return findings


def check_privileged_containers():
    containers = []
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.ID}} {{.Names}} {{.Image}}"],
            capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return containers
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split(None, 2)
            cid = parts[0]
            inspect = subprocess.run(
                ["docker", "inspect", "--format",
                 "{{.HostConfig.Privileged}} {{.HostConfig.PidMode}} "
                 "{{range .HostConfig.Binds}}{{.}} {{end}}"],
                capture_output=True, text=True, timeout=10)
            if inspect.returncode == 0:
                info = inspect.stdout.strip()
                findings = []
                if "true" in info.split()[0:1]:
                    findings.append("privileged_mode")
                if "host" in info:
                    findings.append("host_pid_namespace")
                if "/var/run/docker.sock" in info:
                    findings.append("docker_socket_mounted")
                if findings:
                    containers.append({
                        "container_id": cid,
                        "name": parts[1] if len(parts) > 1 else "",
                        "image": parts[2] if len(parts) > 2 else "",
                        "escape_risks": findings,
                        "severity": "CRITICAL" if "privileged_mode" in findings else "HIGH",
                    })
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return containers


def check_dangerous_capabilities(container_id):
    dangerous_caps = {"SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_RAWIO",
                      "SYS_MODULE", "DAC_READ_SEARCH"}
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.HostConfig.CapAdd}}", container_id],
            capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            caps = set(re.findall(r'\b([A-Z_]+)\b', result.stdout))
            found = caps & dangerous_caps
            return [{"capability": c, "severity": "CRITICAL"} for c in found]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return []


def main():
    parser = argparse.ArgumentParser(description="Container Escape Detector")
    parser.add_argument("--falco-log", help="Path to Falco JSON output log")
    parser.add_argument("--audit-log", help="Path to auditd log file")
    parser.add_argument("--check-containers", action="store_true",
                        help="Check running containers for escape risks")
    parser.add_argument("--container-id", help="Check specific container capabilities")
    args = parser.parse_args()

    results = {"timestamp": datetime.utcnow().isoformat() + "Z", "findings": []}

    if args.falco_log:
        alerts = parse_falco_json(args.falco_log)
        results["falco_alerts"] = alerts
        results["findings"].extend([{"source": "falco", **a} for a in alerts])

    if args.audit_log:
        audit = parse_auditd_escape_events(args.audit_log)
        results["audit_events"] = audit
        results["findings"].extend([{"source": "auditd", **a} for a in audit])

    if args.check_containers:
        priv = check_privileged_containers()
        results["privileged_containers"] = priv
        results["findings"].extend([{"source": "docker_inspect", **c} for c in priv])

    if args.container_id:
        caps = check_dangerous_capabilities(args.container_id)
        results["dangerous_capabilities"] = caps
        results["findings"].extend([{"source": "capabilities", **c} for c in caps])

    results["total_findings"] = len(results["findings"])
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
