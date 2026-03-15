#!/usr/bin/env python3
"""Falco-based container escape detection agent.

Manages Falco rules, parses Falco alert output, and generates
escape detection reports from Falco JSON event streams.
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ESCAPE_RULE_TAGS = ["container", "escape", "T1611", "T1610", "namespace",
                    "docker_socket", "cgroup", "kernel_module", "privileged"]

SEVERITY_MAP = {
    "Emergency": 0, "Alert": 1, "Critical": 2, "Error": 3,
    "Warning": 4, "Notice": 5, "Informational": 6, "Debug": 7
}


def check_falco_status():
    try:
        result = subprocess.run(["falco", "--version"],
                                capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            version = result.stdout.strip()
            return {"installed": True, "version": version}
    except FileNotFoundError:
        pass
    try:
        result = subprocess.run(["systemctl", "is-active", "falco"],
                                capture_output=True, text=True, timeout=5)
        return {"installed": True, "service_status": result.stdout.strip()}
    except FileNotFoundError:
        pass
    return {"installed": False}


def validate_rules_file(rules_path):
    try:
        result = subprocess.run(
            ["falco", "--validate", rules_path],
            capture_output=True, text=True, timeout=30)
        return {
            "valid": result.returncode == 0,
            "output": result.stdout.strip() if result.returncode == 0
                      else result.stderr.strip(),
        }
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {"valid": False, "error": str(e)}


def parse_falco_alerts(filepath, min_priority="Warning"):
    min_level = SEVERITY_MAP.get(min_priority, 4)
    alerts = []
    escape_alerts = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue

            priority = evt.get("priority", "Informational")
            if SEVERITY_MAP.get(priority, 6) > min_level:
                continue

            alert = {
                "time": evt.get("time", ""),
                "rule": evt.get("rule", ""),
                "priority": priority,
                "source": evt.get("source", "syscall"),
                "output": evt.get("output", ""),
                "fields": evt.get("output_fields", {}),
                "tags": evt.get("tags", []),
            }
            alerts.append(alert)

            tags = set(evt.get("tags", []))
            if tags & set(ESCAPE_RULE_TAGS):
                escape_alerts.append(alert)

    return {"total_alerts": len(alerts), "escape_alerts": escape_alerts}


def generate_escape_rules_yaml():
    rules = """# Container Escape Detection Rules for Falco
# Deploy to /etc/falco/rules.d/container-escape.yaml

- list: escape_binaries
  items: [nsenter, unshare, mount, umount, pivot_root, chroot, modprobe, insmod]

- macro: container_escape_binary
  condition: spawned_process and container and proc.name in (escape_binaries)

- rule: Container Escape Binary Execution
  desc: Detect execution of binaries commonly used for container escape
  condition: container_escape_binary
  output: "Escape binary in container (user=%user.name cmd=%proc.cmdline container=%container.name image=%container.image.repository)"
  priority: CRITICAL
  tags: [container, escape, T1611]

- rule: Docker Socket Access from Container
  desc: Container accessing Docker socket enables full host control
  condition: (open_read or open_write) and container and fd.name = /var/run/docker.sock
  output: "Docker socket accessed (user=%user.name container=%container.name cmd=%proc.cmdline)"
  priority: CRITICAL
  tags: [container, escape, docker_socket, T1610]

- rule: Cgroup Release Agent Write
  desc: Writing to cgroup release_agent is a known container escape vector
  condition: open_write and container and fd.name endswith release_agent
  output: "Cgroup escape attempt (user=%user.name container=%container.name file=%fd.name)"
  priority: CRITICAL
  tags: [container, escape, cgroup]

- rule: Kernel Module Load from Container
  desc: Container attempting to load kernel module
  condition: spawned_process and container and proc.name in (modprobe, insmod, rmmod)
  output: "Kernel module load (user=%user.name container=%container.name cmd=%proc.cmdline)"
  priority: CRITICAL
  tags: [container, escape, kernel_module]

- rule: Sensitive Proc Access from Container
  desc: Container accessing sensitive /proc or /sys paths
  condition: open_read and container and (fd.name startswith /proc/sysrq-trigger or fd.name startswith /proc/kcore or fd.name startswith /proc/kallsyms)
  output: "Sensitive proc access (container=%container.name path=%fd.name cmd=%proc.cmdline)"
  priority: CRITICAL
  tags: [container, escape, proc_access]
"""
    return rules


def main():
    parser = argparse.ArgumentParser(description="Falco Container Escape Detection")
    parser.add_argument("--check-status", action="store_true", help="Check Falco installation")
    parser.add_argument("--validate-rules", help="Validate a Falco rules file")
    parser.add_argument("--parse-alerts", help="Parse Falco JSON alert log")
    parser.add_argument("--min-priority", default="Warning",
                        choices=list(SEVERITY_MAP.keys()))
    parser.add_argument("--generate-rules", action="store_true",
                        help="Output escape detection rules YAML")
    args = parser.parse_args()

    results = {"timestamp": datetime.utcnow().isoformat() + "Z"}

    if args.check_status:
        results["falco_status"] = check_falco_status()

    if args.validate_rules:
        results["validation"] = validate_rules_file(args.validate_rules)

    if args.parse_alerts:
        parsed = parse_falco_alerts(args.parse_alerts, args.min_priority)
        results["alert_summary"] = {
            "total_alerts": parsed["total_alerts"],
            "escape_alerts_count": len(parsed["escape_alerts"]),
        }
        results["escape_alerts"] = parsed["escape_alerts"]

    if args.generate_rules:
        print(generate_escape_rules_yaml())
        return

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
