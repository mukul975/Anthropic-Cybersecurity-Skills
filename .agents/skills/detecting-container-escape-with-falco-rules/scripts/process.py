#!/usr/bin/env python3
"""
Falco Container Escape Rule Manager - Generate, validate, and deploy
custom Falco rules for container escape detection.
"""

import json
import subprocess
import sys
import argparse
from pathlib import Path
from datetime import datetime

# Container escape detection rule templates
ESCAPE_RULES = {
    "mount_host_fs": {
        "rule": "Container Mounting Host Filesystem",
        "desc": "Detect a container attempting to mount the host filesystem",
        "condition": 'spawned_process and container and proc.name = mount and (proc.args contains "/host" or proc.args contains "nsenter")',
        "priority": "CRITICAL",
        "tags": ["container", "escape", "T1611"],
    },
    "nsenter_usage": {
        "rule": "Nsenter Execution in Container",
        "desc": "Detect nsenter being used to escape container namespaces",
        "condition": "spawned_process and container and proc.name = nsenter",
        "priority": "CRITICAL",
        "tags": ["container", "escape", "namespace", "T1611"],
    },
    "privileged_container": {
        "rule": "Launch Privileged Container",
        "desc": "Detect a privileged container being launched",
        "condition": "container_started and container and container.privileged=true",
        "priority": "WARNING",
        "tags": ["container", "privileged", "T1610"],
    },
    "cgroup_escape": {
        "rule": "Write to Cgroup Release Agent",
        "desc": "Detect writes to cgroup release_agent - known escape vector",
        "condition": "open_write and container and fd.name endswith release_agent",
        "priority": "CRITICAL",
        "tags": ["container", "escape", "cgroup", "CVE-2022-0492"],
    },
    "docker_socket": {
        "rule": "Container Accessing Docker Socket",
        "desc": "Detect container accessing Docker socket for host control",
        "condition": "(open_read or open_write) and container and fd.name = /var/run/docker.sock",
        "priority": "CRITICAL",
        "tags": ["container", "escape", "docker-socket", "T1610"],
    },
    "kernel_module": {
        "rule": "Container Loading Kernel Module",
        "desc": "Detect a container attempting to load a kernel module",
        "condition": "spawned_process and container and proc.name in (insmod, modprobe)",
        "priority": "CRITICAL",
        "tags": ["container", "escape", "kernel", "T1611"],
    },
    "shadow_file": {
        "rule": "Container Reading Host Shadow File",
        "desc": "Detect container reading /etc/shadow",
        "condition": 'open_read and container and (fd.name = /etc/shadow or fd.name startswith /host/etc/shadow)',
        "priority": "CRITICAL",
        "tags": ["container", "credential-access", "T1003"],
    },
    "sysrq_trigger": {
        "rule": "Write to Sysrq Trigger from Container",
        "desc": "Detect writes to /proc/sysrq-trigger from container",
        "condition": "open_write and container and fd.name = /proc/sysrq-trigger",
        "priority": "CRITICAL",
        "tags": ["container", "escape", "host-manipulation"],
    },
}


def generate_rule_yaml(rule_key: str, rule_data: dict) -> str:
    """Generate a single Falco rule in YAML format."""
    tags_str = ", ".join(rule_data["tags"])
    output_fields = (
        "user=%user.name container_id=%container.id "
        "container_name=%container.name image=%container.image.repository "
        "command=%proc.cmdline"
    )
    return f"""- rule: {rule_data['rule']}
  desc: {rule_data['desc']}
  condition: >
    {rule_data['condition']}
  output: >
    {rule_data['desc']}
    ({output_fields})
  priority: {rule_data['priority']}
  tags: [{tags_str}]
"""


def generate_all_rules() -> str:
    """Generate complete Falco rules file for container escape detection."""
    header = f"""# Container Escape Detection Rules for Falco
# Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
# Deploy to: /etc/falco/rules.d/container-escape.yaml

- list: escape_binaries
  items: [nsenter, chroot, unshare, mount, umount, pivot_root]

- macro: container_escape_binary
  condition: spawned_process and container and proc.name in (escape_binaries)

"""
    rules = ""
    for key, data in ESCAPE_RULES.items():
        rules += generate_rule_yaml(key, data) + "\n"

    return header + rules


def parse_falco_alerts(log_file: str) -> list:
    """Parse Falco JSON alerts from log file."""
    alerts = []
    path = Path(log_file)
    if not path.exists():
        print(f"Log file not found: {log_file}", file=sys.stderr)
        return alerts

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            alert = json.loads(line)
            alerts.append({
                "time": alert.get("time", ""),
                "rule": alert.get("rule", ""),
                "priority": alert.get("priority", ""),
                "output": alert.get("output", ""),
                "tags": alert.get("tags", []),
                "container_name": alert.get("output_fields", {}).get("container.name", ""),
                "container_image": alert.get("output_fields", {}).get("container.image.repository", ""),
            })
        except json.JSONDecodeError:
            continue

    return alerts


def summarize_alerts(alerts: list) -> dict:
    """Summarize Falco alerts by rule and severity."""
    summary = {"total": len(alerts), "by_priority": {}, "by_rule": {}, "escape_attempts": []}

    for alert in alerts:
        pri = alert["priority"]
        rule = alert["rule"]
        summary["by_priority"][pri] = summary["by_priority"].get(pri, 0) + 1
        summary["by_rule"][rule] = summary["by_rule"].get(rule, 0) + 1

        if any(tag in alert.get("tags", []) for tag in ["escape", "T1611", "T1610"]):
            summary["escape_attempts"].append(alert)

    return summary


def check_falco_health() -> dict:
    """Check if Falco is running and healthy."""
    result = subprocess.run(
        ["kubectl", "get", "pods", "-n", "falco", "-l", "app.kubernetes.io/name=falco",
         "-o", "json"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return {"healthy": False, "error": result.stderr}

    pods = json.loads(result.stdout)
    pod_status = []
    for pod in pods.get("items", []):
        name = pod["metadata"]["name"]
        phase = pod["status"]["phase"]
        node = pod["spec"].get("nodeName", "unknown")
        pod_status.append({"name": name, "phase": phase, "node": node})

    all_running = all(p["phase"] == "Running" for p in pod_status)
    return {"healthy": all_running, "pods": pod_status}


def main():
    parser = argparse.ArgumentParser(description="Falco Container Escape Rule Manager")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("generate", help="Generate container escape detection rules")

    parse_cmd = subparsers.add_parser("parse-alerts", help="Parse Falco alert logs")
    parse_cmd.add_argument("--log-file", required=True, help="Path to Falco JSON log file")

    subparsers.add_parser("health", help="Check Falco deployment health")

    deploy_cmd = subparsers.add_parser("deploy", help="Deploy rules to Kubernetes")
    deploy_cmd.add_argument("--namespace", default="falco", help="Falco namespace")

    args = parser.parse_args()

    if args.command == "generate":
        print(generate_all_rules())

    elif args.command == "parse-alerts":
        alerts = parse_falco_alerts(args.log_file)
        summary = summarize_alerts(alerts)
        print(json.dumps(summary, indent=2))

    elif args.command == "health":
        health = check_falco_health()
        print(json.dumps(health, indent=2))

    elif args.command == "deploy":
        rules_yaml = generate_all_rules()
        proc = subprocess.run(
            ["kubectl", "create", "configmap", "falco-escape-rules",
             "-n", args.namespace, "--from-literal=container-escape.yaml=" + rules_yaml,
             "--dry-run=client", "-o", "yaml"],
            capture_output=True, text=True,
        )
        apply = subprocess.run(
            ["kubectl", "apply", "-f", "-"],
            input=proc.stdout, capture_output=True, text=True,
        )
        print(apply.stdout)
        if apply.returncode == 0:
            print("Rules deployed. Restart Falco to load:")
            print(f"  kubectl rollout restart daemonset/falco -n {args.namespace}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
