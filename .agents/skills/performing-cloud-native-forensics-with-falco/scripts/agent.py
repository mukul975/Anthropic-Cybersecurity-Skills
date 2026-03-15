#!/usr/bin/env python3
"""Agent for managing Falco rules and parsing alerts for container forensics."""

import os
import json
import argparse
from datetime import datetime
from collections import defaultdict
from pathlib import Path

import yaml
import requests


FALCO_RULES = [
    {
        "rule": "Shell Spawned in Container",
        "desc": "Detect shell process started in a container",
        "condition": "spawned_process and container and proc.name in (bash, sh, zsh, dash) "
                     "and not proc.pname in (docker-entrypo, supervisord, crond)",
        "output": "Shell spawned (user=%user.name command=%proc.cmdline "
                  "container=%container.name image=%container.image.repository)",
        "priority": "WARNING",
        "tags": ["container", "shell", "mitre_execution"],
    },
    {
        "rule": "Sensitive File Access in Container",
        "desc": "Detect read of sensitive files in container",
        "condition": "open_read and container and fd.name in (/etc/shadow, /etc/passwd, "
                     "/etc/sudoers) and not proc.name in (su, sudo, login)",
        "output": "Sensitive file read (file=%fd.name user=%user.name "
                  "container=%container.name)",
        "priority": "WARNING",
        "tags": ["container", "filesystem", "mitre_credential_access"],
    },
    {
        "rule": "Outbound Connection from Container",
        "desc": "Detect unexpected outbound network connections from containers",
        "condition": "evt.type=connect and fd.typechar=4 and fd.ip != 0.0.0.0 "
                     "and container and not fd.snet in (10.0.0.0/8, 172.16.0.0/12, "
                     "192.168.0.0/16)",
        "output": "Outbound connection (command=%proc.cmdline dest=%fd.name "
                  "container=%container.name)",
        "priority": "NOTICE",
        "tags": ["container", "network", "mitre_command_and_control"],
    },
    {
        "rule": "Privilege Escalation in Container",
        "desc": "Detect setuid/setgid calls in container",
        "condition": "evt.type in (setuid, setgid) and container "
                     "and not user.name=root",
        "output": "Privilege escalation attempt (user=%user.name command=%proc.cmdline "
                  "container=%container.name)",
        "priority": "CRITICAL",
        "tags": ["container", "privilege_escalation", "mitre_privilege_escalation"],
    },
    {
        "rule": "Container Escape Attempt via Mount",
        "desc": "Detect mount syscall in container indicating escape attempt",
        "condition": "evt.type=mount and container",
        "output": "Mount in container (user=%user.name command=%proc.cmdline "
                  "container=%container.name)",
        "priority": "CRITICAL",
        "tags": ["container", "escape", "mitre_privilege_escalation"],
    },
]


def generate_falco_rules(output_path, custom_rules=None):
    """Generate Falco rules YAML file."""
    rules = custom_rules or FALCO_RULES
    with open(output_path, "w") as f:
        yaml.dump(rules, f, default_flow_style=False, sort_keys=False)
    return len(rules)


def parse_falco_alerts(alert_file):
    """Parse Falco JSON alert output file."""
    alerts = []
    with open(alert_file) as f:
        for line in f:
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
                    "output_fields": alert.get("output_fields", {}),
                    "source": alert.get("source", ""),
                    "tags": alert.get("tags", []),
                })
            except json.JSONDecodeError:
                continue
    return alerts


def summarize_alerts(alerts):
    """Generate alert summary statistics."""
    by_rule = defaultdict(int)
    by_priority = defaultdict(int)
    by_container = defaultdict(int)
    for alert in alerts:
        by_rule[alert["rule"]] += 1
        by_priority[alert["priority"]] += 1
        container = alert.get("output_fields", {}).get("container.name", "unknown")
        by_container[container] += 1
    return {
        "total_alerts": len(alerts),
        "by_rule": dict(by_rule),
        "by_priority": dict(by_priority),
        "by_container": dict(sorted(by_container.items(), key=lambda x: -x[1])[:20]),
    }


def check_falco_health(falco_url="http://localhost:8765"):
    """Check Falco health via HTTP endpoint."""
    try:
        resp = requests.get(f"{falco_url}/healthz", timeout=5)
        return {"status": "healthy" if resp.status_code == 200 else "unhealthy",
                "code": resp.status_code}
    except requests.RequestException as e:
        return {"status": "unreachable", "error": str(e)}


def get_falco_version(falco_url="http://localhost:8765"):
    """Get Falco version information."""
    try:
        resp = requests.get(f"{falco_url}/version", timeout=5)
        return resp.json()
    except requests.RequestException as e:
        return {"error": str(e)}


def correlate_alerts_with_k8s(alerts, suspicious_images=None):
    """Correlate Falco alerts with known suspicious container images."""
    if not suspicious_images:
        suspicious_images = []
    correlated = []
    for alert in alerts:
        fields = alert.get("output_fields", {})
        image = fields.get("container.image.repository", "")
        if any(s in image for s in suspicious_images):
            alert["correlation"] = "suspicious_image"
            correlated.append(alert)
        elif alert["priority"] in ("CRITICAL", "ERROR"):
            correlated.append(alert)
    return correlated


def main():
    parser = argparse.ArgumentParser(description="Falco Cloud Native Forensics Agent")
    parser.add_argument("--alert-file", help="Path to Falco JSON alert log")
    parser.add_argument("--rules-output", default="custom_falco_rules.yaml")
    parser.add_argument("--falco-url", default="http://localhost:8765")
    parser.add_argument("--output", default="falco_report.json")
    parser.add_argument("--action", choices=[
        "generate_rules", "parse_alerts", "health", "full_analysis"
    ], default="full_analysis")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.action in ("generate_rules", "full_analysis"):
        count = generate_falco_rules(args.rules_output)
        report["findings"]["rules_generated"] = count
        print(f"[+] Generated {count} Falco rules to {args.rules_output}")

    if args.action in ("parse_alerts", "full_analysis") and args.alert_file:
        alerts = parse_falco_alerts(args.alert_file)
        summary = summarize_alerts(alerts)
        report["findings"]["alert_summary"] = summary
        report["findings"]["critical_alerts"] = [
            a for a in alerts if a["priority"] in ("CRITICAL", "ERROR")
        ]
        print(f"[+] Parsed {summary['total_alerts']} alerts")
        print(f"    Critical: {summary['by_priority'].get('CRITICAL', 0)}")

    if args.action in ("health", "full_analysis"):
        health = check_falco_health(args.falco_url)
        report["findings"]["falco_health"] = health
        print(f"[+] Falco health: {health['status']}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
