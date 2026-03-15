#!/usr/bin/env python3
"""Agent for auditing and hardening Docker daemon configuration."""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone


DAEMON_JSON_PATH = "/etc/docker/daemon.json"

RECOMMENDED_SETTINGS = {
    "icc": False,
    "live-restore": True,
    "userland-proxy": False,
    "no-new-privileges": True,
    "userns-remap": "default",
    "log-driver": "json-file",
    "log-opts": {"max-size": "10m", "max-file": "3"},
}


def read_daemon_config():
    """Read Docker daemon.json configuration."""
    if not os.path.isfile(DAEMON_JSON_PATH):
        return {"error": f"{DAEMON_JSON_PATH} not found"}
    try:
        with open(DAEMON_JSON_PATH, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, PermissionError) as e:
        return {"error": str(e)}


def audit_daemon_config(config):
    """Audit daemon.json against CIS benchmarks."""
    findings = []
    if "error" in config:
        findings.append({"check": "daemon.json", "issue": config["error"], "severity": "HIGH"})
        return findings

    if config.get("icc", True):
        findings.append({"check": "CIS 2.1", "issue": "Inter-container communication enabled", "severity": "MEDIUM"})
    if not config.get("live-restore"):
        findings.append({"check": "CIS 2.2", "issue": "Live restore not enabled", "severity": "LOW"})
    if config.get("userland-proxy", True):
        findings.append({"check": "CIS 2.3", "issue": "Userland proxy enabled (use iptables)", "severity": "LOW"})
    if not config.get("no-new-privileges"):
        findings.append({"check": "CIS 2.4", "issue": "no-new-privileges not set", "severity": "MEDIUM"})
    if "userns-remap" not in config:
        findings.append({"check": "CIS 2.8", "issue": "User namespace remapping not configured", "severity": "MEDIUM"})
    if not config.get("tls"):
        if not config.get("tlsverify"):
            findings.append({"check": "CIS 2.6", "issue": "TLS not configured for Docker daemon", "severity": "HIGH"})
    log_driver = config.get("log-driver", "")
    if not log_driver:
        findings.append({"check": "CIS 2.12", "issue": "No log driver configured", "severity": "MEDIUM"})
    if config.get("insecure-registries"):
        findings.append({"check": "CIS 2.4", "issue": f"Insecure registries: {config['insecure-registries']}", "severity": "HIGH"})

    return findings


def check_docker_socket():
    """Check Docker socket permissions."""
    findings = []
    socket_path = "/var/run/docker.sock"
    if os.path.exists(socket_path):
        stat = os.stat(socket_path)
        mode = oct(stat.st_mode)[-3:]
        if mode != "660":
            findings.append({
                "check": "CIS 3.3",
                "issue": f"Docker socket permissions: {mode} (should be 660)",
                "severity": "HIGH",
            })
    return findings


def check_docker_files():
    """Audit Docker configuration file permissions."""
    findings = []
    files_to_check = {
        "/etc/docker/daemon.json": "644",
        "/etc/default/docker": "644",
        "/etc/docker/certs.d": "444",
    }
    for fpath, expected in files_to_check.items():
        if os.path.exists(fpath):
            stat = os.stat(fpath)
            mode = oct(stat.st_mode)[-3:]
            if mode > expected:
                findings.append({
                    "check": "CIS 3.x",
                    "issue": f"{fpath}: permissions {mode} (should be {expected})",
                    "severity": "MEDIUM",
                })
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Audit Docker daemon configuration against CIS benchmarks"
    )
    parser.add_argument("--config", default=DAEMON_JSON_PATH, help="Path to daemon.json")
    parser.add_argument("--output", "-o", help="Output JSON report")
    args = parser.parse_args()

    print("[*] Docker Daemon Configuration Audit Agent")
    global DAEMON_JSON_PATH
    DAEMON_JSON_PATH = args.config

    config = read_daemon_config()
    findings = audit_daemon_config(config)
    findings.extend(check_docker_socket())
    findings.extend(check_docker_files())

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "daemon_config": config if "error" not in config else {},
        "findings": findings,
        "finding_count": len(findings),
    }

    critical = sum(1 for f in findings if f["severity"] == "HIGH")
    print(f"[*] Findings: {len(findings)} (HIGH: {critical})")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
