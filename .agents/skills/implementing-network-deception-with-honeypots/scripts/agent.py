#!/usr/bin/env python3
"""Honeypot Deployment Agent - deploys OpenCanary honeypots and analyzes interaction logs."""

import json
import argparse
import logging
import subprocess
import os
import re
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

OPENCANARY_CONFIG_TEMPLATE = {
    "device.node_id": "opencanary-001",
    "ip.ignorelist": [],
    "logtype.console.enabled": True,
    "logger": {
        "class": "PyLogger",
        "kwargs": {
            "formatters": {"plain": {"format": "%(message)s"}},
            "handlers": {
                "file": {
                    "class": "logging.FileHandler",
                    "filename": "/var/tmp/opencanary.log",
                },
                "console": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                },
            },
        },
    },
    "ftp.enabled": False,
    "ftp.port": 21,
    "ftp.banner": "FTP server ready",
    "http.enabled": False,
    "http.port": 80,
    "http.banner": "Apache/2.4.41 (Ubuntu)",
    "http.skin": "nasLogin",
    "httpproxy.enabled": False,
    "httpproxy.port": 8080,
    "ssh.enabled": False,
    "ssh.port": 22,
    "ssh.version": "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3",
    "smb.enabled": False,
    "smb.filelist": [{"name": "passwords.xlsx", "type": "xlsx"}, {"name": "backup-credentials.txt", "type": "txt"}],
    "telnet.enabled": False,
    "telnet.port": 23,
    "telnet.banner": "Welcome to the management console",
    "rdp.enabled": False,
    "rdp.port": 3389,
    "mysql.enabled": False,
    "mysql.port": 3306,
    "snmp.enabled": False,
    "snmp.port": 161,
}


def generate_config(services, node_id="opencanary-001", log_path="/var/tmp/opencanary.log"):
    """Generate OpenCanary configuration with specified services enabled."""
    config = OPENCANARY_CONFIG_TEMPLATE.copy()
    config["device.node_id"] = node_id
    config["logger"]["kwargs"]["handlers"]["file"]["filename"] = log_path
    for service in services:
        key = f"{service}.enabled"
        if key in config:
            config[key] = True
    enabled = [s for s in services if f"{s}.enabled" in config]
    logger.info("Generated config with %d services: %s", len(enabled), ", ".join(enabled))
    return config


def deploy_opencanary(config, config_path="/etc/opencanaryd/opencanary.conf"):
    """Deploy OpenCanary with generated configuration."""
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    logger.info("Configuration written to %s", config_path)
    start_cmd = ["opencanaryd", "--start"]
    result = subprocess.run(start_cmd, capture_output=True, text=True)
    return {"config_path": config_path, "started": result.returncode == 0, "output": result.stdout[:200]}


def parse_opencanary_log(log_path="/var/tmp/opencanary.log"):
    """Parse OpenCanary JSON log file for interaction events."""
    events = []
    try:
        with open(log_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    events.append({
                        "timestamp": event.get("utc_time", ""),
                        "dst_host": event.get("dst_host", ""),
                        "dst_port": event.get("dst_port", 0),
                        "src_host": event.get("src_host", ""),
                        "src_port": event.get("src_port", 0),
                        "logtype": event.get("logtype", 0),
                        "node_id": event.get("node_id", ""),
                        "logdata": event.get("logdata", {}),
                    })
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        logger.warning("Log file not found: %s", log_path)
    return events


def analyze_interactions(events):
    """Analyze honeypot interactions for threat intelligence."""
    by_source = defaultdict(lambda: {"count": 0, "services": set(), "credentials": []})
    by_service = defaultdict(int)
    credential_attempts = []
    log_type_map = {
        1001: "ftp_login", 2001: "http_login", 3001: "ssh_login",
        5001: "smb_file_open", 6001: "telnet_login", 7001: "mysql_login",
        8001: "rdp_login",
    }

    for event in events:
        src = event["src_host"]
        service = log_type_map.get(event["logtype"], f"type_{event['logtype']}")
        by_source[src]["count"] += 1
        by_source[src]["services"].add(service)
        by_service[service] += 1
        logdata = event.get("logdata", {})
        username = logdata.get("USERNAME", logdata.get("username", ""))
        password = logdata.get("PASSWORD", logdata.get("password", ""))
        if username:
            cred = {"username": username, "password": password, "service": service, "source": src}
            credential_attempts.append(cred)
            by_source[src]["credentials"].append(cred)

    source_summary = {}
    for ip, data in sorted(by_source.items(), key=lambda x: x[1]["count"], reverse=True):
        source_summary[ip] = {
            "interaction_count": data["count"],
            "services_targeted": list(data["services"]),
            "credential_attempts": len(data["credentials"]),
        }

    return {
        "total_interactions": len(events),
        "unique_sources": len(by_source),
        "service_distribution": dict(sorted(by_service.items(), key=lambda x: x[1], reverse=True)),
        "top_sources": dict(list(source_summary.items())[:20]),
        "credential_attempts": len(credential_attempts),
        "unique_usernames": len(set(c["username"] for c in credential_attempts)),
        "top_credentials": credential_attempts[:20],
    }


def check_honeypot_status():
    """Check if OpenCanary daemon is running."""
    cmd = ["opencanaryd", "--status"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    is_running = "running" in result.stdout.lower() or result.returncode == 0
    return {"running": is_running, "status_output": result.stdout.strip()[:200]}


def generate_report(analysis, status, config):
    """Generate honeypot deployment and interaction report."""
    enabled_services = [k.replace(".enabled", "") for k, v in config.items() if k.endswith(".enabled") and v]
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "honeypot_type": "OpenCanary",
        "node_id": config.get("device.node_id", ""),
        "enabled_services": enabled_services,
        "daemon_status": status,
        "interaction_analysis": analysis,
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="Honeypot Deployment and Analysis Agent")
    parser.add_argument("--action", choices=["deploy", "analyze", "status", "full"], default="analyze")
    parser.add_argument("--services", nargs="+", default=["ssh", "http", "smb", "ftp", "telnet"],
                        help="Services to enable (default: ssh http smb ftp telnet)")
    parser.add_argument("--node-id", default="opencanary-001", help="Honeypot node identifier")
    parser.add_argument("--log-path", default="/var/tmp/opencanary.log", help="OpenCanary log file path")
    parser.add_argument("--config-path", default="/etc/opencanaryd/opencanary.conf")
    parser.add_argument("--output", default="honeypot_report.json")
    args = parser.parse_args()

    config = generate_config(args.services, args.node_id, args.log_path)

    if args.action in ("deploy", "full"):
        deploy_result = deploy_opencanary(config, args.config_path)
        logger.info("Deployment: %s", "success" if deploy_result["started"] else "failed")

    status = check_honeypot_status()
    events = parse_opencanary_log(args.log_path)
    analysis = analyze_interactions(events)
    report = generate_report(analysis, status, config)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Honeypot: %d interactions from %d sources, %d credential attempts",
                analysis["total_interactions"], analysis["unique_sources"],
                analysis["credential_attempts"])
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
