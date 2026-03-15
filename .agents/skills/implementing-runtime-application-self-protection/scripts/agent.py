#!/usr/bin/env python3
"""RASP Agent - audits runtime application protection config, attack logs, and coverage."""

import json
import argparse
import logging
import os
import re
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

OWASP_TOP10_CHECKS = {
    "sqli": {"name": "SQL Injection", "owasp": "A03:2021", "hook": "sql_query"},
    "cmdi": {"name": "Command Injection", "owasp": "A03:2021", "hook": "command_exec"},
    "ssrf": {"name": "Server-Side Request Forgery", "owasp": "A10:2021", "hook": "http_request"},
    "path_traversal": {"name": "Path Traversal", "owasp": "A01:2021", "hook": "file_open"},
    "xxe": {"name": "XML External Entity", "owasp": "A05:2021", "hook": "xml_parse"},
    "deserialization": {"name": "Insecure Deserialization", "owasp": "A08:2021", "hook": "deserialize"},
    "xss": {"name": "Cross-Site Scripting", "owasp": "A03:2021", "hook": "response_write"},
    "ldap_injection": {"name": "LDAP Injection", "owasp": "A03:2021", "hook": "ldap_query"},
    "rce": {"name": "Remote Code Execution", "owasp": "A03:2021", "hook": "code_eval"},
}


def parse_rasp_config(config_file):
    """Parse OpenRASP or RASP agent configuration."""
    with open(config_file) as f:
        return json.load(f)


def audit_rasp_policy(config):
    """Audit RASP detection policies against OWASP Top 10 coverage."""
    findings = []
    enabled_checks = config.get("detection_plugins", {})
    for check_id, check_info in OWASP_TOP10_CHECKS.items():
        plugin = enabled_checks.get(check_id, {})
        if not plugin.get("enabled", False):
            findings.append({
                "check": check_id, "name": check_info["name"],
                "owasp": check_info["owasp"], "status": "disabled",
                "severity": "high",
                "recommendation": f"Enable {check_info['name']} detection plugin",
            })
        elif plugin.get("action", "log") != "block":
            findings.append({
                "check": check_id, "name": check_info["name"],
                "owasp": check_info["owasp"], "status": "monitor_only",
                "severity": "medium",
                "recommendation": f"Switch {check_info['name']} from monitor to block mode",
            })
    block_mode = config.get("global_action", "log")
    if block_mode == "log":
        findings.append({
            "check": "global_mode", "status": "monitor_only",
            "severity": "high",
            "recommendation": "Switch RASP from monitor to block mode after baseline period",
        })
    return findings


def analyze_attack_logs(log_file, limit=10000):
    """Analyze RASP attack detection logs."""
    attacks = []
    by_type = defaultdict(int)
    by_source = defaultdict(int)
    blocked = 0
    try:
        with open(log_file) as f:
            for i, line in enumerate(f):
                if i >= limit:
                    break
                try:
                    event = json.loads(line)
                    attack_type = event.get("attack_type", "unknown")
                    by_type[attack_type] += 1
                    by_source[event.get("client_ip", "")] += 1
                    if event.get("action") == "block":
                        blocked += 1
                    attacks.append(event)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        logger.warning("RASP log file not found: %s", log_file)
    return {
        "total_attacks": len(attacks),
        "blocked": blocked,
        "block_rate": round(blocked / max(len(attacks), 1) * 100, 1),
        "by_attack_type": dict(sorted(by_type.items(), key=lambda x: x[1], reverse=True)),
        "top_sources": dict(sorted(by_source.items(), key=lambda x: x[1], reverse=True)[:10]),
    }


def check_agent_health(config):
    """Verify RASP agent deployment health."""
    findings = []
    if not config.get("agent_version"):
        findings.append({"issue": "Agent version unknown", "severity": "medium"})
    if config.get("cpu_limit_percent", 100) > 10:
        findings.append({
            "issue": f"CPU limit set to {config.get('cpu_limit_percent')}% (recommend < 5%)",
            "severity": "low",
        })
    if not config.get("siem_integration", {}).get("enabled"):
        findings.append({
            "issue": "SIEM log forwarding not configured",
            "severity": "high",
            "recommendation": "Enable syslog or webhook forwarding to SIEM",
        })
    return findings


def calculate_coverage(config):
    """Calculate OWASP Top 10 coverage percentage."""
    enabled_checks = config.get("detection_plugins", {})
    covered = sum(1 for check_id in OWASP_TOP10_CHECKS if enabled_checks.get(check_id, {}).get("enabled"))
    return {
        "total_checks": len(OWASP_TOP10_CHECKS),
        "enabled": covered,
        "coverage_percent": round(covered / len(OWASP_TOP10_CHECKS) * 100, 1),
    }


def generate_report(policy_findings, attack_analysis, health_findings, coverage, config):
    all_findings = policy_findings + health_findings
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "rasp_agent": config.get("agent_type", "openrasp"),
        "agent_version": config.get("agent_version", "unknown"),
        "global_mode": config.get("global_action", "log"),
        "owasp_coverage": coverage,
        "policy_findings": policy_findings,
        "attack_analysis": attack_analysis,
        "health_findings": health_findings,
        "total_findings": len(all_findings),
        "critical_findings": sum(1 for f in all_findings if f.get("severity") == "critical"),
    }


def main():
    parser = argparse.ArgumentParser(description="RASP Security Audit Agent")
    parser.add_argument("--config", required=True, help="RASP agent config JSON file")
    parser.add_argument("--attack-log", help="RASP attack log file (JSON lines)")
    parser.add_argument("--output", default="rasp_audit_report.json")
    args = parser.parse_args()

    config = parse_rasp_config(args.config)
    policy_findings = audit_rasp_policy(config)
    attack_analysis = analyze_attack_logs(args.attack_log) if args.attack_log else {}
    health_findings = check_agent_health(config)
    coverage = calculate_coverage(config)
    report = generate_report(policy_findings, attack_analysis, health_findings, coverage, config)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("RASP audit: %.1f%% OWASP coverage, %d findings, mode: %s",
                coverage["coverage_percent"], report["total_findings"], config.get("global_action", "log"))
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
