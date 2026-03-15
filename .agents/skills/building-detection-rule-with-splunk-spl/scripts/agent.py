#!/usr/bin/env python3
"""Splunk SPL Detection Rule Builder Agent - Generates and validates Splunk detection rules."""

import json
import logging
import argparse
from datetime import datetime

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DETECTION_TEMPLATES = {
    "brute_force": {
        "spl": 'index=main sourcetype=WinEventLog:Security EventCode=4625 | stats count by src_ip, user | where count > {threshold}',
        "description": "Detect brute force login attempts",
        "mitre": "T1110",
        "severity": "high",
    },
    "lateral_movement_rdp": {
        "spl": 'index=main sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=10 | stats count by src_ip, dest, user | where count > 1',
        "description": "Detect RDP lateral movement",
        "mitre": "T1021.001",
        "severity": "high",
    },
    "powershell_encoded": {
        "spl": 'index=main sourcetype=WinEventLog:Security EventCode=4104 ScriptBlockText="*-EncodedCommand*" OR ScriptBlockText="*FromBase64String*" | table _time, ComputerName, ScriptBlockText',
        "description": "Detect encoded PowerShell execution",
        "mitre": "T1059.001",
        "severity": "critical",
    },
    "suspicious_process": {
        "spl": 'index=main sourcetype=sysmon EventCode=1 (ParentImage="*\\\\cmd.exe" OR ParentImage="*\\\\powershell.exe") (Image="*\\\\whoami.exe" OR Image="*\\\\net.exe" OR Image="*\\\\nltest.exe") | table _time, Computer, User, ParentImage, Image, CommandLine',
        "description": "Detect suspicious child process spawning",
        "mitre": "T1059.003",
        "severity": "high",
    },
    "scheduled_task_creation": {
        "spl": 'index=main sourcetype=WinEventLog:Security EventCode=4698 | table _time, SubjectUserName, TaskName, TaskContent',
        "description": "Detect new scheduled task creation",
        "mitre": "T1053.005",
        "severity": "medium",
    },
    "credential_dumping": {
        "spl": 'index=main sourcetype=sysmon EventCode=10 TargetImage="*\\\\lsass.exe" GrantedAccess IN ("0x1010", "0x1038", "0x1fffff") | table _time, SourceImage, TargetImage, GrantedAccess',
        "description": "Detect LSASS memory access (credential dumping)",
        "mitre": "T1003.001",
        "severity": "critical",
    },
    "data_exfiltration": {
        "spl": 'index=main sourcetype=proxy | stats sum(bytes_out) as total_bytes by src_ip, dest | where total_bytes > {threshold_bytes} | eval MB=round(total_bytes/1024/1024,2)',
        "description": "Detect large data transfers (exfiltration)",
        "mitre": "T1048",
        "severity": "high",
    },
}


def generate_spl_rule(template_name, params=None):
    """Generate an SPL detection rule from template."""
    if template_name not in DETECTION_TEMPLATES:
        return {"error": f"Unknown template: {template_name}"}
    template = DETECTION_TEMPLATES[template_name]
    spl = template["spl"]
    if params:
        for key, value in params.items():
            spl = spl.replace(f"{{{key}}}", str(value))
    return {
        "name": template_name,
        "spl": spl,
        "description": template["description"],
        "mitre_technique": template["mitre"],
        "severity": template["severity"],
    }


def deploy_saved_search(splunk_url, token, rule_name, spl, severity="high"):
    """Deploy a saved search to Splunk via REST API."""
    headers = {"Authorization": f"Bearer {token}"}
    data = {
        "name": f"Detection - {rule_name}",
        "search": spl,
        "is_scheduled": 1,
        "cron_schedule": "*/5 * * * *",
        "dispatch.earliest_time": "-5m",
        "dispatch.latest_time": "now",
        "alert.severity": {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}.get(severity, 4),
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "actions": "email",
    }
    try:
        resp = requests.post(f"{splunk_url}/servicesNS/admin/search/saved/searches", headers=headers, data=data, verify=False, timeout=30)
        return {"status": resp.status_code, "deployed": resp.status_code in (200, 201)}
    except requests.RequestException as e:
        return {"error": str(e)}


def generate_report(rules, deployment_results=None):
    """Generate detection rule report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "rules_generated": len(rules),
        "rules": rules,
        "deployment_results": deployment_results or [],
    }
    print(f"SPL REPORT: {len(rules)} detection rules generated")
    return report


def main():
    parser = argparse.ArgumentParser(description="Splunk SPL Detection Rule Builder Agent")
    parser.add_argument("--templates", nargs="*", choices=list(DETECTION_TEMPLATES.keys()), default=list(DETECTION_TEMPLATES.keys()))
    parser.add_argument("--threshold", type=int, default=10)
    parser.add_argument("--threshold-bytes", type=int, default=104857600)
    parser.add_argument("--splunk-url", help="Splunk URL for deployment")
    parser.add_argument("--splunk-token", help="Splunk auth token")
    parser.add_argument("--output", default="splunk_rules.json")
    args = parser.parse_args()

    rules = []
    for template in args.templates:
        rule = generate_spl_rule(template, {"threshold": args.threshold, "threshold_bytes": args.threshold_bytes})
        rules.append(rule)

    deployments = []
    if args.splunk_url and args.splunk_token:
        for rule in rules:
            result = deploy_saved_search(args.splunk_url, args.splunk_token, rule["name"], rule["spl"], rule["severity"])
            deployments.append({"rule": rule["name"], "result": result})

    report = generate_report(rules, deployments)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
