#!/usr/bin/env python3
"""SIEM Correlation Rules Agent - Builds and deploys multi-event APT detection rules via Splunk and Sigma."""

import json
import time
import logging
import argparse
from datetime import datetime

import yaml
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

LATERAL_MOVEMENT_RULES = [
    {
        "name": "RDP Lateral Movement Chain",
        "description": "RDP logon followed by service installation on same host within 15 minutes",
        "spl": (
            'index=wineventlog (EventCode=4624 Logon_Type=10) OR (EventCode=7045) '
            '| transaction Computer maxspan=15m startswith=(EventCode=4624) endswith=(EventCode=7045) '
            '| where eventcount >= 2 '
            '| table _time Computer Account_Name ServiceName'
        ),
        "severity": "high",
        "mitre": "T1021.001",
    },
    {
        "name": "PsExec Service Installation",
        "description": "Named pipe PSEXESVC created followed by remote service install",
        "spl": (
            'index=sysmon (EventCode=17 PipeName="\\\\PSEXESVC*") OR '
            '(index=wineventlog EventCode=7045 ServiceFileName="*PSEXESVC*") '
            '| transaction Computer maxspan=5m '
            '| where eventcount >= 2 '
            '| table _time Computer User Image ServiceName'
        ),
        "severity": "high",
        "mitre": "T1021.002",
    },
    {
        "name": "NTLM Pass-the-Hash Followed by Admin Tool",
        "description": "NTLM network logon followed by admin tool execution within 10 minutes",
        "spl": (
            'index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package=NTLM '
            '| join Computer maxspan=10m [search index=sysmon EventCode=1 '
            '(Image="*\\\\net.exe" OR Image="*\\\\net1.exe" OR Image="*\\\\wmic.exe" '
            'OR Image="*\\\\psexec.exe" OR Image="*\\\\powershell.exe")] '
            '| table _time Computer Account_Name Image CommandLine'
        ),
        "severity": "critical",
        "mitre": "T1550.002",
    },
    {
        "name": "WMI Remote Execution Chain",
        "description": "WMI process creation on remote host correlated with network logon",
        "spl": (
            'index=sysmon EventCode=1 ParentImage="*\\\\WmiPrvSE.exe" '
            '| join Computer [search index=wineventlog EventCode=4624 Logon_Type=3] '
            '| where Account_Name!="-" '
            '| stats count by Computer, Account_Name, Image, CommandLine '
            '| where count > 0'
        ),
        "severity": "high",
        "mitre": "T1047",
    },
    {
        "name": "Credential Dumping After Lateral Move",
        "description": "Network logon followed by LSASS access within 30 minutes",
        "spl": (
            'index=wineventlog EventCode=4624 Logon_Type=3 '
            '| join Computer maxspan=30m [search index=sysmon EventCode=10 '
            'TargetImage="*\\\\lsass.exe" GrantedAccess=0x1010] '
            '| table _time Computer Account_Name SourceImage GrantedAccess'
        ),
        "severity": "critical",
        "mitre": "T1003.001",
    },
]


def authenticate_splunk(base_url, username, password):
    """Authenticate to Splunk and return session headers."""
    resp = requests.post(
        f"{base_url}/services/auth/login",
        data={"username": username, "password": password},
        verify=False,
    )
    resp.raise_for_status()
    session_key = resp.json()["sessionKey"]
    logger.info("Authenticated to Splunk")
    return {"Authorization": f"Splunk {session_key}"}


def deploy_correlation_search(base_url, headers, rule):
    """Deploy a correlation search to Splunk ES."""
    search_payload = {
        "search": f"search {rule['spl']}",
        "name": rule["name"],
        "description": rule["description"],
        "cron_schedule": "*/15 * * * *",
        "dispatch.earliest_time": "-15m",
        "dispatch.latest_time": "now",
        "alert_type": "always",
        "alert.severity": "4" if rule["severity"] == "critical" else "3",
        "action.notable": "1",
        "action.notable.param.security_domain": "threat",
        "action.notable.param.severity": rule["severity"],
        "action.notable.param.rule_title": rule["name"],
    }
    resp = requests.post(
        f"{base_url}/services/saved/searches",
        headers=headers,
        data=search_payload,
        verify=False,
    )
    if resp.status_code in (200, 201):
        logger.info("Deployed correlation search: %s", rule["name"])
        return True
    logger.warning("Deploy failed for %s: %d %s", rule["name"], resp.status_code, resp.text[:100])
    return False


def generate_sigma_rule(rule):
    """Generate a Sigma-format YAML rule from a correlation definition."""
    sigma = {
        "title": rule["name"],
        "id": None,
        "status": "experimental",
        "description": rule["description"],
        "references": [f"https://attack.mitre.org/techniques/{rule['mitre']}/"],
        "logsource": {"product": "windows", "service": "sysmon"},
        "detection": {
            "selection": {"EventID": [1, 3, 17, 18]},
            "condition": "selection",
        },
        "level": rule["severity"],
        "tags": [f"attack.{rule['mitre'].lower()}"],
    }
    return yaml.dump(sigma, default_flow_style=False, sort_keys=False)


def audit_existing_searches(base_url, headers):
    """Audit existing Splunk saved searches for coverage gaps."""
    resp = requests.get(
        f"{base_url}/services/saved/searches",
        headers=headers,
        params={"output_mode": "json", "count": 0},
        verify=False,
    )
    if resp.status_code != 200:
        return []
    searches = resp.json().get("entry", [])
    mitre_covered = set()
    for s in searches:
        content = s.get("content", {})
        search_text = content.get("search", "").lower()
        for technique in ["t1021", "t1047", "t1053", "t1550", "t1003"]:
            if technique in search_text or technique in s.get("name", "").lower():
                mitre_covered.add(technique)
    lateral_techniques = {"t1021", "t1047", "t1053", "t1550", "t1003", "t1059", "t1570"}
    gaps = lateral_techniques - mitre_covered
    logger.info("Coverage: %d/%d lateral movement techniques covered", len(mitre_covered), len(lateral_techniques))
    return list(gaps)


def run_test_search(base_url, headers, spl, earliest="-24h"):
    """Execute a correlation search and return matching events."""
    resp = requests.post(
        f"{base_url}/services/search/jobs",
        headers=headers,
        data={"search": f"search {spl}", "earliest_time": earliest, "output_mode": "json"},
        verify=False,
    )
    resp.raise_for_status()
    sid = resp.json()["sid"]
    for _ in range(60):
        status = requests.get(
            f"{base_url}/services/search/jobs/{sid}",
            headers=headers, params={"output_mode": "json"}, verify=False,
        ).json()
        if status["entry"][0]["content"]["isDone"]:
            break
        time.sleep(2)
    results = requests.get(
        f"{base_url}/services/search/jobs/{sid}/results",
        headers=headers, params={"output_mode": "json", "count": 50}, verify=False,
    ).json()
    return results.get("results", [])


def generate_report(deployed, gaps, test_results):
    """Generate correlation rules deployment report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "rules_deployed": deployed,
        "coverage_gaps": gaps,
        "test_results_summary": {r["name"]: len(r.get("hits", [])) for r in test_results},
    }
    print(f"CORRELATION RULES REPORT: {len(deployed)} deployed, {len(gaps)} gaps")
    return report


def main():
    parser = argparse.ArgumentParser(description="SIEM Correlation Rules Agent")
    parser.add_argument("--splunk-url", default="https://localhost:8089")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", required=True)
    parser.add_argument("--deploy", action="store_true", help="Deploy rules to Splunk")
    parser.add_argument("--test", action="store_true", help="Test rules against recent data")
    parser.add_argument("--sigma-export", help="Export rules as Sigma YAML to directory")
    parser.add_argument("--output", default="correlation_report.json")
    args = parser.parse_args()

    headers = authenticate_splunk(args.splunk_url, args.username, args.password)
    deployed = []
    test_results = []

    if args.deploy:
        for rule in LATERAL_MOVEMENT_RULES:
            if deploy_correlation_search(args.splunk_url, headers, rule):
                deployed.append(rule["name"])

    if args.test:
        for rule in LATERAL_MOVEMENT_RULES:
            hits = run_test_search(args.splunk_url, headers, rule["spl"])
            test_results.append({"name": rule["name"], "hits": hits})
            logger.info("Rule '%s': %d hits", rule["name"], len(hits))

    if args.sigma_export:
        import os
        os.makedirs(args.sigma_export, exist_ok=True)
        for rule in LATERAL_MOVEMENT_RULES:
            sigma_yaml = generate_sigma_rule(rule)
            fname = rule["name"].lower().replace(" ", "_") + ".yml"
            with open(os.path.join(args.sigma_export, fname), "w") as f:
                f.write(sigma_yaml)
        logger.info("Exported %d Sigma rules", len(LATERAL_MOVEMENT_RULES))

    gaps = audit_existing_searches(args.splunk_url, headers)
    report = generate_report(deployed, gaps, test_results)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
