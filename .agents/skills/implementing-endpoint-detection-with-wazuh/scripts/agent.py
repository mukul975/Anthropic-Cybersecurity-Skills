#!/usr/bin/env python3
"""Agent for implementing endpoint detection with Wazuh.

Manages Wazuh agents, queries alerts, tests custom decoder/rule
logic via logtest, and audits endpoint coverage using the
Wazuh REST API.
"""

import argparse
import json
import os
from datetime import datetime
from pathlib import Path

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    requests = None


class WazuhDetectionAgent:
    """Manages Wazuh endpoint detection via its REST API."""

    def __init__(self, wazuh_url, username, password,
                 output_dir="./wazuh_detection"):
        self.base_url = wazuh_url.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []
        self.token = self._authenticate(username, password)

    def _authenticate(self, username, password):
        """Authenticate and obtain JWT token."""
        if not requests:
            return None
        try:
            resp = requests.post(
                f"{self.base_url}/security/user/authenticate",
                auth=HTTPBasicAuth(username, password),
                verify=False, timeout=10,
            )
            if resp.status_code == 200:
                return resp.json().get("data", {}).get("token")
        except requests.RequestException:
            pass
        return None

    def _api(self, method, path, params=None, data=None):
        if not requests or not self.token:
            return None
        try:
            resp = requests.request(
                method, f"{self.base_url}{path}",
                headers={"Authorization": f"Bearer {self.token}"},
                params=params, json=data, verify=False, timeout=15,
            )
            return resp.json() if resp.status_code == 200 else None
        except requests.RequestException:
            return None

    def list_agents(self):
        """List all registered Wazuh agents with status."""
        data = self._api("GET", "/agents", params={"limit": 500, "select": "id,name,status,os.name,os.version,version,lastKeepAlive,ip"})
        if not data:
            return []
        agents = data.get("data", {}).get("affected_items", [])
        disconnected = [a for a in agents if a.get("status") == "disconnected"]
        if disconnected:
            self.findings.append({
                "severity": "medium", "type": "Disconnected Agents",
                "detail": f"{len(disconnected)} agents disconnected",
            })
        return agents

    def get_agent_summary(self):
        """Get agent status summary counts."""
        data = self._api("GET", "/agents/summary/status")
        if data:
            return data.get("data", {})
        return {}

    def query_alerts(self, limit=20, level_min=10):
        """Query recent high-severity alerts."""
        data = self._api("GET", "/alerts", params={
            "limit": limit, "sort": "-timestamp",
            "q": f"rule.level>={level_min}",
        })
        if not data:
            return []
        alerts = data.get("data", {}).get("affected_items", [])
        return [{
            "id": a.get("id"),
            "timestamp": a.get("timestamp"),
            "rule_id": a.get("rule", {}).get("id"),
            "rule_description": a.get("rule", {}).get("description"),
            "rule_level": a.get("rule", {}).get("level"),
            "agent_name": a.get("agent", {}).get("name"),
            "agent_id": a.get("agent", {}).get("id"),
        } for a in alerts]

    def get_rules_summary(self):
        """Get summary of active detection rules."""
        data = self._api("GET", "/rules", params={"limit": 500, "select": "id,description,level,groups"})
        if not data:
            return {"total": 0}
        rules = data.get("data", {}).get("affected_items", [])
        total = data.get("data", {}).get("total_affected_items", len(rules))
        levels = {}
        for r in rules:
            lvl = str(r.get("level", 0))
            levels[lvl] = levels.get(lvl, 0) + 1
        return {"total_rules": total, "by_level": levels}

    def test_logtest(self, log_line, log_format="syslog"):
        """Test a log line against Wazuh decoders and rules."""
        data = self._api("PUT", "/logtest", data={
            "log_format": log_format,
            "location": "test",
            "event": log_line,
        })
        if not data:
            return {"error": "Logtest failed"}
        result = data.get("data", {})
        return {
            "decoder": result.get("decoder", {}).get("name"),
            "rule_id": result.get("rule", {}).get("id"),
            "rule_description": result.get("rule", {}).get("description"),
            "rule_level": result.get("rule", {}).get("level"),
            "output": result.get("output"),
        }

    def check_vulnerability_detection(self):
        """Check if vulnerability detection module is enabled."""
        data = self._api("GET", "/manager/configuration",
                         params={"section": "vulnerability-detector"})
        if data:
            config = data.get("data", {}).get("affected_items", [])
            if config:
                enabled = config[0].get("vulnerability-detector", {}).get("enabled", "no")
                if enabled != "yes":
                    self.findings.append({
                        "severity": "medium", "type": "Vuln Detection Disabled",
                        "detail": "Vulnerability detection module is not enabled",
                    })
                return {"enabled": enabled == "yes"}
        return {"enabled": False}

    def generate_report(self):
        agents = self.list_agents()
        summary = self.get_agent_summary()
        alerts = self.query_alerts()
        rules = self.get_rules_summary()
        vuln_det = self.check_vulnerability_detection()

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "wazuh_url": self.base_url,
            "agent_summary": summary,
            "agents": agents[:50],
            "total_agents": len(agents),
            "recent_critical_alerts": alerts,
            "rules_summary": rules,
            "vulnerability_detection": vuln_det,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "wazuh_detection_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    parser = argparse.ArgumentParser(
        description="Manage Wazuh endpoint detection and query alerts"
    )
    parser.add_argument("wazuh_url", help="Wazuh API URL (e.g. https://wazuh:55000)")
    parser.add_argument("--username", default="wazuh-wui", help="API username")
    parser.add_argument("--password", required=True, help="API password")
    parser.add_argument("--output-dir", default="./wazuh_detection")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    agent = WazuhDetectionAgent(args.wazuh_url, args.username, args.password,
                                output_dir=args.output_dir)
    agent.generate_report()


if __name__ == "__main__":
    main()
