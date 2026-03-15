#!/usr/bin/env python3
"""Agent for implementing security monitoring with Datadog.

Configures Cloud SIEM detection rules, queries security signals,
manages log pipelines, and audits security monitoring coverage
using the Datadog API.
"""

import json
import sys
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


class DatadogSecurityAgent:
    """Manages Datadog security monitoring configuration."""

    def __init__(self, api_key, app_key, site="datadoghq.com",
                 output_dir="./datadog_security"):
        self.api_key = api_key
        self.app_key = app_key
        self.base_url = f"https://api.{site}/api"
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def _get(self, path, params=None):
        if not requests:
            return None
        try:
            return requests.get(
                f"{self.base_url}{path}", params=params,
                headers={"DD-API-KEY": self.api_key, "DD-APPLICATION-KEY": self.app_key},
                timeout=15,
            )
        except requests.RequestException:
            return None

    def _post(self, path, data=None):
        if not requests:
            return None
        try:
            return requests.post(
                f"{self.base_url}{path}", json=data,
                headers={"DD-API-KEY": self.api_key, "DD-APPLICATION-KEY": self.app_key,
                          "Content-Type": "application/json"},
                timeout=15,
            )
        except requests.RequestException:
            return None

    def list_security_rules(self):
        """List configured security detection rules."""
        resp = self._get("/v2/security_monitoring/rules")
        if resp and resp.status_code == 200:
            rules = resp.json().get("data", [])
            return [{"id": r["id"], "name": r.get("name"), "enabled": r.get("isEnabled"),
                     "type": r.get("type")} for r in rules]
        return []

    def query_security_signals(self, query="*", hours=24):
        """Query security signals from Cloud SIEM."""
        now = datetime.utcnow()
        body = {
            "filter": {"query": query, "from": f"now-{hours}h", "to": "now"},
            "sort": "timestamp", "page": {"limit": 25},
        }
        resp = self._post("/v2/security_monitoring/signals/search", body)
        if resp and resp.status_code == 200:
            signals = resp.json().get("data", [])
            by_severity = {}
            for s in signals:
                sev = s.get("attributes", {}).get("severity", "unknown")
                by_severity[sev] = by_severity.get(sev, 0) + 1
            return {"total": len(signals), "by_severity": by_severity}
        return {"total": 0}

    def list_log_pipelines(self):
        """List log processing pipelines."""
        resp = self._get("/v1/logs/config/pipelines")
        if resp and resp.status_code == 200:
            pipelines = resp.json()
            return [{"id": p["id"], "name": p.get("name"), "enabled": p.get("is_enabled"),
                     "type": p.get("type")} for p in pipelines]
        return []

    def check_log_indexes(self):
        """Check log index configuration for retention."""
        resp = self._get("/v1/logs/config/indexes")
        if resp and resp.status_code == 200:
            indexes = resp.json().get("indexes", [])
            for idx in indexes:
                retention = idx.get("num_retention_days", 0)
                if retention < 90:
                    self.findings.append({"severity": "medium", "type": "Short Log Retention",
                                          "detail": f"Index '{idx.get('name')}' retains {retention} days"})
            return indexes
        return []

    def audit_monitors(self):
        """Audit security-related monitors."""
        resp = self._get("/v1/monitor", params={"tags": "security"})
        if resp and resp.status_code == 200:
            monitors = resp.json()
            return {"total": len(monitors),
                    "by_state": self._count_by(monitors, lambda m: m.get("overall_state", "unknown"))}
        return {"total": 0}

    def _count_by(self, items, key_fn):
        counts = {}
        for item in items:
            k = key_fn(item)
            counts[k] = counts.get(k, 0) + 1
        return counts

    def generate_report(self):
        rules = self.list_security_rules()
        signals = self.query_security_signals()
        pipelines = self.list_log_pipelines()
        indexes = self.check_log_indexes()
        monitors = self.audit_monitors()

        if len(rules) < 10:
            self.findings.append({"severity": "medium", "type": "Low Rule Coverage",
                                  "detail": f"Only {len(rules)} detection rules configured"})

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "detection_rules": {"count": len(rules), "rules": rules[:20]},
            "security_signals": signals,
            "log_pipelines": {"count": len(pipelines), "pipelines": pipelines},
            "monitors": monitors,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "datadog_security_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 3:
        print("Usage: agent.py <api_key> <app_key> [--site datadoghq.eu]")
        sys.exit(1)
    site = "datadoghq.com"
    if "--site" in sys.argv:
        site = sys.argv[sys.argv.index("--site") + 1]
    agent = DatadogSecurityAgent(sys.argv[1], sys.argv[2], site)
    agent.generate_report()


if __name__ == "__main__":
    main()
