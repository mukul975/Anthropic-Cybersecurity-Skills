#!/usr/bin/env python3
"""Agent for securing container registry with Harbor.

Audits Harbor registry security configuration including RBAC,
vulnerability scanning policies, content trust, immutable tags,
and OIDC authentication via Harbor REST API v2.0.
"""

import json
import sys
import base64
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


class HarborSecurityAgent:
    """Audits and hardens Harbor container registry security."""

    def __init__(self, harbor_url, username="admin", password="",
                 output_dir="./harbor_audit"):
        self.base_url = harbor_url.rstrip("/") + "/api/v2.0"
        self.auth = (username, password)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def _get(self, path, params=None):
        if not requests:
            return {"error": "requests library required"}
        resp = requests.get(f"{self.base_url}{path}", auth=self.auth,
                            params=params, verify=True, timeout=15)
        try:
            return resp.json()
        except (json.JSONDecodeError, ValueError):
            return {"status": resp.status_code}

    def audit_projects(self):
        """Audit all projects for security configuration."""
        projects = self._get("/projects", {"page_size": 100})
        if isinstance(projects, dict) and "error" in projects:
            return projects

        results = []
        for p in projects:
            meta = p.get("metadata", {})
            name = p.get("name", "")
            issues = []

            if meta.get("public") == "true":
                issues.append("Project is public - images accessible without auth")
            if meta.get("auto_scan") != "true":
                issues.append("Auto-scan on push not enabled")
            if meta.get("prevent_vul") != "true":
                issues.append("Vulnerability prevention not enabled")
            if meta.get("enable_content_trust") != "true":
                issues.append("Content trust (Notary) not enabled")
            if meta.get("enable_content_trust_cosign") != "true":
                issues.append("Cosign content trust not enabled")

            for issue in issues:
                self.findings.append({
                    "severity": "high" if "public" in issue or "prevent_vul" in issue else "medium",
                    "project": name,
                    "issue": issue,
                })

            results.append({
                "name": name,
                "public": meta.get("public"),
                "auto_scan": meta.get("auto_scan"),
                "prevent_vul": meta.get("prevent_vul"),
                "content_trust": meta.get("enable_content_trust"),
                "cosign": meta.get("enable_content_trust_cosign"),
                "issues": issues,
            })
        return results

    def audit_system_config(self):
        """Check system-level security configuration."""
        config = self._get("/configurations")
        if isinstance(config, dict) and "error" in config:
            return config

        checks = []
        auth_mode = config.get("auth_mode", {}).get("value", "db_auth")
        if auth_mode == "db_auth":
            self.findings.append({
                "severity": "medium",
                "issue": "Using local database auth instead of OIDC/LDAP",
            })
            checks.append({"check": "auth_mode", "value": auth_mode, "status": "WARN"})
        else:
            checks.append({"check": "auth_mode", "value": auth_mode, "status": "OK"})

        self_reg = config.get("self_registration", {}).get("value", True)
        if self_reg:
            self.findings.append({
                "severity": "high",
                "issue": "Self-registration enabled - anyone can create accounts",
            })
        checks.append({"check": "self_registration", "value": self_reg,
                        "status": "FAIL" if self_reg else "OK"})

        return checks

    def list_project_members(self, project_name):
        """List members and their roles for a project."""
        members = self._get(f"/projects/{project_name}/members")
        if isinstance(members, dict) and "error" in members:
            return members
        role_map = {1: "ProjectAdmin", 2: "Maintainer", 3: "Developer",
                    4: "Guest", 5: "LimitedGuest"}
        return [
            {"username": m.get("entity_name", ""), "role": role_map.get(m.get("role_id"), "Unknown")}
            for m in (members if isinstance(members, list) else [])
        ]

    def check_immutable_tags(self, project_name):
        """Check immutable tag rules for a project."""
        rules = self._get(f"/projects/{project_name}/immutabletagrules")
        if not rules or (isinstance(rules, dict) and "error" in rules):
            self.findings.append({
                "severity": "medium",
                "project": project_name,
                "issue": "No immutable tag rules configured",
            })
            return []
        return rules

    def audit_logs(self, page_size=20):
        """Retrieve recent audit log entries."""
        logs = self._get("/audit-logs", {"page_size": page_size})
        if isinstance(logs, dict) and "error" in logs:
            return logs
        return [
            {"operation": l.get("operation"), "resource": l.get("resource"),
             "username": l.get("username"), "time": l.get("op_time")}
            for l in (logs if isinstance(logs, list) else [])
        ]

    def generate_report(self):
        projects = self.audit_projects()
        sys_config = self.audit_system_config()

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "harbor_url": self.base_url.replace("/api/v2.0", ""),
            "projects_audited": len(projects) if isinstance(projects, list) else 0,
            "system_config": sys_config,
            "projects": projects,
            "findings": self.findings,
            "finding_count": len(self.findings),
        }
        out = self.output_dir / "harbor_audit_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <harbor_url> [--user admin] [--pass Harbor12345]")
        sys.exit(1)

    url = sys.argv[1]
    user = "admin"
    password = "Harbor12345"
    if "--user" in sys.argv:
        user = sys.argv[sys.argv.index("--user") + 1]
    if "--pass" in sys.argv:
        password = sys.argv[sys.argv.index("--pass") + 1]

    agent = HarborSecurityAgent(url, user, password)
    agent.generate_report()


if __name__ == "__main__":
    main()
