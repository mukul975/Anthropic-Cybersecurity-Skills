#!/usr/bin/env python3
"""Agent for scanning infrastructure with Tenable Nessus.

Interacts with the Nessus REST API to create scan policies,
launch scans, monitor progress, retrieve results, and generate
vulnerability reports with severity-based prioritization.
"""

import json
import sys
import time
import urllib3
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class NessusScanAgent:
    """Manages Nessus vulnerability scans via REST API."""

    def __init__(self, host="https://localhost:8834", username="admin",
                 password="", output_dir="./nessus_scan"):
        self.base_url = host.rstrip("/")
        self.username = username
        self.password = password
        self.token = None
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _req(self, method, path, data=None):
        """Make authenticated request to Nessus API."""
        if not requests:
            return {"error": "requests library required: pip install requests"}
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["X-Cookie"] = f"token={self.token}"
        url = f"{self.base_url}{path}"
        resp = requests.request(method, url, json=data, headers=headers,
                                verify=False, timeout=30)
        try:
            return resp.json()
        except (json.JSONDecodeError, ValueError):
            return {"status_code": resp.status_code, "text": resp.text[:200]}

    def authenticate(self):
        """Authenticate and obtain session token."""
        result = self._req("POST", "/session",
                           {"username": self.username, "password": self.password})
        self.token = result.get("token")
        return bool(self.token)

    def list_scans(self):
        """List all configured scans."""
        result = self._req("GET", "/scans")
        scans = []
        for s in result.get("scans", []):
            scans.append({
                "id": s.get("id"),
                "name": s.get("name"),
                "status": s.get("status"),
                "last_modification_date": s.get("last_modification_date"),
            })
        return scans

    def create_scan(self, name, targets, template_uuid=None):
        """Create a new scan configuration."""
        data = {
            "uuid": template_uuid or "ab4bacd2-05f6-425c-9d79-3f5a0a1f28b0",
            "settings": {
                "name": name,
                "text_targets": targets,
                "enabled": True,
                "launch": "ON_DEMAND",
            },
        }
        return self._req("POST", "/scans", data)

    def launch_scan(self, scan_id):
        """Launch a configured scan."""
        return self._req("POST", f"/scans/{scan_id}/launch")

    def get_scan_status(self, scan_id):
        """Get current scan status."""
        result = self._req("GET", f"/scans/{scan_id}")
        info = result.get("info", {})
        return {
            "status": info.get("status"),
            "host_count": info.get("hostcount", 0),
            "name": info.get("name"),
        }

    def get_scan_results(self, scan_id):
        """Retrieve scan results with vulnerability details."""
        result = self._req("GET", f"/scans/{scan_id}")
        hosts = []
        for h in result.get("hosts", []):
            hosts.append({
                "hostname": h.get("hostname"),
                "host_id": h.get("host_id"),
                "critical": h.get("critical", 0),
                "high": h.get("high", 0),
                "medium": h.get("medium", 0),
                "low": h.get("low", 0),
                "info": h.get("info", 0),
            })

        vulns = []
        for v in result.get("vulnerabilities", []):
            vulns.append({
                "plugin_id": v.get("plugin_id"),
                "plugin_name": v.get("plugin_name"),
                "severity": v.get("severity"),
                "count": v.get("count", 0),
                "family": v.get("plugin_family"),
            })

        return {
            "scan_id": scan_id,
            "hosts": hosts,
            "vulnerabilities": sorted(vulns, key=lambda x: x.get("severity", 0), reverse=True),
            "total_vulns": len(vulns),
        }

    def export_scan(self, scan_id, fmt="nessus"):
        """Export scan results in specified format."""
        result = self._req("POST", f"/scans/{scan_id}/export", {"format": fmt})
        file_id = result.get("file")
        if not file_id:
            return {"error": "Export failed"}

        for _ in range(60):
            status = self._req("GET", f"/scans/{scan_id}/export/{file_id}/status")
            if status.get("status") == "ready":
                break
            time.sleep(5)

        return {"file_id": file_id, "format": fmt, "status": "ready"}

    def generate_report(self, scan_id):
        results = self.get_scan_results(scan_id)
        report = {
            "report_date": datetime.utcnow().isoformat(),
            "scan_id": scan_id,
            "results": results,
        }
        out = self.output_dir / "nessus_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 3:
        print("Usage: agent.py <nessus_url> <scan_id> [--user admin] [--pass password]")
        sys.exit(1)

    host = sys.argv[1]
    scan_id = int(sys.argv[2])
    user = "admin"
    password = ""
    if "--user" in sys.argv:
        user = sys.argv[sys.argv.index("--user") + 1]
    if "--pass" in sys.argv:
        password = sys.argv[sys.argv.index("--pass") + 1]

    agent = NessusScanAgent(host, user, password)
    if agent.authenticate():
        agent.generate_report(scan_id)
    else:
        print("Authentication failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
