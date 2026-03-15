#!/usr/bin/env python3
"""Host-based intrusion detection agent using OSSEC/Wazuh API and osquery."""

import json
import sys
import argparse
import subprocess
from datetime import datetime

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


class WazuhClient:
    """Wazuh API client for HIDS management."""

    def __init__(self, base_url, username, password):
        self.url = base_url.rstrip("/")
        self.token = self._authenticate(username, password)

    def _authenticate(self, username, password):
        resp = requests.post(f"{self.url}/security/user/authenticate",
                             auth=(username, password), verify=False)
        resp.raise_for_status()
        return resp.json()["data"]["token"]

    def _get(self, endpoint, params=None):
        resp = requests.get(f"{self.url}/{endpoint}",
                            headers={"Authorization": f"Bearer {self.token}"},
                            params=params, verify=False)
        resp.raise_for_status()
        return resp.json()

    def list_agents(self, status=None):
        params = {}
        if status:
            params["status"] = status
        return self._get("agents", params)

    def get_agent_alerts(self, agent_id, limit=20):
        return self._get(f"alerts", {"agent.id": agent_id, "limit": limit})

    def get_sca_results(self, agent_id):
        return self._get(f"sca/{agent_id}")

    def get_rootcheck(self, agent_id):
        return self._get(f"rootcheck/{agent_id}")


def run_osquery_check(query):
    """Execute osquery for host inspection."""
    cmd = ["osqueryi", "--json", query]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return json.loads(result.stdout) if result.stdout.strip() else []
    except (FileNotFoundError, json.JSONDecodeError):
        return [{"error": "osquery not available"}]


def check_file_integrity(paths):
    """Check file integrity for key system files."""
    checks = []
    import hashlib, os
    for path in paths:
        if os.path.exists(path):
            with open(path, "rb") as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
            stat = os.stat(path)
            checks.append({
                "path": path,
                "sha256": sha256,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "status": "present",
            })
        else:
            checks.append({"path": path, "status": "missing", "severity": "HIGH"})
    return checks


def run_audit(wazuh_url=None, username=None, password=None, agent_id=None):
    """Execute HIDS audit."""
    print(f"\n{'='*60}")
    print(f"  HOST-BASED INTRUSION DETECTION AUDIT")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    if wazuh_url and username and password:
        client = WazuhClient(wazuh_url, username, password)
        agents = client.list_agents()
        data = agents.get("data", {})
        items = data.get("affected_items", [])
        print(f"--- WAZUH AGENTS ({data.get('total_affected_items', 0)}) ---")
        for a in items[:10]:
            print(f"  {a.get('name', 'N/A')} ({a.get('id', '')}): {a.get('status', '')}")

        if agent_id:
            sca = client.get_sca_results(agent_id)
            sca_data = sca.get("data", {}).get("affected_items", [])
            print(f"\n--- SCA RESULTS (agent {agent_id}) ---")
            for s in sca_data[:5]:
                print(f"  {s.get('name', '')}: pass={s.get('pass', 0)} fail={s.get('fail', 0)}")

    system_files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config"]
    integrity = check_file_integrity(system_files)
    print(f"\n--- FILE INTEGRITY CHECK ---")
    for f in integrity:
        print(f"  {f['path']}: {f['status']}")

    processes = run_osquery_check("SELECT name, pid, uid FROM processes WHERE uid = 0")
    print(f"\n--- ROOT PROCESSES ({len(processes)}) ---")
    for p in processes[:10]:
        if "error" not in p:
            print(f"  PID {p.get('pid', '')}: {p.get('name', '')}")

    return {"integrity": integrity, "processes": processes}


def main():
    parser = argparse.ArgumentParser(description="HIDS Audit Agent")
    parser.add_argument("--wazuh-url", help="Wazuh API URL (https://host:55000)")
    parser.add_argument("--username", help="Wazuh API username")
    parser.add_argument("--password", help="Wazuh API password")
    parser.add_argument("--agent-id", help="Specific agent ID to audit")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args.wazuh_url, args.username, args.password, args.agent_id)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
