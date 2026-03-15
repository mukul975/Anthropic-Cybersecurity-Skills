#!/usr/bin/env python3
"""Splunk SOAR (Phantom) automation agent for playbook management."""

import json
import sys
import argparse
from datetime import datetime

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)


class SplunkSOARClient:
    """Client for Splunk SOAR (Phantom) REST API."""

    def __init__(self, base_url, auth_token, verify_ssl=False):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "ph-auth-token": auth_token,
            "Content-Type": "application/json",
        })
        self.session.verify = verify_ssl

    def _get(self, endpoint, params=None):
        resp = self.session.get(f"{self.base_url}/rest{endpoint}", params=params)
        resp.raise_for_status()
        return resp.json()

    def _post(self, endpoint, data=None):
        resp = self.session.post(f"{self.base_url}/rest{endpoint}", json=data)
        resp.raise_for_status()
        return resp.json()

    def list_playbooks(self, page_size=50):
        """List all configured playbooks."""
        return self._get("/playbook", params={"page_size": page_size})

    def get_playbook(self, playbook_id):
        """Get details of a specific playbook."""
        return self._get(f"/playbook/{playbook_id}")

    def run_playbook(self, playbook_id, container_id, scope="all"):
        """Execute a playbook against a container."""
        return self._post("/playbook_run", data={
            "playbook_id": playbook_id,
            "container_id": container_id,
            "scope": scope,
        })

    def list_containers(self, label=None, status=None, page_size=50):
        """List containers (incidents/events)."""
        params = {"page_size": page_size, "sort": "id", "order": "desc"}
        if label:
            params["_filter_label"] = f'"{label}"'
        if status:
            params["_filter_status"] = f'"{status}"'
        return self._get("/container", params=params)

    def create_container(self, name, label, severity, description=""):
        """Create a new container for an incident."""
        return self._post("/container", data={
            "name": name, "label": label,
            "severity": severity, "description": description,
            "status": "new",
        })

    def add_artifact(self, container_id, name, cef_data, label="event"):
        """Add an artifact (IOC) to a container."""
        return self._post("/artifact", data={
            "container_id": container_id,
            "name": name,
            "label": label,
            "cef": cef_data,
            "severity": "medium",
        })

    def list_apps(self):
        """List installed apps (connectors)."""
        return self._get("/app")

    def list_assets(self):
        """List configured assets."""
        return self._get("/asset")

    def get_action_results(self, action_run_id):
        """Get results of an action run."""
        return self._get(f"/action_run/{action_run_id}")

    def run_action(self, action_name, app_id, asset_id, parameters, container_id):
        """Run an action via an app connector."""
        return self._post("/action_run", data={
            "action": action_name,
            "app_id": app_id,
            "asset_id": asset_id,
            "container_id": container_id,
            "parameters": [parameters],
        })

    def get_system_info(self):
        """Get SOAR system information."""
        return self._get("/system_info")

    def list_users(self):
        """List SOAR users."""
        return self._get("/ph_user")


def create_phishing_response_playbook_data():
    """Generate phishing response playbook configuration."""
    return {
        "name": "Phishing Investigation and Response",
        "description": "Automated phishing email triage and response",
        "steps": [
            {"action": "file_reputation", "app": "VirusTotal",
             "description": "Check attachment hash against VT"},
            {"action": "url_reputation", "app": "VirusTotal",
             "description": "Check URLs in email against VT"},
            {"action": "domain_reputation", "app": "VirusTotal",
             "description": "Check sender domain reputation"},
            {"action": "whois_domain", "app": "WHOIS",
             "description": "WHOIS lookup on sender domain"},
            {"action": "hunt_email", "app": "Exchange",
             "description": "Search for same email across mailboxes"},
            {"action": "decision_gate", "type": "prompt",
             "description": "Analyst reviews enrichment and decides"},
            {"action": "quarantine_email", "app": "Exchange",
             "description": "Quarantine email from all mailboxes"},
            {"action": "block_sender", "app": "Firewall",
             "description": "Block sender IP/domain on email gateway"},
            {"action": "create_ticket", "app": "ServiceNow",
             "description": "Create incident ticket for tracking"},
        ],
    }


def create_malware_containment_playbook_data():
    """Generate malware containment playbook configuration."""
    return {
        "name": "Malware Containment and Remediation",
        "steps": [
            {"action": "get_process_info", "app": "CrowdStrike",
             "description": "Get process details from EDR"},
            {"action": "file_reputation", "app": "VirusTotal",
             "description": "Check file hash reputation"},
            {"action": "detonate_file", "app": "Sandbox",
             "description": "Detonate in sandbox if unknown"},
            {"action": "decision_gate", "type": "prompt",
             "description": "Analyst approves containment"},
            {"action": "contain_device", "app": "CrowdStrike",
             "description": "Network isolate the endpoint"},
            {"action": "disable_user", "app": "ActiveDirectory",
             "description": "Disable compromised user account"},
            {"action": "create_ticket", "app": "ServiceNow",
             "description": "Create P1 incident ticket"},
        ],
    }


def run_soar_audit(client):
    """Run SOAR platform audit."""
    print(f"\n{'='*60}")
    print(f"  SPLUNK SOAR (PHANTOM) AUDIT")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    try:
        sys_info = client.get_system_info()
        print(f"--- SYSTEM INFO ---")
        print(f"  Version: {sys_info.get('version', 'N/A')}")
        print(f"  Build: {sys_info.get('build', 'N/A')}")
    except Exception as e:
        print(f"  System info unavailable: {e}")

    playbooks = client.list_playbooks()
    pb_data = playbooks.get("data", [])
    print(f"\n--- PLAYBOOKS ({len(pb_data)}) ---")
    for pb in pb_data[:15]:
        status = "ACTIVE" if pb.get("active") else "INACTIVE"
        print(f"  [{status}] {pb.get('name', 'N/A')} (ID: {pb.get('id')})")

    apps = client.list_apps()
    app_data = apps.get("data", [])
    print(f"\n--- INSTALLED APPS ({len(app_data)}) ---")
    for app in app_data[:15]:
        print(f"  {app.get('name', 'N/A')} v{app.get('app_version', 'N/A')}")

    assets = client.list_assets()
    asset_data = assets.get("data", [])
    print(f"\n--- CONFIGURED ASSETS ({len(asset_data)}) ---")
    for asset in asset_data[:10]:
        print(f"  {asset.get('name', 'N/A')} -> {asset.get('product_name', 'N/A')}")

    containers = client.list_containers(status="open")
    ct_data = containers.get("data", [])
    print(f"\n--- OPEN CONTAINERS ({len(ct_data)}) ---")
    for ct in ct_data[:10]:
        print(f"  [{ct.get('severity', 'N/A')}] {ct.get('name', 'N/A')} (Status: {ct.get('status')})")

    print(f"\n--- PLAYBOOK TEMPLATES ---")
    phishing = create_phishing_response_playbook_data()
    print(f"  {phishing['name']}: {len(phishing['steps'])} steps")
    malware = create_malware_containment_playbook_data()
    print(f"  {malware['name']}: {len(malware['steps'])} steps")

    print(f"\n{'='*60}\n")
    return {"playbooks": len(pb_data), "apps": len(app_data), "containers": len(ct_data)}


def main():
    parser = argparse.ArgumentParser(description="Splunk SOAR Automation Agent")
    parser.add_argument("--url", required=True, help="SOAR instance URL")
    parser.add_argument("--token", required=True, help="SOAR auth token")
    parser.add_argument("--audit", action="store_true", help="Run SOAR audit")
    parser.add_argument("--list-playbooks", action="store_true")
    parser.add_argument("--run-playbook", nargs=2, metavar=("PB_ID", "CONTAINER_ID"),
                        help="Run playbook on container")
    parser.add_argument("--output", help="Save report to JSON")
    args = parser.parse_args()

    client = SplunkSOARClient(args.url, args.token)

    if args.audit:
        report = run_soar_audit(client)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
    elif args.list_playbooks:
        pb = client.list_playbooks()
        for p in pb.get("data", []):
            print(f"  [{p.get('id')}] {p.get('name')}")
    elif args.run_playbook:
        result = client.run_playbook(int(args.run_playbook[0]), int(args.run_playbook[1]))
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
