#!/usr/bin/env python3
"""Active security breach containment agent for automated response actions."""

import json
import sys
import argparse
import subprocess
from datetime import datetime

try:
    import requests
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


def isolate_host_crowdstrike(api_base, api_token, device_id):
    """Isolate a compromised host via CrowdStrike Falcon API."""
    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
    resp = requests.post(f"{api_base}/devices/entities/devices-actions/v2",
                         params={"action_name": "contain"},
                         headers=headers,
                         json={"ids": [device_id]})
    return {"action": "host_isolation", "device_id": device_id,
            "status": resp.status_code, "response": resp.json()}


def disable_ad_account(username, domain_controller):
    """Disable compromised AD account via PowerShell."""
    cmd = ["powershell", "-Command",
           f"Disable-ADAccount -Identity '{username}' -Server '{domain_controller}' -Confirm:$false"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return {"action": "disable_account", "username": username,
                "status": "success" if result.returncode == 0 else "failed",
                "output": result.stderr[:200] if result.stderr else ""}
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {"action": "disable_account", "status": "error", "error": str(e)}


def block_ip_firewall(ip_address):
    """Block attacker IP on network firewall."""
    cmd = ["powershell", "-Command",
           f"New-NetFirewallRule -DisplayName 'IR-Block-{ip_address}' -Direction Inbound "
           f"-Action Block -RemoteAddress '{ip_address}' -Profile Any"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return {"action": "block_ip", "ip": ip_address,
                "status": "success" if result.returncode == 0 else "failed"}
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {"action": "block_ip", "status": "error", "error": str(e)}


def generate_containment_checklist(incident_type):
    """Generate containment checklist based on incident type."""
    checklists = {
        "ransomware": [
            {"step": 1, "action": "Isolate affected hosts from network", "priority": "CRITICAL"},
            {"step": 2, "action": "Disable compromised user accounts", "priority": "CRITICAL"},
            {"step": 3, "action": "Block C2 IPs and domains at firewall", "priority": "HIGH"},
            {"step": 4, "action": "Preserve forensic evidence before reimaging", "priority": "HIGH"},
            {"step": 5, "action": "Reset Kerberos KRBTGT password twice", "priority": "HIGH"},
            {"step": 6, "action": "Revoke active VPN and remote access sessions", "priority": "HIGH"},
            {"step": 7, "action": "Notify legal and executive leadership", "priority": "MEDIUM"},
        ],
        "data_breach": [
            {"step": 1, "action": "Identify and isolate exfiltration channel", "priority": "CRITICAL"},
            {"step": 2, "action": "Revoke compromised API keys and tokens", "priority": "CRITICAL"},
            {"step": 3, "action": "Block external IPs involved in exfiltration", "priority": "HIGH"},
            {"step": 4, "action": "Preserve logs and network captures", "priority": "HIGH"},
            {"step": 5, "action": "Assess scope of data exposed", "priority": "HIGH"},
            {"step": 6, "action": "Engage legal for breach notification requirements", "priority": "MEDIUM"},
        ],
        "account_compromise": [
            {"step": 1, "action": "Disable compromised accounts immediately", "priority": "CRITICAL"},
            {"step": 2, "action": "Revoke all active sessions and tokens", "priority": "CRITICAL"},
            {"step": 3, "action": "Reset passwords and MFA enrollments", "priority": "HIGH"},
            {"step": 4, "action": "Review recent account activity and access logs", "priority": "HIGH"},
            {"step": 5, "action": "Check for persistence mechanisms (forwarding rules, OAuth apps)", "priority": "HIGH"},
        ],
    }
    return checklists.get(incident_type, checklists["ransomware"])


def run_containment(incident_type="ransomware"):
    """Execute breach containment planning."""
    print(f"\n{'='*60}")
    print(f"  ACTIVE BREACH CONTAINMENT")
    print(f"  Incident Type: {incident_type}")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    checklist = generate_containment_checklist(incident_type)
    print(f"--- CONTAINMENT CHECKLIST ---")
    for item in checklist:
        print(f"  [{item['priority']}] Step {item['step']}: {item['action']}")

    return {"incident_type": incident_type, "checklist": checklist}


def main():
    parser = argparse.ArgumentParser(description="Breach Containment Agent")
    parser.add_argument("--incident-type", choices=["ransomware", "data_breach", "account_compromise"],
                        default="ransomware", help="Type of incident")
    parser.add_argument("--isolate-host", help="CrowdStrike device ID to isolate")
    parser.add_argument("--disable-account", help="AD username to disable")
    parser.add_argument("--block-ip", help="Attacker IP to block")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_containment(args.incident_type)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
