#!/usr/bin/env python3
"""Active breach containment agent for incident response operations."""

import json
import subprocess
import sys
from datetime import datetime


def block_ip_at_firewall(ip_address, chain="INPUT", comment="breach-containment"):
    """Block a C2 or malicious IP address using iptables."""
    cmd = [
        "iptables", "-A", chain, "-s", ip_address, "-j", "DROP",
        "-m", "comment", "--comment", comment,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return {
            "action": "block_ip",
            "ip": ip_address,
            "success": result.returncode == 0,
            "error": result.stderr.strip() if result.returncode != 0 else None,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    except Exception as e:
        return {"action": "block_ip", "ip": ip_address, "success": False, "error": str(e)}


def disable_ad_account(username, domain_controller=None):
    """Disable a compromised Active Directory account via PowerShell."""
    ps_cmd = f'Disable-ADAccount -Identity "{username}" -Confirm:$false'
    if domain_controller:
        ps_cmd += f' -Server "{domain_controller}"'
    cmd = ["powershell", "-Command", ps_cmd]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {
            "action": "disable_account",
            "username": username,
            "success": result.returncode == 0,
            "error": result.stderr.strip() if result.returncode != 0 else None,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    except Exception as e:
        return {"action": "disable_account", "username": username, "success": False, "error": str(e)}


def reset_ad_password(username, domain_controller=None):
    """Force password reset for a compromised AD account."""
    ps_cmd = (
        f'Set-ADAccountPassword -Identity "{username}" -Reset '
        f'-NewPassword (ConvertTo-SecureString -AsPlainText '
        f'"TempP@ss{datetime.now().strftime("%H%M%S")}!" -Force)'
    )
    if domain_controller:
        ps_cmd += f' -Server "{domain_controller}"'
    cmd = ["powershell", "-Command", ps_cmd]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {
            "action": "reset_password",
            "username": username,
            "success": result.returncode == 0,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    except Exception as e:
        return {"action": "reset_password", "username": username, "success": False, "error": str(e)}


def isolate_host_firewall(host_ip, management_ip=None):
    """Isolate a compromised host by blocking all traffic except management."""
    commands = []
    if management_ip:
        commands.append(
            ["iptables", "-A", "FORWARD", "-s", host_ip, "-d", management_ip, "-j", "ACCEPT"]
        )
        commands.append(
            ["iptables", "-A", "FORWARD", "-s", management_ip, "-d", host_ip, "-j", "ACCEPT"]
        )
    commands.append(["iptables", "-A", "FORWARD", "-s", host_ip, "-j", "DROP"])
    commands.append(["iptables", "-A", "FORWARD", "-d", host_ip, "-j", "DROP"])

    results = []
    for cmd in commands:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            results.append({"cmd": " ".join(cmd), "success": r.returncode == 0})
        except Exception as e:
            results.append({"cmd": " ".join(cmd), "success": False, "error": str(e)})

    return {
        "action": "isolate_host",
        "host_ip": host_ip,
        "management_ip": management_ip,
        "results": results,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


def block_smb_lateral_movement():
    """Block SMB (port 445) between server VLANs to prevent lateral movement."""
    cmd = ["iptables", "-A", "FORWARD", "-p", "tcp", "--dport", "445", "-j", "DROP"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return {
            "action": "block_smb",
            "success": result.returncode == 0,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    except Exception as e:
        return {"action": "block_smb", "success": False, "error": str(e)}


def sinkhole_domain(domain, sinkhole_ip="127.0.0.1", hosts_file="/etc/hosts"):
    """Add DNS sinkhole entry for a C2 domain."""
    entry = f"{sinkhole_ip}\t{domain}\t# breach-containment {datetime.utcnow().isoformat()}"
    try:
        with open(hosts_file, "r") as f:
            existing = f.read()
        if domain in existing:
            return {"action": "sinkhole", "domain": domain, "status": "already_sinkholed"}
        with open(hosts_file, "a") as f:
            f.write("\n" + entry + "\n")
        return {
            "action": "sinkhole",
            "domain": domain,
            "sinkhole_ip": sinkhole_ip,
            "success": True,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    except Exception as e:
        return {"action": "sinkhole", "domain": domain, "success": False, "error": str(e)}


def collect_volatile_evidence(host="localhost"):
    """Collect volatile system data from a compromised host for forensics."""
    evidence = {}
    commands = {
        "processes": ["ps", "auxww"],
        "network_connections": ["ss", "-tunap"],
        "logged_users": ["who"],
        "routing_table": ["ip", "route", "show"],
        "arp_table": ["arp", "-an"],
        "open_files": ["lsof", "-i", "-P"],
    }
    for name, cmd in commands.items():
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            evidence[name] = r.stdout.strip()
        except Exception as e:
            evidence[name] = f"Error: {e}"

    return {
        "action": "collect_evidence",
        "host": host,
        "evidence": evidence,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


def generate_containment_report(incident_id, actions_taken):
    """Generate a structured containment status report."""
    return {
        "report_type": "CONTAINMENT_STATUS",
        "incident_id": incident_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "status": "CONTAINED",
        "actions_taken": actions_taken,
        "validation_pending": [
            "Confirm C2 beacons ceased",
            "Verify disabled accounts produce auth failures",
            "Check no new lateral movement attempts",
        ],
    }


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "help"
    if action == "block-ip" and len(sys.argv) > 2:
        print(json.dumps(block_ip_at_firewall(sys.argv[2]), indent=2))
    elif action == "disable-account" and len(sys.argv) > 2:
        print(json.dumps(disable_ad_account(sys.argv[2]), indent=2))
    elif action == "isolate-host" and len(sys.argv) > 2:
        mgmt = sys.argv[3] if len(sys.argv) > 3 else None
        print(json.dumps(isolate_host_firewall(sys.argv[2], mgmt), indent=2))
    elif action == "block-smb":
        print(json.dumps(block_smb_lateral_movement(), indent=2))
    elif action == "sinkhole" and len(sys.argv) > 2:
        print(json.dumps(sinkhole_domain(sys.argv[2]), indent=2))
    elif action == "collect-evidence":
        print(json.dumps(collect_volatile_evidence(), indent=2))
    else:
        print("Usage: agent.py [block-ip <ip>|disable-account <user>|isolate-host <ip> [mgmt_ip]|block-smb|sinkhole <domain>|collect-evidence]")
