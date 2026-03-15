#!/usr/bin/env python3
"""Fail2ban port scan detection and management agent."""

import json
import os
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime


FAIL2BAN_CLIENT = "fail2ban-client"
FAIL2BAN_LOG = "/var/log/fail2ban.log"
AUTH_LOG = "/var/log/auth.log"


def check_fail2ban_status():
    """Check Fail2ban service status and active jails."""
    try:
        result = subprocess.run(
            [FAIL2BAN_CLIENT, "status"], capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return {"running": False, "error": result.stderr.strip()}

        jails = []
        for line in result.stdout.splitlines():
            if "Jail list" in line:
                jail_str = line.split(":", 1)[1].strip()
                jails = [j.strip() for j in jail_str.split(",") if j.strip()]
        return {"running": True, "jails": jails, "jail_count": len(jails)}
    except FileNotFoundError:
        return {"running": False, "error": "fail2ban-client not found"}


def get_jail_status(jail_name):
    """Get detailed status of a specific jail."""
    try:
        result = subprocess.run(
            [FAIL2BAN_CLIENT, "status", jail_name],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip()}

        info = {"jail": jail_name}
        for line in result.stdout.splitlines():
            line = line.strip()
            if "Currently failed" in line:
                info["currently_failed"] = int(line.split(":", 1)[1].strip())
            elif "Total failed" in line:
                info["total_failed"] = int(line.split(":", 1)[1].strip())
            elif "Currently banned" in line:
                info["currently_banned"] = int(line.split(":", 1)[1].strip())
            elif "Total banned" in line:
                info["total_banned"] = int(line.split(":", 1)[1].strip())
            elif "Banned IP list" in line:
                ips = line.split(":", 1)[1].strip()
                info["banned_ips"] = [ip.strip() for ip in ips.split() if ip.strip()]
        return info
    except Exception as e:
        return {"error": str(e)}


def ban_ip(ip_address, jail_name="sshd"):
    """Manually ban an IP address in a specific jail."""
    try:
        result = subprocess.run(
            [FAIL2BAN_CLIENT, "set", jail_name, "banip", ip_address],
            capture_output=True, text=True, timeout=10
        )
        return {
            "action": "ban",
            "ip": ip_address,
            "jail": jail_name,
            "success": result.returncode == 0,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    except Exception as e:
        return {"action": "ban", "success": False, "error": str(e)}


def unban_ip(ip_address, jail_name="sshd"):
    """Unban an IP address from a specific jail."""
    try:
        result = subprocess.run(
            [FAIL2BAN_CLIENT, "set", jail_name, "unbanip", ip_address],
            capture_output=True, text=True, timeout=10
        )
        return {
            "action": "unban",
            "ip": ip_address,
            "jail": jail_name,
            "success": result.returncode == 0,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    except Exception as e:
        return {"action": "unban", "success": False, "error": str(e)}


def parse_fail2ban_log(log_path=None, limit=5000):
    """Parse Fail2ban log for ban/unban statistics."""
    log_path = log_path or FAIL2BAN_LOG
    if not os.path.exists(log_path):
        return {"error": f"Log not found: {log_path}"}

    bans = Counter()
    unbans = Counter()
    jails = Counter()
    recent_bans = []

    with open(log_path, "r") as f:
        for i, line in enumerate(f):
            if i > limit:
                break
            if "Ban " in line:
                ip_match = re.search(r'Ban\s+(\d+\.\d+\.\d+\.\d+)', line)
                jail_match = re.search(r'\[([^\]]+)\]', line)
                if ip_match:
                    ip = ip_match.group(1)
                    jail = jail_match.group(1) if jail_match else "unknown"
                    bans[ip] += 1
                    jails[jail] += 1
                    recent_bans.append({"ip": ip, "jail": jail, "line": line.strip()[:200]})
            elif "Unban " in line:
                ip_match = re.search(r'Unban\s+(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    unbans[ip_match.group(1)] += 1

    return {
        "total_bans": sum(bans.values()),
        "total_unbans": sum(unbans.values()),
        "unique_banned_ips": len(bans),
        "top_banned_ips": bans.most_common(20),
        "bans_by_jail": dict(jails),
        "recent_bans": recent_bans[-20:],
    }


def parse_auth_log_ssh(log_path=None):
    """Parse auth.log for SSH brute force patterns."""
    log_path = log_path or AUTH_LOG
    if not os.path.exists(log_path):
        return {"error": f"Auth log not found: {log_path}"}

    failed_ips = Counter()
    failed_users = Counter()
    success_ips = Counter()

    with open(log_path, "r") as f:
        for line in f:
            if "Failed password" in line or "Failed publickey" in line:
                ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                user_match = re.search(r'for\s+(?:invalid\s+user\s+)?(\S+)', line)
                if ip_match:
                    failed_ips[ip_match.group(1)] += 1
                if user_match:
                    failed_users[user_match.group(1)] += 1
            elif "Accepted password" in line or "Accepted publickey" in line:
                ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    success_ips[ip_match.group(1)] += 1

    return {
        "total_failed": sum(failed_ips.values()),
        "unique_failed_ips": len(failed_ips),
        "top_failed_ips": failed_ips.most_common(20),
        "top_targeted_users": failed_users.most_common(20),
        "successful_logins": success_ips.most_common(10),
    }


def detect_port_scan_from_logs(log_path=None):
    """Detect port scanning patterns from system logs."""
    log_path = log_path or "/var/log/syslog"
    if not os.path.exists(log_path):
        return {"error": f"Syslog not found: {log_path}"}

    scanners = Counter()
    with open(log_path, "r") as f:
        for line in f:
            if "UFW BLOCK" in line or "iptables" in line.lower():
                ip_match = re.search(r'SRC=(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    scanners[ip_match.group(1)] += 1

    port_scanners = {ip: count for ip, count in scanners.items() if count > 20}
    return {
        "potential_scanners": len(port_scanners),
        "scanner_ips": sorted(port_scanners.items(), key=lambda x: x[1], reverse=True)[:20],
    }


def generate_report():
    """Generate comprehensive Fail2ban security report."""
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "service_status": check_fail2ban_status(),
        "ban_statistics": parse_fail2ban_log(),
        "ssh_analysis": parse_auth_log_ssh(),
        "port_scan_detection": detect_port_scan_from_logs(),
    }


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "report"
    if action == "report":
        print(json.dumps(generate_report(), indent=2, default=str))
    elif action == "status":
        print(json.dumps(check_fail2ban_status(), indent=2))
    elif action == "jail" and len(sys.argv) > 2:
        print(json.dumps(get_jail_status(sys.argv[2]), indent=2))
    elif action == "ban" and len(sys.argv) > 2:
        jail = sys.argv[3] if len(sys.argv) > 3 else "sshd"
        print(json.dumps(ban_ip(sys.argv[2], jail), indent=2))
    elif action == "unban" and len(sys.argv) > 2:
        jail = sys.argv[3] if len(sys.argv) > 3 else "sshd"
        print(json.dumps(unban_ip(sys.argv[2], jail), indent=2))
    elif action == "bans":
        print(json.dumps(parse_fail2ban_log(), indent=2))
    elif action == "ssh":
        print(json.dumps(parse_auth_log_ssh(), indent=2))
    else:
        print("Usage: agent.py [report|status|jail <name>|ban <ip> [jail]|unban <ip> [jail]|bans|ssh]")
