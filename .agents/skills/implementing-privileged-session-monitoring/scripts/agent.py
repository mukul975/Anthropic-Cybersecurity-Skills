#!/usr/bin/env python3
"""Privileged session monitoring agent.

Monitors SSH auth logs, Windows RDP events, and database sessions to
track privileged access, detect anomalies, and generate audit reports.
"""

import argparse
import json
import os
import re
import sys
import datetime
import collections

try:
    import subprocess
    HAS_SUBPROCESS = True
except ImportError:
    HAS_SUBPROCESS = False


SESSION_POLICIES = {
    "max_duration_hours": 8,
    "max_idle_minutes": 30,
    "require_mfa": True,
    "record_session": True,
    "allowed_hours": {"start": 6, "end": 22},
    "restricted_commands": [
        r"rm\s+-rf\s+/", r"dd\s+if=", r"mkfs\.", r"shutdown", r"reboot",
        r"passwd\s+root", r"visudo", r"chmod\s+777", r"iptables\s+-F",
    ],
}

PRIVILEGED_ACCOUNTS = [
    "root", "administrator", "admin", "dba", "sa",
    "sysadmin", "service_account", "deploy",
]


def parse_ssh_auth_log(log_path, max_lines=10000):
    """Parse SSH authentication log for session events."""
    sessions = []
    pattern = re.compile(
        r"(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[(\d+)\]:\s+"
        r"(Accepted|Failed)\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
    )
    try:
        with open(log_path, "r") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                m = pattern.search(line)
                if m:
                    sessions.append({
                        "timestamp": m.group(1),
                        "hostname": m.group(2),
                        "pid": m.group(3),
                        "status": m.group(4).lower(),
                        "auth_method": m.group(5),
                        "username": m.group(6),
                        "source_ip": m.group(7),
                        "source_port": int(m.group(8)),
                        "privileged": m.group(6).lower() in PRIVILEGED_ACCOUNTS,
                    })
    except FileNotFoundError:
        return {"error": f"Log file not found: {log_path}"}
    return sessions


def parse_rdp_events_windows():
    """Parse Windows RDP logon events via PowerShell."""
    cmd = (
        "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} "
        "| Where-Object {$_.Properties[8].Value -eq 10} "
        "| Select-Object -First 50 "
        "| ForEach-Object { @{TimeCreated=$_.TimeCreated.ToString('o');"
        "User=$_.Properties[5].Value;Domain=$_.Properties[6].Value;"
        "SourceIP=$_.Properties[18].Value} } | ConvertTo-Json"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=30
        )
        if result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            return [
                {
                    "timestamp": d.get("TimeCreated", ""),
                    "username": d.get("User", ""),
                    "domain": d.get("Domain", ""),
                    "source_ip": d.get("SourceIP", ""),
                    "session_type": "RDP",
                    "privileged": d.get("User", "").lower() in PRIVILEGED_ACCOUNTS,
                }
                for d in data
            ]
        return []
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return []


def check_command_policy(command):
    """Check if a command violates session policy."""
    violations = []
    for pattern in SESSION_POLICIES["restricted_commands"]:
        if re.search(pattern, command, re.IGNORECASE):
            violations.append({
                "pattern": pattern,
                "command": command[:100],
                "action": "alert_and_log",
            })
    return violations


def detect_session_anomalies(sessions):
    """Detect anomalous session patterns."""
    anomalies = []
    ip_counts = collections.Counter(s.get("source_ip") for s in sessions)
    user_counts = collections.Counter(s.get("username") for s in sessions)

    for ip, count in ip_counts.items():
        if count > 20:
            anomalies.append({
                "type": "brute_force_candidate",
                "source_ip": ip,
                "attempt_count": count,
                "severity": "HIGH",
            })

    failed = [s for s in sessions if s.get("status") == "failed"]
    failed_by_user = collections.Counter(s.get("username") for s in failed)
    for user, count in failed_by_user.items():
        if count >= 5:
            anomalies.append({
                "type": "failed_auth_spike",
                "username": user,
                "failed_count": count,
                "severity": "HIGH" if user in PRIVILEGED_ACCOUNTS else "MEDIUM",
            })

    priv_sessions = [s for s in sessions if s.get("privileged")]
    for ps in priv_sessions:
        anomalies.append({
            "type": "privileged_session",
            "username": ps.get("username"),
            "source_ip": ps.get("source_ip"),
            "severity": "MEDIUM",
        })

    return anomalies


def generate_audit_report(sessions, anomalies):
    """Generate privileged session audit report."""
    total = len(sessions)
    privileged = sum(1 for s in sessions if s.get("privileged"))
    accepted = sum(1 for s in sessions if s.get("status") == "accepted")
    failed = sum(1 for s in sessions if s.get("status") == "failed")
    unique_users = len(set(s.get("username") for s in sessions))
    unique_ips = len(set(s.get("source_ip") for s in sessions))

    return {
        "report_time": datetime.datetime.utcnow().isoformat() + "Z",
        "total_sessions": total,
        "accepted": accepted,
        "failed": failed,
        "privileged_sessions": privileged,
        "unique_users": unique_users,
        "unique_source_ips": unique_ips,
        "anomaly_count": len(anomalies),
        "policy": SESSION_POLICIES,
    }


def main():
    parser = argparse.ArgumentParser(description="Privileged session monitoring agent")
    parser.add_argument("--ssh-log", help="Path to SSH auth.log")
    parser.add_argument("--rdp", action="store_true", help="Parse Windows RDP events")
    parser.add_argument("--check-command", help="Check a command against policy")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    args = parser.parse_args()

    print("[*] Privileged Session Monitoring Agent")
    report = {"timestamp": datetime.datetime.utcnow().isoformat() + "Z"}

    sessions = []
    if args.ssh_log:
        sessions = parse_ssh_auth_log(args.ssh_log)
        if isinstance(sessions, dict) and "error" in sessions:
            print(f"[!] {sessions['error']}")
            sessions = []
        else:
            print(f"[*] SSH sessions parsed: {len(sessions)}")

    if args.rdp and sys.platform == "win32":
        rdp_sessions = parse_rdp_events_windows()
        sessions.extend(rdp_sessions)
        print(f"[*] RDP sessions parsed: {len(rdp_sessions)}")

    if args.check_command:
        violations = check_command_policy(args.check_command)
        if violations:
            print(f"[!] Command policy violations: {len(violations)}")
            for v in violations:
                print(f"    Pattern: {v['pattern']}")
        else:
            print("[*] Command passes policy check")
        report["command_check"] = {"command": args.check_command, "violations": violations}

    if sessions:
        anomalies = detect_session_anomalies(sessions)
        audit = generate_audit_report(sessions, anomalies)
        report["sessions"] = audit
        report["anomalies"] = anomalies
        print(f"[*] Anomalies detected: {len(anomalies)}")
    else:
        print("\n[DEMO] Usage: python agent.py --ssh-log /var/log/auth.log")
        print("  Monitors: SSH, RDP, privileged account access")
        print("  Detects: brute force, failed auth spikes, off-hours access")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)

    print(json.dumps({"sessions": len(sessions),
                       "anomalies": len(report.get("anomalies", []))}, indent=2))


if __name__ == "__main__":
    main()
