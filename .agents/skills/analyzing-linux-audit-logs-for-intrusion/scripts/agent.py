#!/usr/bin/env python3
"""Linux audit log analysis agent for intrusion detection.

Parses /var/log/audit/audit.log entries to detect privilege escalation,
unauthorized file access, suspicious syscalls, and process execution anomalies.
"""

import argparse
import json
import os
import re
import sys
import datetime
import collections
import subprocess


SUSPICIOUS_SYSCALLS = {
    "execve": "Program execution",
    "connect": "Network connection",
    "bind": "Port binding",
    "ptrace": "Process tracing/debugging",
    "init_module": "Kernel module loading",
    "finit_module": "Kernel module loading",
    "delete_module": "Kernel module unloading",
    "mount": "Filesystem mount",
    "umount2": "Filesystem unmount",
    "setuid": "UID change",
    "setgid": "GID change",
    "sethostname": "Hostname change",
    "open_by_handle_at": "File open by handle (container escape)",
}

SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/ssh/sshd_config", "/root/.ssh/authorized_keys",
    "/etc/crontab", "/var/spool/cron",
]

SUSPICIOUS_COMMANDS = [
    "curl", "wget", "nc", "ncat", "nmap", "tcpdump",
    "python", "perl", "ruby", "gcc", "cc", "make",
    "useradd", "usermod", "groupadd", "visudo",
    "iptables", "ip6tables", "nft",
]


def parse_audit_log(log_path, max_lines=50000):
    """Parse raw audit.log file into structured events."""
    events = []
    current = {}
    try:
        with open(log_path, "r") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                match = re.match(
                    r"type=(\S+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)", line
                )
                if not match:
                    continue
                event_type = match.group(1)
                timestamp = float(match.group(2))
                event_id = match.group(3)
                data_str = match.group(4)
                fields = dict(re.findall(r'(\w+)=("[^"]*"|\S+)', data_str))
                for k, v in fields.items():
                    fields[k] = v.strip('"')
                event = {
                    "type": event_type,
                    "timestamp": datetime.datetime.fromtimestamp(timestamp).isoformat(),
                    "event_id": event_id,
                    **fields,
                }
                events.append(event)
    except FileNotFoundError:
        return {"error": f"Log file not found: {log_path}"}
    return events


def detect_privilege_escalation(events):
    """Detect privilege escalation indicators in audit events."""
    findings = []
    for e in events:
        if e.get("type") == "SYSCALL" and e.get("syscall_name") in ("setuid", "setgid", "execve"):
            if e.get("uid") != "0" and e.get("euid") == "0":
                findings.append({
                    "type": "privilege_escalation",
                    "detail": f"UID {e.get('uid')} escalated to eUID 0",
                    "command": e.get("comm", ""),
                    "exe": e.get("exe", ""),
                    "timestamp": e.get("timestamp"),
                    "severity": "CRITICAL",
                })
        if e.get("type") == "USER_CMD" and "sudo" in e.get("cmd", "").lower():
            findings.append({
                "type": "sudo_usage",
                "user": e.get("acct", e.get("uid", "")),
                "command": e.get("cmd", ""),
                "timestamp": e.get("timestamp"),
                "severity": "MEDIUM",
            })
    return findings


def detect_file_access(events):
    """Detect access to sensitive files."""
    findings = []
    for e in events:
        if e.get("type") in ("PATH", "SYSCALL"):
            path = e.get("name", e.get("exe", ""))
            for sensitive in SENSITIVE_PATHS:
                if sensitive in path:
                    findings.append({
                        "type": "sensitive_file_access",
                        "path": path,
                        "syscall": e.get("syscall_name", e.get("syscall", "")),
                        "user": e.get("uid", ""),
                        "timestamp": e.get("timestamp"),
                        "severity": "HIGH",
                    })
                    break
    return findings


def detect_suspicious_commands(events):
    """Detect execution of suspicious commands."""
    findings = []
    for e in events:
        if e.get("type") in ("EXECVE", "SYSCALL"):
            comm = e.get("comm", "").lower()
            exe = e.get("exe", "").lower()
            for cmd in SUSPICIOUS_COMMANDS:
                if cmd in comm or cmd in exe:
                    findings.append({
                        "type": "suspicious_command",
                        "command": comm,
                        "exe": exe,
                        "user": e.get("uid", ""),
                        "timestamp": e.get("timestamp"),
                        "severity": "MEDIUM",
                    })
                    break
    return findings


def run_ausearch(key=None, message_type=None, success=None):
    """Run ausearch command and return results."""
    cmd = ["ausearch"]
    if key:
        cmd.extend(["-k", key])
    if message_type:
        cmd.extend(["-m", message_type])
    if success is not None:
        cmd.extend(["--success", "yes" if success else "no"])
    cmd.extend(["--format", "csv"])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {"output": result.stdout[:5000], "exit_code": result.returncode}
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {"error": str(e)}


def generate_summary(events, findings):
    """Generate audit log analysis summary."""
    event_types = collections.Counter(e.get("type") for e in events)
    finding_types = collections.Counter(f.get("type") for f in findings)
    severity_counts = collections.Counter(f.get("severity") for f in findings)
    return {
        "total_events": len(events),
        "event_types": dict(event_types.most_common(10)),
        "total_findings": len(findings),
        "finding_types": dict(finding_types),
        "by_severity": dict(severity_counts),
    }


def main():
    parser = argparse.ArgumentParser(description="Linux audit log intrusion detection agent")
    parser.add_argument("log_file", nargs="?", default="/var/log/audit/audit.log",
                        help="Path to audit.log (default: /var/log/audit/audit.log)")
    parser.add_argument("--max-lines", type=int, default=50000, help="Max log lines to parse")
    parser.add_argument("--ausearch-key", help="Run ausearch with this key")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    args = parser.parse_args()

    print("[*] Linux Audit Log Intrusion Detection Agent")

    if args.ausearch_key:
        result = run_ausearch(key=args.ausearch_key)
        print(json.dumps(result, indent=2))
        sys.exit(0)

    events = parse_audit_log(args.log_file, args.max_lines)
    if isinstance(events, dict) and "error" in events:
        print(f"[!] {events['error']}")
        print("[DEMO] Specify a valid audit.log path or run on a Linux system")
        print(json.dumps({"demo": True, "monitored_syscalls": len(SUSPICIOUS_SYSCALLS)}, indent=2))
        sys.exit(0)

    findings = []
    findings.extend(detect_privilege_escalation(events))
    findings.extend(detect_file_access(events))
    findings.extend(detect_suspicious_commands(events))

    summary = generate_summary(events, findings)
    print(f"[*] Events parsed: {summary['total_events']}")
    print(f"[*] Findings: {summary['total_findings']}")
    print(f"    By severity: {summary['by_severity']}")
    for f in findings[:15]:
        print(f"  [{f['severity']}] {f['type']}: {f.get('command', f.get('path', ''))}")

    if args.output:
        report = {"summary": summary, "findings": findings}
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
