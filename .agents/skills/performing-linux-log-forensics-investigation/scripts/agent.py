#!/usr/bin/env python3
"""Agent for performing Linux log forensics investigation."""

import json
import argparse
import re
import gzip
from datetime import datetime
from pathlib import Path
from collections import Counter


def analyze_auth_log(log_file):
    """Analyze /var/log/auth.log for suspicious authentication events."""
    content = _read_log(log_file)
    failed_logins = []
    successful_logins = []
    sudo_events = []
    ssh_events = []
    for line in content.splitlines():
        if "Failed password" in line or "authentication failure" in line:
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            user_match = re.search(r"for (?:invalid user )?(\S+)", line)
            failed_logins.append({
                "user": user_match.group(1) if user_match else "",
                "source_ip": ip_match.group(1) if ip_match else "",
                "line": line.strip()[:200],
            })
        elif "Accepted" in line:
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            user_match = re.search(r"for (\S+)", line)
            successful_logins.append({
                "user": user_match.group(1) if user_match else "",
                "source_ip": ip_match.group(1) if ip_match else "",
            })
        elif "sudo:" in line and "COMMAND=" in line:
            cmd_match = re.search(r"COMMAND=(.*)", line)
            user_match = re.search(r"sudo:\s+(\S+)", line)
            sudo_events.append({
                "user": user_match.group(1) if user_match else "",
                "command": cmd_match.group(1)[:200] if cmd_match else "",
            })
        elif "sshd" in line:
            ssh_events.append(line.strip()[:200])
    brute_force_ips = Counter(f.get("source_ip") for f in failed_logins if f.get("source_ip"))
    bf_suspects = [{"ip": ip, "attempts": count} for ip, count in brute_force_ips.most_common(10) if count >= 5]
    return {
        "log_file": log_file,
        "failed_logins": len(failed_logins),
        "successful_logins": len(successful_logins),
        "sudo_commands": len(sudo_events),
        "brute_force_suspects": bf_suspects,
        "failed_users": dict(Counter(f.get("user") for f in failed_logins).most_common(10)),
        "sudo_events": sudo_events[:20],
        "successful_logins_detail": successful_logins[:20],
    }


def analyze_syslog(log_file):
    """Analyze /var/log/syslog for anomalies."""
    content = _read_log(log_file)
    errors = []
    kernel_events = []
    cron_events = []
    for line in content.splitlines():
        lower = line.lower()
        if "error" in lower or "fail" in lower or "critical" in lower:
            errors.append(line.strip()[:200])
        if "kernel:" in lower:
            if any(kw in lower for kw in ["segfault", "oom", "killed", "panic", "bug", "usb"]):
                kernel_events.append(line.strip()[:200])
        if "cron" in lower:
            cron_events.append(line.strip()[:200])
    return {
        "log_file": log_file,
        "total_errors": len(errors),
        "kernel_anomalies": len(kernel_events),
        "cron_jobs": len(cron_events),
        "top_errors": errors[:20],
        "kernel_events": kernel_events[:15],
        "cron_events": cron_events[:15],
    }


def analyze_command_history(history_file):
    """Analyze bash history for suspicious commands."""
    content = Path(history_file).read_text(encoding="utf-8", errors="replace")
    suspicious_patterns = [
        (r"curl.*\|.*sh", "REMOTE_CODE_EXECUTION"),
        (r"wget.*\|.*bash", "REMOTE_CODE_EXECUTION"),
        (r"chmod\s+[47]77", "WORLD_WRITABLE_PERMISSION"),
        (r"nc\s+-[elp]", "NETCAT_LISTENER"),
        (r"/dev/tcp/", "BASH_REVERSE_SHELL"),
        (r"base64\s+-d", "BASE64_DECODE"),
        (r"python.*-c.*import.*socket", "PYTHON_REVERSE_SHELL"),
        (r"crontab\s+-[er]", "CRONTAB_MODIFICATION"),
        (r"iptables\s+-F", "FIREWALL_FLUSH"),
        (r"history\s+-c", "HISTORY_CLEAR"),
        (r"rm\s+-rf\s+/", "DESTRUCTIVE_COMMAND"),
        (r"dd\s+if=.*of=/dev/", "DISK_OVERWRITE"),
    ]
    findings = []
    for line in content.splitlines():
        cmd = line.strip()
        for pattern, tag in suspicious_patterns:
            if re.search(pattern, cmd, re.I):
                findings.append({"command": cmd[:200], "tag": tag, "pattern": pattern})
                break
    return {
        "history_file": history_file,
        "total_commands": len(content.splitlines()),
        "suspicious_commands": len(findings),
        "findings": findings[:30],
        "tags": dict(Counter(f["tag"] for f in findings)),
    }


def timeline_analysis(log_files, start_time=None, end_time=None):
    """Create timeline from multiple log sources."""
    events = []
    ts_patterns = [
        re.compile(r"(\w{3}\s+\d+\s+\d+:\d+:\d+)"),
        re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"),
    ]
    for log_file in log_files:
        content = _read_log(log_file)
        for line in content.splitlines():
            ts = None
            for tp in ts_patterns:
                m = tp.search(line)
                if m:
                    ts = m.group(1)
                    break
            if ts:
                events.append({"timestamp": ts, "source": Path(log_file).name, "event": line.strip()[:200]})
    events.sort(key=lambda x: x["timestamp"])
    return {
        "sources": log_files,
        "total_events": len(events),
        "timeline": events[:100],
    }


def _read_log(filepath):
    """Read log file, supporting gzip."""
    p = Path(filepath)
    if p.suffix == ".gz":
        with gzip.open(filepath, "rt", encoding="utf-8", errors="replace") as f:
            return f.read()
    return p.read_text(encoding="utf-8", errors="replace")


def main():
    parser = argparse.ArgumentParser(description="Linux Log Forensics Investigation Agent")
    sub = parser.add_subparsers(dest="command")
    a = sub.add_parser("auth", help="Analyze auth.log")
    a.add_argument("--file", required=True)
    s = sub.add_parser("syslog", help="Analyze syslog")
    s.add_argument("--file", required=True)
    h = sub.add_parser("history", help="Analyze bash history")
    h.add_argument("--file", required=True)
    t = sub.add_parser("timeline", help="Create event timeline")
    t.add_argument("--files", nargs="+", required=True)
    args = parser.parse_args()
    if args.command == "auth":
        result = analyze_auth_log(args.file)
    elif args.command == "syslog":
        result = analyze_syslog(args.file)
    elif args.command == "history":
        result = analyze_command_history(args.file)
    elif args.command == "timeline":
        result = timeline_analysis(args.files)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
