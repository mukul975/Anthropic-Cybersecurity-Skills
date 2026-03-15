#!/usr/bin/env python3
"""Analyze Linux persistence mechanisms: crontab, systemd, LD_PRELOAD, shell profiles, SSH keys."""

import os
import re
import json
import glob
import subprocess
import argparse
from datetime import datetime
from collections import defaultdict

CRON_PATHS = [
    "/etc/crontab", "/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/",
    "/etc/cron.weekly/", "/etc/cron.monthly/", "/var/spool/cron/crontabs/",
    "/var/spool/cron/",
]

SYSTEMD_PATHS = [
    "/etc/systemd/system/", "/lib/systemd/system/", "/usr/lib/systemd/system/",
    "/run/systemd/system/",
]

SHELL_PROFILES = [".bashrc", ".bash_profile", ".profile", ".zshrc", ".bash_logout"]

SUSPICIOUS_PATTERNS = [
    r"(nc|ncat|netcat)\s+.*-[elp]", r"(bash|sh)\s+-i\s+>&", r"/dev/tcp/",
    r"curl\s+.*\|\s*(bash|sh)", r"wget\s+.*-O\s*-\s*\|\s*(bash|sh)",
    r"python.*-c\s+.*socket", r"base64\s+--decode", r"chmod\s+\+s\s",
    r"(socat|openssl)\s+.*exec", r"crontab\s+-r",
]


def scan_crontabs():
    """Scan all crontab locations for suspicious entries."""
    findings = []
    for path in CRON_PATHS:
        if os.path.isfile(path):
            findings.extend(_scan_cron_file(path))
        elif os.path.isdir(path):
            for entry in os.listdir(path):
                full_path = os.path.join(path, entry)
                if os.path.isfile(full_path):
                    findings.extend(_scan_cron_file(full_path))
    user_crontabs = subprocess.run(
        ["bash", "-c", "for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u $u 2>/dev/null && echo \"__USER:$u\"; done"],
        capture_output=True, text=True
    )
    if user_crontabs.returncode == 0:
        current_user = None
        for line in user_crontabs.stdout.splitlines():
            if line.startswith("__USER:"):
                current_user = line.split(":")[1]
            elif line.strip() and not line.startswith("#") and current_user:
                risk = _assess_cron_risk(line)
                findings.append({
                    "type": "user_crontab", "user": current_user,
                    "command": line.strip(), "risk": risk,
                    "mitre": "T1053.003",
                })
    return findings


def _scan_cron_file(filepath):
    """Scan a single cron file for entries."""
    entries = []
    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    risk = _assess_cron_risk(line)
                    entries.append({
                        "type": "cron_file", "path": filepath,
                        "command": line, "risk": risk,
                        "mtime": datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat(),
                        "mitre": "T1053.003",
                    })
    except PermissionError:
        entries.append({"type": "cron_file", "path": filepath, "error": "Permission denied"})
    return entries


def _assess_cron_risk(command):
    """Assess risk level of a cron command."""
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return "critical"
    if any(kw in command.lower() for kw in ["wget", "curl", "/tmp/", "base64", "chmod"]):
        return "high"
    return "low"


def scan_systemd_units():
    """Scan systemd service and timer units for persistence."""
    findings = []
    for base_path in SYSTEMD_PATHS:
        if not os.path.isdir(base_path):
            continue
        for unit_file in glob.glob(os.path.join(base_path, "*.service")) + \
                          glob.glob(os.path.join(base_path, "*.timer")):
            try:
                stat = os.stat(unit_file)
                with open(unit_file) as f:
                    content = f.read()
                risk = "low"
                exec_lines = re.findall(r"ExecStart\s*=\s*(.+)", content)
                for ex in exec_lines:
                    if any(s in ex for s in ["/tmp/", "/dev/shm/", "curl", "wget", "bash -c"]):
                        risk = "high"
                    for pattern in SUSPICIOUS_PATTERNS:
                        if re.search(pattern, ex, re.IGNORECASE):
                            risk = "critical"
                dpkg_check = subprocess.run(
                    ["dpkg", "-S", unit_file], capture_output=True, text=True
                )
                package_managed = dpkg_check.returncode == 0
                if not package_managed:
                    risk = max(risk, "medium", key=lambda x: ["low", "medium", "high", "critical"].index(x))
                findings.append({
                    "type": "systemd_unit", "path": unit_file,
                    "exec_start": exec_lines, "package_managed": package_managed,
                    "risk": risk, "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "mitre": "T1543.002",
                })
            except (PermissionError, FileNotFoundError):
                continue
    return findings


def scan_ld_preload():
    """Check for LD_PRELOAD hijacking."""
    findings = []
    preload_file = "/etc/ld.so.preload"
    if os.path.exists(preload_file):
        with open(preload_file) as f:
            content = f.read().strip()
        if content:
            findings.append({
                "type": "ld_preload_file", "path": preload_file,
                "libraries": content.splitlines(), "risk": "critical",
                "mitre": "T1574.006",
            })
    env_check = subprocess.run(["env"], capture_output=True, text=True)
    for line in env_check.stdout.splitlines():
        if line.startswith("LD_PRELOAD="):
            findings.append({
                "type": "ld_preload_env", "value": line.split("=", 1)[1],
                "risk": "critical", "mitre": "T1574.006",
            })
    return findings


def scan_shell_profiles():
    """Scan shell profile files for injected commands."""
    findings = []
    for home_dir in glob.glob("/home/*") + ["/root"]:
        for profile in SHELL_PROFILES:
            filepath = os.path.join(home_dir, profile)
            if not os.path.exists(filepath):
                continue
            try:
                with open(filepath) as f:
                    content = f.read()
                for pattern in SUSPICIOUS_PATTERNS:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        findings.append({
                            "type": "shell_profile", "path": filepath,
                            "matched_pattern": pattern, "risk": "critical",
                            "mitre": "T1546.004",
                        })
            except PermissionError:
                continue
    etc_profiles = glob.glob("/etc/profile.d/*.sh")
    for filepath in etc_profiles:
        dpkg = subprocess.run(["dpkg", "-S", filepath], capture_output=True, text=True)
        if dpkg.returncode != 0:
            findings.append({
                "type": "etc_profile_d", "path": filepath,
                "package_managed": False, "risk": "medium", "mitre": "T1546.004",
            })
    return findings


def scan_ssh_authorized_keys():
    """Audit SSH authorized_keys files for unauthorized entries."""
    findings = []
    for home_dir in glob.glob("/home/*") + ["/root"]:
        auth_keys = os.path.join(home_dir, ".ssh", "authorized_keys")
        if not os.path.exists(auth_keys):
            continue
        try:
            with open(auth_keys) as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    risk = "low"
                    if "command=" in line:
                        risk = "high"
                    if "no-pty" not in line and "command=" in line:
                        risk = "critical"
                    findings.append({
                        "type": "authorized_key", "path": auth_keys,
                        "line_number": i, "key_snippet": line[:80] + "...",
                        "has_command_restriction": "command=" in line,
                        "risk": risk, "mitre": "T1098.004",
                    })
        except PermissionError:
            continue
    return findings


def generate_report(cron, systemd, ld_preload, profiles, ssh_keys):
    """Generate persistence analysis report."""
    all_findings = cron + systemd + ld_preload + profiles + ssh_keys
    risk_counts = defaultdict(int)
    for f in all_findings:
        risk_counts[f.get("risk", "unknown")] += 1
    return {
        "report_time": datetime.utcnow().isoformat(),
        "total_findings": len(all_findings),
        "risk_summary": dict(risk_counts),
        "crontab_findings": len(cron),
        "systemd_findings": len(systemd),
        "ld_preload_findings": len(ld_preload),
        "shell_profile_findings": len(profiles),
        "ssh_key_findings": len(ssh_keys),
        "findings": all_findings,
    }


def main():
    parser = argparse.ArgumentParser(description="Linux Persistence Mechanism Analyzer")
    parser.add_argument("--output", default="linux_persistence_report.json")
    parser.add_argument("--scan", nargs="+", default=["all"],
                        choices=["all", "cron", "systemd", "ldpreload", "profiles", "ssh"])
    args = parser.parse_args()

    scans = set(args.scan) if "all" not in args.scan else {"cron", "systemd", "ldpreload", "profiles", "ssh"}
    cron = scan_crontabs() if "cron" in scans else []
    systemd = scan_systemd_units() if "systemd" in scans else []
    ld_preload = scan_ld_preload() if "ldpreload" in scans else []
    profiles = scan_shell_profiles() if "profiles" in scans else []
    ssh_keys = scan_ssh_authorized_keys() if "ssh" in scans else []

    report = generate_report(cron, systemd, ld_preload, profiles, ssh_keys)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Scanned {len(scans)} persistence categories")
    print(f"[+] Found {report['total_findings']} persistence artifacts")
    print(f"[+] Risk: critical={report['risk_summary'].get('critical', 0)} "
          f"high={report['risk_summary'].get('high', 0)}")
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
