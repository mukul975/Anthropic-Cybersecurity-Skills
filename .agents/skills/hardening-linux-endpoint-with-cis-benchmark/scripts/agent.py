#!/usr/bin/env python3
"""Agent for auditing Linux endpoints against CIS Benchmark hardening controls."""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone


def run_cmd(cmd, timeout=10):
    """Run a shell command and return stdout."""
    try:
        return subprocess.check_output(
            cmd, shell=True, text=True, errors="replace",
            timeout=timeout, stderr=subprocess.DEVNULL
        ).strip()
    except subprocess.SubprocessError:
        return ""


def check_filesystem_config():
    """CIS Section 1 — Filesystem Configuration."""
    findings = []
    cramfs = run_cmd("modprobe -n -v cramfs 2>/dev/null")
    if "install /bin/true" not in cramfs and "install /bin/false" not in cramfs:
        findings.append({"check": "1.1.1.1", "issue": "cramfs module not disabled", "severity": "LOW"})
    tmp_mount = run_cmd("findmnt /tmp")
    if not tmp_mount:
        findings.append({"check": "1.1.2", "issue": "/tmp not a separate partition", "severity": "MEDIUM"})
    elif "nodev" not in tmp_mount or "nosuid" not in tmp_mount:
        findings.append({"check": "1.1.3", "issue": "/tmp missing nodev/nosuid options", "severity": "MEDIUM"})
    return findings


def check_services():
    """CIS Section 2 — Services."""
    findings = []
    unnecessary = ["avahi-daemon", "cups", "dhcpd", "slapd", "nfs-server",
                    "rpcbind", "named", "vsftpd", "httpd", "dovecot", "smb", "squid"]
    for svc in unnecessary:
        status = run_cmd(f"systemctl is-enabled {svc} 2>/dev/null")
        if status == "enabled":
            findings.append({"check": "2.x", "issue": f"Unnecessary service enabled: {svc}", "severity": "MEDIUM"})
    return findings


def check_network_parameters():
    """CIS Section 3 — Network Parameters."""
    findings = []
    params = {
        "net.ipv4.ip_forward": ("0", "3.1.1", "IP forwarding enabled"),
        "net.ipv4.conf.all.send_redirects": ("0", "3.1.2", "ICMP redirects enabled"),
        "net.ipv4.conf.all.accept_source_route": ("0", "3.2.1", "Source routing accepted"),
        "net.ipv4.conf.all.accept_redirects": ("0", "3.2.2", "ICMP redirects accepted"),
        "net.ipv4.conf.all.log_martians": ("1", "3.2.4", "Martian logging disabled"),
        "net.ipv4.tcp_syncookies": ("1", "3.2.8", "SYN cookies disabled"),
    }
    for param, (expected, cis_id, desc) in params.items():
        value = run_cmd(f"sysctl -n {param} 2>/dev/null")
        if value != expected:
            findings.append({"check": cis_id, "issue": desc, "current": value, "expected": expected, "severity": "MEDIUM"})
    return findings


def check_access_auth():
    """CIS Section 5 — Access, Authentication, Authorization."""
    findings = []
    sshd_config = run_cmd("cat /etc/ssh/sshd_config 2>/dev/null")
    if "PermitRootLogin yes" in sshd_config:
        findings.append({"check": "5.2.10", "issue": "SSH root login permitted", "severity": "HIGH"})
    if "PasswordAuthentication yes" in sshd_config:
        findings.append({"check": "5.2.12", "issue": "SSH password authentication enabled", "severity": "MEDIUM"})
    if "Protocol 1" in sshd_config:
        findings.append({"check": "5.2.4", "issue": "SSH Protocol 1 enabled", "severity": "HIGH"})

    passwd_maxdays = run_cmd("grep PASS_MAX_DAYS /etc/login.defs 2>/dev/null")
    if passwd_maxdays:
        match = re.search(r'PASS_MAX_DAYS\s+(\d+)', passwd_maxdays)
        if match and int(match.group(1)) > 365:
            findings.append({"check": "5.4.1.1", "issue": f"Password max age: {match.group(1)} days", "severity": "MEDIUM"})
    return findings


def check_audit_logging():
    """CIS Section 4 — Logging and Auditing."""
    findings = []
    auditd = run_cmd("systemctl is-active auditd 2>/dev/null")
    if auditd != "active":
        findings.append({"check": "4.1.1", "issue": "auditd not active", "severity": "HIGH"})
    rsyslog = run_cmd("systemctl is-active rsyslog 2>/dev/null")
    if rsyslog != "active":
        findings.append({"check": "4.2.1", "issue": "rsyslog not active", "severity": "MEDIUM"})
    return findings


def check_file_permissions():
    """CIS Section 6 — System File Permissions."""
    findings = []
    critical_files = {
        "/etc/passwd": "644",
        "/etc/shadow": "000",
        "/etc/group": "644",
        "/etc/gshadow": "000",
    }
    for fpath, expected in critical_files.items():
        if os.path.isfile(fpath):
            mode = oct(os.stat(fpath).st_mode)[-3:]
            if mode > expected:
                findings.append({"check": "6.1.x", "issue": f"{fpath}: mode {mode} > {expected}", "severity": "MEDIUM"})
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Audit Linux endpoint against CIS Benchmark"
    )
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    print("[*] Linux CIS Benchmark Hardening Audit Agent")
    all_findings = []
    all_findings.extend(check_filesystem_config())
    all_findings.extend(check_services())
    all_findings.extend(check_network_parameters())
    all_findings.extend(check_access_auth())
    all_findings.extend(check_audit_logging())
    all_findings.extend(check_file_permissions())

    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": all_findings,
        "total": len(all_findings),
        "high_severity": high,
        "compliance_score": max(0, 100 - len(all_findings) * 5),
    }
    print(f"[*] Findings: {len(all_findings)} (HIGH: {high})")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
