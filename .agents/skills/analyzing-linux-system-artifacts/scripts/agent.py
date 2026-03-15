#!/usr/bin/env python3
"""Linux system artifact forensics agent for investigating compromised systems."""

import os
import sys
import glob
import json
import re
import datetime
import subprocess


def run_cmd(cmd):
    """Execute a shell command and return output."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def analyze_passwd(passwd_path):
    """Analyze /etc/passwd for suspicious accounts."""
    findings = []
    with open(passwd_path, "r") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) < 7:
                continue
            username, _, uid, gid = parts[0], parts[1], int(parts[2]), int(parts[3])
            home, shell = parts[5], parts[6]
            if uid == 0 and username != "root":
                findings.append({
                    "severity": "CRITICAL",
                    "finding": f"UID 0 account: {username} (shell: {shell})",
                })
            login_shells = ["/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/zsh"]
            if uid < 1000 and uid > 0 and shell in login_shells:
                findings.append({
                    "severity": "WARNING",
                    "finding": f"System account with login shell: {username} (UID:{uid})",
                })
            if uid >= 1000 and shell not in ["/bin/false", "/usr/sbin/nologin", "/bin/sync"]:
                findings.append({
                    "severity": "INFO",
                    "finding": f"Interactive user: {username} (UID:{uid}, Home:{home})",
                })
    return findings


def analyze_shadow(shadow_path):
    """Analyze /etc/shadow for password hash types and status."""
    findings = []
    with open(shadow_path, "r") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) < 3:
                continue
            username = parts[0]
            pwd_hash = parts[1]
            if pwd_hash and pwd_hash not in ("*", "!", "!!", ""):
                hash_type = "Unknown"
                if pwd_hash.startswith("$6$"):
                    hash_type = "SHA-512"
                elif pwd_hash.startswith("$5$"):
                    hash_type = "SHA-256"
                elif pwd_hash.startswith("$y$"):
                    hash_type = "yescrypt"
                elif pwd_hash.startswith("$1$"):
                    hash_type = "MD5 (WEAK)"
                    findings.append({
                        "severity": "WARNING",
                        "finding": f"{username} uses weak MD5 password hash",
                    })
                findings.append({
                    "severity": "INFO",
                    "finding": f"{username}: {hash_type} hash, last changed day {parts[2]}",
                })
    return findings


def analyze_bash_history(history_path, username="unknown"):
    """Analyze bash history for suspicious commands."""
    suspicious_patterns = [
        "wget", "curl", "nc ", "ncat", "netcat", "python -c", "python3 -c",
        "perl -e", "base64", "chmod 777", "chmod +s", "/dev/tcp", "/dev/udp",
        "nmap", "masscan", "hydra", "john", "hashcat", "passwd", "useradd",
        "iptables -F", "ufw disable", "history -c", "rm -rf", "dd if=",
        "crontab", "systemctl enable", "ssh-keygen", "scp ", "rsync",
        "/tmp/", "/dev/shm/", "mkfifo", "socat",
    ]
    findings = []
    with open(history_path, "r", errors="ignore") as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        line_stripped = line.strip()
        for pattern in suspicious_patterns:
            if pattern in line_stripped.lower():
                findings.append({
                    "user": username,
                    "line_number": i + 1,
                    "command": line_stripped[:200],
                    "matched_pattern": pattern,
                })
                break
    return findings


def check_cron_persistence(evidence_root):
    """Check cron jobs for persistence mechanisms."""
    findings = []
    cron_paths = [
        os.path.join(evidence_root, "etc/crontab"),
        *glob.glob(os.path.join(evidence_root, "etc/cron.d/*")),
        *glob.glob(os.path.join(evidence_root, "var/spool/cron/crontabs/*")),
    ]
    for cron_path in cron_paths:
        if os.path.exists(cron_path) and os.path.isfile(cron_path):
            with open(cron_path, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        suspicious = any(
                            p in line.lower()
                            for p in ["wget", "curl", "/tmp/", "/dev/shm/", "base64",
                                      "python", "bash -i", "reverse", "nc ", "ncat"]
                        )
                        if suspicious:
                            findings.append({
                                "severity": "HIGH",
                                "source": cron_path,
                                "entry": line[:200],
                            })
    return findings


def check_ssh_keys(evidence_root):
    """Check for unauthorized SSH authorized_keys."""
    findings = []
    key_files = glob.glob(
        os.path.join(evidence_root, "home/*/.ssh/authorized_keys")
    ) + glob.glob(
        os.path.join(evidence_root, "root/.ssh/authorized_keys")
    )
    for key_file in key_files:
        if os.path.exists(key_file):
            with open(key_file, "r") as f:
                keys = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            if keys:
                findings.append({
                    "file": key_file,
                    "key_count": len(keys),
                    "keys": [k[:80] + "..." for k in keys],
                })
    return findings


def check_systemd_persistence(evidence_root):
    """Check for suspicious systemd service files."""
    findings = []
    service_dirs = [
        os.path.join(evidence_root, "etc/systemd/system"),
        os.path.join(evidence_root, "usr/lib/systemd/system"),
    ]
    for svc_dir in service_dirs:
        if not os.path.exists(svc_dir):
            continue
        for svc_file in glob.glob(os.path.join(svc_dir, "*.service")):
            with open(svc_file, "r", errors="ignore") as f:
                content = f.read()
            suspicious = any(
                p in content.lower()
                for p in ["/tmp/", "/dev/shm/", "wget", "curl", "reverse",
                          "bash -i", "nc ", "python", "base64"]
            )
            if suspicious:
                findings.append({
                    "severity": "HIGH",
                    "file": svc_file,
                    "preview": content[:300],
                })
    return findings


def check_ld_preload(evidence_root):
    """Check for LD_PRELOAD rootkit indicators."""
    findings = []
    preload_path = os.path.join(evidence_root, "etc/ld.so.preload")
    if os.path.exists(preload_path):
        with open(preload_path, "r") as f:
            content = f.read().strip()
        if content:
            findings.append({
                "severity": "CRITICAL",
                "finding": f"/etc/ld.so.preload contains: {content}",
            })
    return findings


def find_suid_binaries(evidence_root):
    """Find SUID/SGID binaries (potential privilege escalation)."""
    stdout, _, rc = run_cmd(
        f"find {evidence_root} -perm -4000 -type f 2>/dev/null"
    )
    return stdout.splitlines() if rc == 0 and stdout else []


def find_suspicious_tmp_files(evidence_root):
    """Find suspicious files in /tmp and /dev/shm."""
    findings = []
    for tmp_dir in ["tmp", "dev/shm"]:
        full_path = os.path.join(evidence_root, tmp_dir)
        if os.path.exists(full_path):
            for root, dirs, files in os.walk(full_path):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    findings.append(fpath)
    return findings


if __name__ == "__main__":
    print("=" * 60)
    print("Linux System Artifacts Forensics Agent")
    print("User accounts, persistence, shell history, rootkit detection")
    print("=" * 60)

    evidence_root = sys.argv[1] if len(sys.argv) > 1 else "/mnt/evidence"

    if os.path.exists(evidence_root):
        print(f"\n[*] Examining evidence root: {evidence_root}")

        passwd_path = os.path.join(evidence_root, "etc/passwd")
        if os.path.exists(passwd_path):
            print("\n--- User Account Analysis ---")
            for f in analyze_passwd(passwd_path):
                print(f"  [{f['severity']}] {f['finding']}")

        print("\n--- Cron Persistence ---")
        cron = check_cron_persistence(evidence_root)
        for c in cron:
            print(f"  [{c['severity']}] {c['source']}: {c['entry'][:80]}")

        print("\n--- SSH Authorized Keys ---")
        ssh = check_ssh_keys(evidence_root)
        for s in ssh:
            print(f"  {s['file']}: {s['key_count']} keys")

        print("\n--- Systemd Persistence ---")
        systemd = check_systemd_persistence(evidence_root)
        for s in systemd:
            print(f"  [{s['severity']}] {s['file']}")

        print("\n--- LD_PRELOAD Rootkit Check ---")
        ld = check_ld_preload(evidence_root)
        for l in ld:
            print(f"  [{l['severity']}] {l['finding']}")

        print("\n--- Suspicious Temp Files ---")
        tmp = find_suspicious_tmp_files(evidence_root)
        for t in tmp[:20]:
            print(f"  {t}")
    else:
        print(f"\n[DEMO] Usage: python agent.py <evidence_mount_point>")
        print("[*] Mount a forensic image and provide the path for analysis.")
