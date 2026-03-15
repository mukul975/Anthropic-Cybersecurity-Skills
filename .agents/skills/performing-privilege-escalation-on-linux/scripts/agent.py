#!/usr/bin/env python3
"""Agent for performing Linux privilege escalation enumeration — authorized testing only."""

import json
import argparse
import subprocess
import os
import re
from datetime import datetime
from pathlib import Path


def enumerate_system_info():
    """Gather basic system information for privilege escalation assessment."""
    cmds = {
        "hostname": ["hostname"],
        "kernel": ["uname", "-a"],
        "os_release": ["cat", "/etc/os-release"],
        "architecture": ["uname", "-m"],
        "current_user": ["whoami"],
        "id": ["id"],
        "env_path": ["echo", "$PATH"],
    }
    results = {}
    for key, cmd in cmds.items():
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            results[key] = result.stdout.strip()
        except Exception as e:
            results[key] = str(e)
    return {"system_info": results, "timestamp": datetime.utcnow().isoformat()}


def check_sudo_permissions():
    """Check sudo permissions for current user."""
    try:
        result = subprocess.run(["sudo", "-l"], capture_output=True, text=True, timeout=10)
        output = result.stdout + result.stderr
        escalation_vectors = []
        dangerous_binaries = [
            "vim", "vi", "nano", "less", "more", "man", "find", "nmap", "python",
            "python3", "perl", "ruby", "lua", "awk", "bash", "sh", "env", "cp",
            "mv", "tar", "zip", "wget", "curl", "ftp", "nc", "ncat", "docker",
            "lxc", "mount", "strace", "ltrace", "gdb", "journalctl", "systemctl",
        ]
        for binary in dangerous_binaries:
            if binary in output and "NOPASSWD" in output:
                escalation_vectors.append({"binary": binary, "type": "SUDO_NOPASSWD", "severity": "CRITICAL"})
            elif binary in output:
                escalation_vectors.append({"binary": binary, "type": "SUDO_WITH_PASSWORD", "severity": "HIGH"})
        if "ALL) ALL" in output or "(ALL : ALL) ALL" in output:
            escalation_vectors.append({"type": "FULL_SUDO", "severity": "CRITICAL"})
        return {
            "sudo_output": output[:1000],
            "escalation_vectors": escalation_vectors,
            "has_sudo": result.returncode == 0,
        }
    except Exception as e:
        return {"error": str(e)}


def find_suid_binaries():
    """Find SUID/SGID binaries that may allow privilege escalation."""
    cmd = ["find", "/", "-perm", "-4000", "-type", "f", "-exec", "ls", "-la", "{}", ";"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        binaries = []
        gtfobins_suid = [
            "nmap", "vim", "find", "bash", "more", "less", "nano", "cp", "mv",
            "python", "python3", "perl", "ruby", "awk", "env", "tar", "zip",
            "docker", "strace", "ltrace", "gdb", "pkexec", "mount",
        ]
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 9:
                path = parts[-1]
                name = Path(path).name
                exploitable = name in gtfobins_suid
                binaries.append({
                    "path": path, "permissions": parts[0],
                    "owner": parts[2], "group": parts[3],
                    "exploitable": exploitable,
                })
        exploitable = [b for b in binaries if b["exploitable"]]
        return {
            "total_suid": len(binaries),
            "exploitable": len(exploitable),
            "suid_binaries": binaries[:30],
            "exploitable_binaries": exploitable,
        }
    except Exception as e:
        return {"error": str(e)}


def check_writable_files():
    """Find world-writable files and directories of interest."""
    interesting_paths = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/crontab",
                         "/etc/cron.d", "/etc/systemd/system", "/root"]
    findings = []
    for path in interesting_paths:
        p = Path(path)
        if p.exists():
            writable = os.access(str(p), os.W_OK)
            if writable:
                findings.append({"path": path, "writable": True, "severity": "CRITICAL"})
    cmd = ["find", "/", "-writable", "-type", "f", "-not", "-path", "'/proc/*'",
           "-not", "-path", "'/sys/*'", "-not", "-path", "'/dev/*'"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        writable_files = result.stdout.strip().splitlines()[:50]
        sensitive = [f for f in writable_files if any(p in f for p in ["/etc/", "/root/", "cron", ".service", "/bin/", "/sbin/"])]
        findings.extend([{"path": f, "writable": True, "severity": "HIGH"} for f in sensitive[:10]])
    except Exception:
        pass
    return {"writable_findings": findings, "total_findings": len(findings)}


def check_cron_jobs():
    """Enumerate cron jobs for privilege escalation opportunities."""
    findings = []
    cron_paths = ["/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs"]
    for path in cron_paths:
        p = Path(path)
        if p.is_file():
            content = p.read_text(encoding="utf-8", errors="replace")
            for line in content.splitlines():
                if line.strip() and not line.startswith("#"):
                    writable_script = re.search(r"(/\S+\.sh|/\S+\.py|/\S+\.pl)", line)
                    if writable_script:
                        script = writable_script.group(1)
                        if Path(script).exists() and os.access(script, os.W_OK):
                            findings.append({"cron_file": str(p), "script": script, "writable": True, "severity": "CRITICAL"})
        elif p.is_dir():
            for f in p.iterdir():
                if f.is_file():
                    findings.append({"cron_file": str(f), "type": "cron.d entry"})
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            findings.append({"type": "user_crontab", "content": result.stdout[:500]})
    except Exception:
        pass
    return {"cron_findings": findings}


def check_capabilities():
    """Find binaries with Linux capabilities set."""
    try:
        result = subprocess.run(["getcap", "-r", "/"], capture_output=True, text=True, timeout=15)
        caps = []
        for line in result.stdout.strip().splitlines():
            parts = line.split(" = ")
            if len(parts) == 2:
                binary = parts[0].strip()
                cap = parts[1].strip()
                dangerous = any(c in cap for c in ["cap_setuid", "cap_setgid", "cap_sys_admin", "cap_dac_override", "cap_net_raw"])
                caps.append({"binary": binary, "capabilities": cap, "dangerous": dangerous})
        return {"capabilities": caps, "dangerous_caps": [c for c in caps if c["dangerous"]]}
    except Exception as e:
        return {"error": str(e)}


def full_enumeration():
    """Run complete privilege escalation enumeration."""
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "system": enumerate_system_info(),
        "sudo": check_sudo_permissions(),
        "suid": find_suid_binaries(),
        "writable": check_writable_files(),
        "cron": check_cron_jobs(),
        "capabilities": check_capabilities(),
    }


def main():
    parser = argparse.ArgumentParser(description="Linux Privilege Escalation Enumeration Agent (Authorized Only)")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("sysinfo", help="System information")
    sub.add_parser("sudo", help="Check sudo permissions")
    sub.add_parser("suid", help="Find SUID/SGID binaries")
    sub.add_parser("writable", help="Find writable sensitive files")
    sub.add_parser("cron", help="Enumerate cron jobs")
    sub.add_parser("caps", help="Check Linux capabilities")
    sub.add_parser("full", help="Full enumeration")
    args = parser.parse_args()
    if args.command == "sysinfo":
        result = enumerate_system_info()
    elif args.command == "sudo":
        result = check_sudo_permissions()
    elif args.command == "suid":
        result = find_suid_binaries()
    elif args.command == "writable":
        result = check_writable_files()
    elif args.command == "cron":
        result = check_cron_jobs()
    elif args.command == "caps":
        result = check_capabilities()
    elif args.command == "full":
        result = full_enumeration()
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
