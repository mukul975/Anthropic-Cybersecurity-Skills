#!/usr/bin/env python3
"""Agent for detecting T1548 Abuse Elevation Control Mechanism (UAC bypass, sudo abuse)."""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone


UAC_BYPASS_BINARIES = [
    "fodhelper.exe", "computerdefaults.exe", "eventvwr.exe",
    "sdclt.exe", "slui.exe", "cmstp.exe", "mmc.exe",
    "wsreset.exe", "changepk.exe", "dism.exe",
]

UAC_BYPASS_REGISTRY_KEYS = [
    r"HKCU\Software\Classes\ms-settings\Shell\Open\command",
    r"HKCU\Software\Classes\mscfile\Shell\Open\command",
    r"HKCU\Software\Classes\exefile\Shell\Open\command",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths",
]

SUDO_ABUSE_PATTERNS = [
    r"sudo\s+-u\s+\#-1",
    r"sudo\s+.*NOPASSWD",
    r"sudo\s+.*env_reset.*env_keep",
    r"sudo\s+\S+\s+/bin/bash",
    r"sudo\s+find\s+.*-exec",
    r"sudo\s+vim\s+-c\s+.*!",
    r"sudo\s+python\s+-c",
]


def check_uac_bypass_registry():
    """Check for UAC bypass registry modifications."""
    findings = []
    if sys.platform != "win32":
        return findings
    for key in UAC_BYPASS_REGISTRY_KEYS:
        try:
            result = subprocess.check_output(
                ["reg", "query", key], text=True, errors="replace", timeout=5
            )
            if result.strip() and "ERROR" not in result:
                findings.append({
                    "type": "uac_registry",
                    "key": key,
                    "value": result.strip()[:200],
                    "severity": "HIGH",
                })
        except subprocess.SubprocessError:
            pass
    return findings


def check_uac_bypass_processes():
    """Check Sysmon logs for auto-elevate binary abuse."""
    findings = []
    if sys.platform != "win32":
        return findings
    ps_cmd = (
        "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';"
        "Id=1} -MaxEvents 500 "
        "| Where-Object {$_.Properties[4].Value -match '"
        + "|".join(UAC_BYPASS_BINARIES)
        + "'} | Select-Object TimeCreated,"
        "@{N='Image';E={$_.Properties[4].Value}},"
        "@{N='CommandLine';E={$_.Properties[10].Value}},"
        "@{N='ParentImage';E={$_.Properties[20].Value}} "
        "| ConvertTo-Json"
    )
    try:
        result = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            text=True, errors="replace", timeout=30
        )
        data = json.loads(result) if result.strip() else []
        if not isinstance(data, list):
            data = [data]
        for evt in data:
            parent = (evt.get("ParentImage", "") or "").lower()
            if "explorer.exe" not in parent and "svchost.exe" not in parent:
                findings.append({
                    "type": "uac_auto_elevate",
                    "time": evt.get("TimeCreated", ""),
                    "image": evt.get("Image", ""),
                    "parent": evt.get("ParentImage", ""),
                    "commandline": evt.get("CommandLine", "")[:200],
                })
    except (subprocess.SubprocessError, json.JSONDecodeError):
        pass
    return findings


def check_linux_sudo_abuse():
    """Check auth logs for sudo abuse patterns."""
    findings = []
    if sys.platform == "win32":
        return findings
    log_paths = ["/var/log/auth.log", "/var/log/secure"]
    for log_path in log_paths:
        if not os.path.isfile(log_path):
            continue
        try:
            with open(log_path, "r", errors="replace") as f:
                for line in f:
                    if "sudo" not in line.lower():
                        continue
                    for pat in SUDO_ABUSE_PATTERNS:
                        if re.search(pat, line, re.IGNORECASE):
                            findings.append({
                                "type": "sudo_abuse",
                                "log": log_path,
                                "line": line.strip()[:200],
                                "pattern": pat,
                            })
        except PermissionError:
            pass

    try:
        result = subprocess.check_output(
            ["sudo", "-l", "-n"], text=True, errors="replace", timeout=5
        )
        if "NOPASSWD" in result:
            for line in result.splitlines():
                if "NOPASSWD" in line:
                    findings.append({
                        "type": "nopasswd_sudo",
                        "rule": line.strip(),
                        "severity": "MEDIUM",
                    })
    except subprocess.SubprocessError:
        pass
    return findings


def check_setuid_binaries():
    """Find SUID/SGID binaries that could be abused for elevation."""
    findings = []
    if sys.platform == "win32":
        return findings
    try:
        result = subprocess.check_output(
            ["find", "/", "-perm", "-4000", "-type", "f"],
            text=True, errors="replace", timeout=30, stderr=subprocess.DEVNULL
        )
        known_suid = {"/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
                      "/usr/bin/mount", "/usr/bin/umount", "/usr/bin/ping"}
        for line in result.strip().splitlines():
            path = line.strip()
            if path and path not in known_suid:
                findings.append({"type": "unusual_suid", "path": path})
    except subprocess.SubprocessError:
        pass
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Detect T1548 Abuse Elevation Control Mechanism"
    )
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    print("[*] T1548 Elevation Abuse Detection Agent")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "findings": {}}

    if sys.platform == "win32":
        reg = check_uac_bypass_registry()
        procs = check_uac_bypass_processes()
        report["findings"]["uac_registry"] = reg
        report["findings"]["uac_processes"] = procs
        print(f"[*] UAC registry: {len(reg)}, UAC process: {len(procs)}")
    else:
        sudo = check_linux_sudo_abuse()
        suid = check_setuid_binaries()
        report["findings"]["sudo_abuse"] = sudo
        report["findings"]["suid_binaries"] = suid
        print(f"[*] Sudo abuse: {len(sudo)}, SUID binaries: {len(suid)}")

    total = sum(len(v) if isinstance(v, list) else 0 for v in report["findings"].values())
    report["risk_level"] = "CRITICAL" if total >= 5 else "HIGH" if total >= 2 else "MEDIUM" if total > 0 else "LOW"

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
