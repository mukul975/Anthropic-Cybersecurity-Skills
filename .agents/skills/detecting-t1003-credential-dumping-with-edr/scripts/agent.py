#!/usr/bin/env python3
"""Agent for detecting T1003 credential dumping via EDR telemetry analysis."""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone


LSASS_ACCESS_MASKS = {
    0x1010: "PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ",
    0x1FFFFF: "PROCESS_ALL_ACCESS",
    0x1410: "PROCESS_QUERY_INFORMATION | PROCESS_VM_READ",
    0x0040: "PROCESS_DUP_HANDLE",
}

CREDENTIAL_DUMP_TOOLS = [
    "mimikatz", "procdump", "sqldumper", "comsvcs.dll",
    "nanodump", "pypykatz", "lazagne", "secretsdump",
    "gsecdump", "wce.exe", "fgdump", "pwdump",
    "ntdsutil", "reg save hklm\\sam", "reg save hklm\\system",
]

SYSMON_EVENTS = {
    1: "Process Creation",
    10: "Process Access (LSASS read)",
    11: "File Create (credential dump file)",
    7: "Image Loaded (suspicious DLL)",
}


def check_lsass_access_sysmon():
    """Query Sysmon Event ID 10 for LSASS process access."""
    findings = []
    if sys.platform != "win32":
        return findings
    ps_cmd = (
        "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';"
        "Id=10} -MaxEvents 500 "
        "| Where-Object {$_.Properties[8].Value -match 'lsass'} "
        "| Select-Object TimeCreated,"
        "@{N='SourceProcess';E={$_.Properties[4].Value}},"
        "@{N='SourcePID';E={$_.Properties[3].Value}},"
        "@{N='TargetProcess';E={$_.Properties[8].Value}},"
        "@{N='GrantedAccess';E={$_.Properties[10].Value}} "
        "| ConvertTo-Json -Depth 3"
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
            source = evt.get("SourceProcess", "")
            access = evt.get("GrantedAccess", "")
            if not any(safe in source.lower() for safe in ["svchost", "csrss", "lsass", "wmiprvse"]):
                findings.append({
                    "time": evt.get("TimeCreated", ""),
                    "source": source,
                    "target": evt.get("TargetProcess", ""),
                    "access_mask": access,
                    "suspicious": True,
                })
    except (subprocess.SubprocessError, json.JSONDecodeError):
        pass
    return findings


def check_credential_dump_processes():
    """Check for known credential dumping tool processes."""
    findings = []
    if sys.platform != "win32":
        return findings
    ps_cmd = (
        "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';"
        "Id=1} -MaxEvents 1000 "
        "| Select-Object TimeCreated,"
        "@{N='Image';E={$_.Properties[4].Value}},"
        "@{N='CommandLine';E={$_.Properties[10].Value}},"
        "@{N='ParentImage';E={$_.Properties[20].Value}} "
        "| ConvertTo-Json -Depth 3"
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
            cmdline = (evt.get("CommandLine", "") or "").lower()
            image = (evt.get("Image", "") or "").lower()
            for tool in CREDENTIAL_DUMP_TOOLS:
                if tool.lower() in cmdline or tool.lower() in image:
                    findings.append({
                        "time": evt.get("TimeCreated", ""),
                        "image": evt.get("Image", ""),
                        "commandline": evt.get("CommandLine", "")[:200],
                        "tool_match": tool,
                    })
                    break
    except (subprocess.SubprocessError, json.JSONDecodeError):
        pass
    return findings


def check_sam_ntds_access():
    """Check for SAM/NTDS.dit/SYSTEM registry hive access."""
    findings = []
    patterns = [
        r"reg\s+save\s+hklm\\sam",
        r"reg\s+save\s+hklm\\system",
        r"reg\s+save\s+hklm\\security",
        r"ntdsutil.*\"ac\s+i\s+ntds\"",
        r"vssadmin.*create\s+shadow",
        r"copy.*ntds\.dit",
    ]
    if sys.platform != "win32":
        return findings
    ps_cmd = (
        "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 500 "
        "| Select-Object TimeCreated,"
        "@{N='CommandLine';E={$_.Properties[8].Value}} "
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
            cmdline = (evt.get("CommandLine", "") or "").lower()
            for pat in patterns:
                if re.search(pat, cmdline):
                    findings.append({
                        "time": evt.get("TimeCreated", ""),
                        "commandline": cmdline[:200],
                        "pattern": pat,
                    })
    except (subprocess.SubprocessError, json.JSONDecodeError):
        pass
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Detect T1003 credential dumping via EDR telemetry"
    )
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    print("[*] T1003 Credential Dumping Detection Agent")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "findings": {}}

    lsass = check_lsass_access_sysmon()
    report["findings"]["lsass_access"] = lsass
    print(f"[*] Suspicious LSASS access events: {len(lsass)}")

    tools = check_credential_dump_processes()
    report["findings"]["dump_tools"] = tools
    print(f"[*] Credential dump tool detections: {len(tools)}")

    sam = check_sam_ntds_access()
    report["findings"]["sam_ntds_access"] = sam
    print(f"[*] SAM/NTDS access events: {len(sam)}")

    total = len(lsass) + len(tools) + len(sam)
    report["risk_level"] = "CRITICAL" if total >= 5 else "HIGH" if total >= 2 else "MEDIUM" if total > 0 else "LOW"

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
