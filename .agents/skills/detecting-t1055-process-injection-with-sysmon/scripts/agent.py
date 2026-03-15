#!/usr/bin/env python3
"""Agent for detecting T1055 process injection via Sysmon event analysis."""

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone


INJECTION_ACCESS_MASKS = {
    "0x1F0FFF": "PROCESS_ALL_ACCESS",
    "0x001F0FFF": "PROCESS_ALL_ACCESS (full)",
    "0x0800": "PROCESS_SUSPEND_RESUME",
    "0x0020": "PROCESS_VM_WRITE",
    "0x0008": "PROCESS_VM_OPERATION",
    "0x0010": "PROCESS_VM_READ",
}

INJECTION_DLLS = [
    "ntdll.dll", "kernel32.dll", "kernelbase.dll",
]

SUSPICIOUS_API_CALLS = [
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtMapViewOfSection", "QueueUserAPC", "SetWindowsHookEx",
    "RtlCreateUserThread", "NtQueueApcThread",
]


def query_sysmon_events(event_id, max_events=500):
    """Query Sysmon operational log for specific event ID."""
    if sys.platform != "win32":
        return []
    ps_cmd = (
        f"Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Sysmon/Operational';"
        f"Id={event_id}}} -MaxEvents {max_events} "
        "| ForEach-Object { @{"
        "TimeCreated=$_.TimeCreated.ToString('o');"
        "Properties=@($_.Properties | ForEach-Object {$_.Value})"
        "}} | ConvertTo-Json -Depth 3"
    )
    try:
        result = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            text=True, errors="replace", timeout=30
        )
        data = json.loads(result) if result.strip() else []
        return data if isinstance(data, list) else [data]
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return []


def analyze_process_access():
    """Analyze Sysmon Event ID 10 for injection-related process access."""
    findings = []
    events = query_sysmon_events(10)
    for evt in events:
        props = evt.get("Properties", [])
        if len(props) < 11:
            continue
        source_img = str(props[4]) if len(props) > 4 else ""
        target_img = str(props[8]) if len(props) > 8 else ""
        access = str(props[10]) if len(props) > 10 else ""
        safe_sources = ["csrss.exe", "svchost.exe", "lsass.exe", "services.exe", "smss.exe"]
        if any(s in source_img.lower() for s in safe_sources):
            continue
        if access in INJECTION_ACCESS_MASKS:
            findings.append({
                "event": "ProcessAccess",
                "time": evt.get("TimeCreated", ""),
                "source": source_img,
                "target": target_img,
                "access_mask": access,
                "mask_meaning": INJECTION_ACCESS_MASKS.get(access, "Unknown"),
            })
    return findings


def analyze_create_remote_thread():
    """Analyze Sysmon Event ID 8 for CreateRemoteThread injection."""
    findings = []
    events = query_sysmon_events(8)
    for evt in events:
        props = evt.get("Properties", [])
        if len(props) < 8:
            continue
        source_img = str(props[4]) if len(props) > 4 else ""
        target_img = str(props[7]) if len(props) > 7 else ""
        findings.append({
            "event": "CreateRemoteThread",
            "time": evt.get("TimeCreated", ""),
            "source": source_img,
            "target": target_img,
            "severity": "HIGH",
        })
    return findings


def analyze_image_loads():
    """Analyze Sysmon Event ID 7 for suspicious DLL loads in unusual processes."""
    findings = []
    events = query_sysmon_events(7, max_events=200)
    for evt in events:
        props = evt.get("Properties", [])
        if len(props) < 6:
            continue
        image = str(props[3]) if len(props) > 3 else ""
        loaded = str(props[5]) if len(props) > 5 else ""
        if loaded.lower().endswith("amsi.dll") and "powershell" not in image.lower():
            findings.append({
                "event": "SuspiciousImageLoad",
                "time": evt.get("TimeCreated", ""),
                "process": image,
                "loaded_image": loaded,
                "note": "AMSI DLL loaded by non-PowerShell process",
            })
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Detect T1055 process injection via Sysmon telemetry"
    )
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--max-events", type=int, default=500)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    print("[*] T1055 Process Injection Detection Agent (Sysmon)")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "findings": {}}

    access = analyze_process_access()
    report["findings"]["process_access"] = access
    print(f"[*] Suspicious process access: {len(access)}")

    threads = analyze_create_remote_thread()
    report["findings"]["remote_threads"] = threads
    print(f"[*] Remote thread creation: {len(threads)}")

    loads = analyze_image_loads()
    report["findings"]["suspicious_loads"] = loads
    print(f"[*] Suspicious image loads: {len(loads)}")

    total = len(access) + len(threads) + len(loads)
    report["risk_level"] = "CRITICAL" if total >= 5 else "HIGH" if total >= 2 else "MEDIUM" if total > 0 else "LOW"

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
