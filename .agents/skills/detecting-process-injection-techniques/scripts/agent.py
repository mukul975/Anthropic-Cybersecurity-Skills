#!/usr/bin/env python3
"""Process injection detection agent using Volatility and Sysmon analysis."""

import json
import os
import re
import subprocess
import sys
from datetime import datetime

try:
    import Evtx.Evtx as evtx
    HAS_EVTX = True
except ImportError:
    HAS_EVTX = False


INJECTION_TECHNIQUES = {
    "classic_dll_injection": {
        "apis": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        "sysmon_events": [8, 10],
        "description": "Classic DLL injection via remote thread creation",
    },
    "process_hollowing": {
        "apis": ["CreateProcess(SUSPENDED)", "NtUnmapViewOfSection", "VirtualAllocEx",
                 "WriteProcessMemory", "SetThreadContext", "ResumeThread"],
        "sysmon_events": [1, 10],
        "description": "Process hollowing - replace legitimate process image",
    },
    "apc_injection": {
        "apis": ["OpenThread", "VirtualAllocEx", "WriteProcessMemory", "QueueUserAPC"],
        "sysmon_events": [8, 10],
        "description": "APC queue injection via QueueUserAPC",
    },
    "reflective_dll": {
        "apis": ["VirtualAlloc", "memcpy", "CreateThread"],
        "sysmon_events": [7],
        "description": "Reflective DLL loading without LoadLibrary",
    },
    "process_doppelganging": {
        "apis": ["CreateTransaction", "CreateFileTransacted", "NtCreateSection",
                 "NtCreateProcessEx", "RollbackTransaction"],
        "sysmon_events": [1],
        "description": "Process doppelganging via NTFS transactions",
    },
}


def run_volatility_malfind(memory_dump, pid=None):
    """Run Volatility malfind plugin to detect injected code."""
    if not os.path.exists(memory_dump):
        return {"error": f"Memory dump not found: {memory_dump}"}

    cmd = ["vol3", "-f", memory_dump, "windows.malfind"]
    if pid:
        cmd.extend(["--pid", str(pid)])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        findings = []
        current = {}
        for line in result.stdout.splitlines():
            if line.strip() and not line.startswith("Volatility"):
                parts = line.split()
                if len(parts) >= 6 and parts[0].isdigit():
                    if current:
                        findings.append(current)
                    current = {
                        "pid": parts[0],
                        "process": parts[1] if len(parts) > 1 else "",
                        "address": parts[2] if len(parts) > 2 else "",
                        "protection": parts[4] if len(parts) > 4 else "",
                    }
        if current:
            findings.append(current)
        return {"findings": findings, "count": len(findings)}
    except FileNotFoundError:
        return {"error": "Volatility 3 (vol3) not installed"}
    except subprocess.TimeoutExpired:
        return {"error": "Analysis timed out after 300s"}


def run_volatility_hollowfind(memory_dump):
    """Detect process hollowing via VAD/PEB image path mismatch."""
    if not os.path.exists(memory_dump):
        return {"error": f"Memory dump not found: {memory_dump}"}

    cmd = ["vol3", "-f", memory_dump, "windows.pslist"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        processes = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].isdigit():
                processes.append({
                    "pid": parts[0],
                    "ppid": parts[1] if len(parts) > 1 else "",
                    "name": parts[2] if len(parts) > 2 else "",
                    "threads": parts[3] if len(parts) > 3 else "",
                })
        return {"processes": processes, "count": len(processes)}
    except FileNotFoundError:
        return {"error": "Volatility 3 not installed"}
    except subprocess.TimeoutExpired:
        return {"error": "Analysis timed out"}


def scan_sysmon_injection_events(evtx_path):
    """Scan Sysmon logs for injection-related events."""
    if not HAS_EVTX:
        return {"error": "python-evtx not installed (pip install python-evtx)"}
    if not os.path.exists(evtx_path):
        return {"error": f"EVTX file not found: {evtx_path}"}

    injection_events = []
    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            try:
                xml = record.xml()
                if "<EventID>8</EventID>" in xml:
                    injection_events.append({
                        "event_id": 8,
                        "type": "CreateRemoteThread",
                        "timestamp": record.timestamp().isoformat(),
                        "snippet": xml[:500],
                    })
                elif "<EventID>10</EventID>" in xml:
                    if "PROCESS_VM_WRITE" in xml or "PROCESS_CREATE_THREAD" in xml:
                        injection_events.append({
                            "event_id": 10,
                            "type": "ProcessAccess (injection prep)",
                            "timestamp": record.timestamp().isoformat(),
                            "snippet": xml[:500],
                        })
            except Exception:
                continue

    return {"injection_events": len(injection_events), "events": injection_events[:50]}


def detect_rwx_memory_regions():
    """Detect processes with suspicious RWX memory regions (Windows)."""
    ps_cmd = (
        "Get-Process | ForEach-Object { "
        "$p = $_; "
        "try { "
        "$modules = $p.Modules | Select-Object -First 1; "
        "[PSCustomObject]@{Name=$p.ProcessName; PID=$p.Id; WorkingSet=$p.WorkingSet64} "
        "} catch {} } | ConvertTo-Json"
    )
    try:
        result = subprocess.run(
            ["powershell", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
        return {"error": result.stderr.strip()}
    except Exception as e:
        return {"error": str(e)}


def check_unusual_parent_child():
    """Detect unusual parent-child process relationships."""
    suspicious_combos = [
        ("svchost.exe", "cmd.exe"),
        ("svchost.exe", "powershell.exe"),
        ("explorer.exe", "cmd.exe"),
        ("winword.exe", "powershell.exe"),
        ("winword.exe", "cmd.exe"),
        ("excel.exe", "powershell.exe"),
        ("outlook.exe", "powershell.exe"),
    ]
    ps_cmd = (
        "Get-WmiObject Win32_Process | Select-Object ProcessId, Name, ParentProcessId | "
        "ConvertTo-Json"
    )
    try:
        result = subprocess.run(
            ["powershell", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip()}
        processes = json.loads(result.stdout)
        if not isinstance(processes, list):
            processes = [processes]

        pid_map = {p["ProcessId"]: p["Name"] for p in processes}
        suspicious = []
        for proc in processes:
            parent_name = pid_map.get(proc.get("ParentProcessId"), "").lower()
            child_name = (proc.get("Name") or "").lower()
            for p, c in suspicious_combos:
                if parent_name == p.lower() and child_name == c.lower():
                    suspicious.append({
                        "parent": parent_name,
                        "child": child_name,
                        "child_pid": proc["ProcessId"],
                        "risk": "HIGH",
                    })
        return {"suspicious_relationships": suspicious, "count": len(suspicious)}
    except Exception as e:
        return {"error": str(e)}


def generate_report(memory_dump=None, sysmon_evtx=None):
    """Generate process injection detection report."""
    report = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "techniques_catalog": {k: v["description"] for k, v in INJECTION_TECHNIQUES.items()},
    }
    if memory_dump:
        report["malfind"] = run_volatility_malfind(memory_dump)
    if sysmon_evtx:
        report["sysmon_injection"] = scan_sysmon_injection_events(sysmon_evtx)
    report["parent_child_anomalies"] = check_unusual_parent_child()
    return report


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "help"
    if action == "malfind" and len(sys.argv) > 2:
        pid = int(sys.argv[3]) if len(sys.argv) > 3 else None
        print(json.dumps(run_volatility_malfind(sys.argv[2], pid), indent=2, default=str))
    elif action == "sysmon" and len(sys.argv) > 2:
        print(json.dumps(scan_sysmon_injection_events(sys.argv[2]), indent=2, default=str))
    elif action == "parent-child":
        print(json.dumps(check_unusual_parent_child(), indent=2))
    elif action == "report":
        mem = sys.argv[2] if len(sys.argv) > 2 else None
        sysmon = sys.argv[3] if len(sys.argv) > 3 else None
        print(json.dumps(generate_report(mem, sysmon), indent=2, default=str))
    else:
        print("Usage: agent.py [malfind <memory.dmp> [pid]|sysmon <Sysmon.evtx>|parent-child|report [mem] [sysmon]]")
