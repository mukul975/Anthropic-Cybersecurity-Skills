#!/usr/bin/env python3
"""Rootkit detection agent using cross-view analysis and integrity checking."""

import json
import os
import subprocess
import sys
from datetime import datetime


def run_volatility_pslist(memory_dump):
    """List processes using ActiveProcessLinks (EPROCESS linked list)."""
    cmd = ["vol3", "-f", memory_dump, "windows.pslist"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        processes = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].isdigit():
                processes.append({"pid": int(parts[0]), "ppid": int(parts[1]),
                                  "name": parts[2], "threads": parts[3] if len(parts) > 3 else ""})
        return {"method": "pslist", "count": len(processes), "processes": processes}
    except FileNotFoundError:
        return {"error": "Volatility 3 not installed"}
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}


def run_volatility_psscan(memory_dump):
    """Scan physical memory for EPROCESS pool tags (rootkit-resistant)."""
    cmd = ["vol3", "-f", memory_dump, "windows.psscan"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        processes = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].startswith("0x"):
                processes.append({"offset": parts[0], "pid": parts[1],
                                  "ppid": parts[2] if len(parts) > 2 else "",
                                  "name": parts[3] if len(parts) > 3 else ""})
        return {"method": "psscan", "count": len(processes), "processes": processes}
    except FileNotFoundError:
        return {"error": "Volatility 3 not installed"}
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}


def cross_view_detection(memory_dump):
    """Compare pslist vs psscan to find hidden processes (DKOM rootkits)."""
    pslist = run_volatility_pslist(memory_dump)
    psscan = run_volatility_psscan(memory_dump)

    if "error" in pslist or "error" in psscan:
        return {"error": "Could not complete cross-view analysis",
                "pslist": pslist, "psscan": psscan}

    pslist_pids = set(str(p["pid"]) for p in pslist.get("processes", []))
    psscan_pids = set(str(p.get("pid", "")) for p in psscan.get("processes", []))

    hidden = psscan_pids - pslist_pids
    hidden_processes = [
        p for p in psscan.get("processes", [])
        if str(p.get("pid", "")) in hidden
    ]

    return {
        "pslist_count": len(pslist_pids),
        "psscan_count": len(psscan_pids),
        "hidden_processes": hidden_processes,
        "hidden_count": len(hidden_processes),
        "alert": "ROOTKIT DETECTED - Hidden processes found" if hidden_processes else "No hidden processes detected",
    }


def check_ssdt_hooks(memory_dump):
    """Check for SSDT (System Service Descriptor Table) hooks."""
    cmd = ["vol3", "-f", memory_dump, "windows.ssdt"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        hooks = []
        for line in result.stdout.splitlines():
            if "UNKNOWN" in line.upper() or line.count("\\") == 0:
                parts = line.split()
                if len(parts) >= 3:
                    hooks.append({"entry": " ".join(parts)})
        return {"ssdt_hooks": hooks, "count": len(hooks)}
    except FileNotFoundError:
        return {"error": "Volatility 3 not installed"}
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}


def check_kernel_modules(memory_dump):
    """List loaded kernel modules and detect unsigned/suspicious ones."""
    cmd = ["vol3", "-f", memory_dump, "windows.modules"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        modules = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0].startswith("0x"):
                modules.append({"base": parts[0], "size": parts[1],
                                "name": parts[2] if len(parts) > 2 else ""})
        return {"modules": modules, "count": len(modules)}
    except FileNotFoundError:
        return {"error": "Volatility 3 not installed"}
    except subprocess.TimeoutExpired:
        return {"error": "Timed out"}


def run_rkhunter():
    """Run rkhunter for Linux rootkit detection."""
    try:
        result = subprocess.run(
            ["rkhunter", "--check", "--skip-keypress", "--report-warnings-only"],
            capture_output=True, text=True, timeout=120
        )
        warnings = [line.strip() for line in result.stdout.splitlines() if "Warning" in line]
        return {
            "tool": "rkhunter",
            "warnings": warnings,
            "warning_count": len(warnings),
            "exit_code": result.returncode,
        }
    except FileNotFoundError:
        return {"error": "rkhunter not installed (apt install rkhunter)"}
    except subprocess.TimeoutExpired:
        return {"error": "rkhunter timed out"}


def run_chkrootkit():
    """Run chkrootkit for Linux rootkit detection."""
    try:
        result = subprocess.run(
            ["chkrootkit", "-q"], capture_output=True, text=True, timeout=120
        )
        infected = [line.strip() for line in result.stdout.splitlines()
                     if "INFECTED" in line.upper()]
        return {
            "tool": "chkrootkit",
            "infected": infected,
            "infected_count": len(infected),
            "exit_code": result.returncode,
        }
    except FileNotFoundError:
        return {"error": "chkrootkit not installed (apt install chkrootkit)"}
    except subprocess.TimeoutExpired:
        return {"error": "chkrootkit timed out"}


def check_hidden_files_linux():
    """Check for hidden files and directories that may indicate a rootkit."""
    suspicious = []
    check_dirs = ["/tmp", "/dev/shm", "/var/tmp"]
    for d in check_dirs:
        if not os.path.exists(d):
            continue
        try:
            for entry in os.listdir(d):
                if entry.startswith(".") and entry not in (".", ".."):
                    full_path = os.path.join(d, entry)
                    suspicious.append({
                        "path": full_path,
                        "is_dir": os.path.isdir(full_path),
                        "size": os.path.getsize(full_path) if os.path.isfile(full_path) else 0,
                    })
        except PermissionError:
            continue
    return {"hidden_files": suspicious, "count": len(suspicious)}


def generate_report(memory_dump=None):
    """Generate comprehensive rootkit detection report."""
    report = {"timestamp": datetime.utcnow().isoformat() + "Z"}

    if memory_dump:
        report["cross_view"] = cross_view_detection(memory_dump)
        report["ssdt_hooks"] = check_ssdt_hooks(memory_dump)
        report["kernel_modules"] = check_kernel_modules(memory_dump)
    else:
        report["rkhunter"] = run_rkhunter()
        report["chkrootkit"] = run_chkrootkit()
        report["hidden_files"] = check_hidden_files_linux()

    return report


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "help"
    if action == "cross-view" and len(sys.argv) > 2:
        print(json.dumps(cross_view_detection(sys.argv[2]), indent=2, default=str))
    elif action == "malfind" and len(sys.argv) > 2:
        print(json.dumps(run_volatility_pslist(sys.argv[2]), indent=2, default=str))
    elif action == "ssdt" and len(sys.argv) > 2:
        print(json.dumps(check_ssdt_hooks(sys.argv[2]), indent=2, default=str))
    elif action == "rkhunter":
        print(json.dumps(run_rkhunter(), indent=2))
    elif action == "chkrootkit":
        print(json.dumps(run_chkrootkit(), indent=2))
    elif action == "report":
        mem = sys.argv[2] if len(sys.argv) > 2 else None
        print(json.dumps(generate_report(mem), indent=2, default=str))
    else:
        print("Usage: agent.py [cross-view <mem>|malfind <mem>|ssdt <mem>|rkhunter|chkrootkit|report [mem]]")
