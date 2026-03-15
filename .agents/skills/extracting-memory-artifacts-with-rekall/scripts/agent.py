#!/usr/bin/env python3
"""Agent for extracting memory forensic artifacts using Rekall."""

import os
import json
import argparse
from datetime import datetime

from rekall import session
from rekall import plugins


def create_session(image_path, profile_path=None):
    """Create a Rekall session for a memory image."""
    kwargs = {
        "filename": image_path,
        "autodetect": ["rsds"],
    }
    if profile_path:
        kwargs["profile_path"] = [profile_path]
    else:
        kwargs["profile_path"] = [
            "https://github.com/google/rekall-profiles/raw/master"
        ]
    return session.Session(**kwargs)


def list_processes(s):
    """List all processes using pslist plugin."""
    processes = []
    for proc in s.plugins.pslist():
        processes.append({
            "pid": int(proc.pid),
            "ppid": int(proc.ppid),
            "name": str(proc.name),
            "create_time": str(getattr(proc, "create_time", "")),
        })
    return processes


def find_hidden_processes(s):
    """Detect hidden processes by comparing pslist vs psscan."""
    pslist_pids = {}
    for proc in s.plugins.pslist():
        pslist_pids[int(proc.pid)] = str(proc.name)
    psscan_pids = {}
    for proc in s.plugins.psscan():
        psscan_pids[int(proc.pid)] = str(proc.name)
    hidden = []
    for pid, name in psscan_pids.items():
        if pid not in pslist_pids and pid > 0:
            hidden.append({"pid": pid, "name": name, "detection": "psscan only"})
    return hidden


def detect_code_injection(s):
    """Detect injected code using malfind plugin (VAD analysis)."""
    injections = []
    for result in s.plugins.malfind():
        injections.append({
            "pid": int(getattr(result, "pid", 0)),
            "process": str(getattr(result, "name", "")),
            "address": hex(getattr(result, "address", 0)),
            "protection": str(getattr(result, "protection", "")),
            "tag": str(getattr(result, "tag", "")),
        })
    return injections


def list_network_connections(s):
    """List network connections using netscan plugin."""
    connections = []
    for conn in s.plugins.netscan():
        connections.append({
            "pid": int(getattr(conn, "pid", 0)),
            "local_addr": str(getattr(conn, "local_addr", "")),
            "remote_addr": str(getattr(conn, "remote_addr", "")),
            "state": str(getattr(conn, "state", "")),
            "protocol": str(getattr(conn, "protocol", "")),
        })
    return connections


def list_dlls(s, target_pid=None):
    """List loaded DLLs for processes using dlllist plugin."""
    dlls = []
    for entry in s.plugins.dlllist(pids=[target_pid] if target_pid else None):
        dlls.append({
            "pid": int(getattr(entry, "pid", 0)),
            "process": str(getattr(entry, "name", "")),
            "dll_path": str(getattr(entry, "path", "")),
            "base": hex(getattr(entry, "base", 0)),
            "size": int(getattr(entry, "size", 0)),
        })
    return dlls


def check_drivers(s):
    """List loaded kernel drivers using modules plugin."""
    drivers = []
    for mod in s.plugins.modules():
        drivers.append({
            "name": str(getattr(mod, "name", "")),
            "base": hex(getattr(mod, "base", 0)),
            "size": int(getattr(mod, "size", 0)),
        })
    return drivers


def analyze_vad(s, target_pid):
    """Analyze Virtual Address Descriptor tree for a process."""
    vad_entries = []
    for entry in s.plugins.vadinfo(pids=[target_pid]):
        vad_entries.append({
            "start": hex(getattr(entry, "start", 0)),
            "end": hex(getattr(entry, "end", 0)),
            "protection": str(getattr(entry, "protection", "")),
            "tag": str(getattr(entry, "tag", "")),
            "filename": str(getattr(entry, "filename", "")),
        })
    return vad_entries


def main():
    parser = argparse.ArgumentParser(description="Rekall Memory Forensics Agent")
    parser.add_argument("--image", required=True, help="Path to memory image")
    parser.add_argument("--profile-path", help="Path to Rekall profiles")
    parser.add_argument("--pid", type=int, help="Target PID for focused analysis")
    parser.add_argument("--output", default="rekall_report.json")
    parser.add_argument("--action", choices=[
        "pslist", "hidden", "malfind", "netscan", "dlls", "full_analysis"
    ], default="full_analysis")
    args = parser.parse_args()

    s = create_session(args.image, args.profile_path)
    report = {"image": args.image, "generated_at": datetime.utcnow().isoformat(),
              "findings": {}}

    if args.action in ("pslist", "full_analysis"):
        procs = list_processes(s)
        report["findings"]["processes"] = procs
        print(f"[+] Processes found: {len(procs)}")

    if args.action in ("hidden", "full_analysis"):
        hidden = find_hidden_processes(s)
        report["findings"]["hidden_processes"] = hidden
        print(f"[+] Hidden processes: {len(hidden)}")

    if args.action in ("malfind", "full_analysis"):
        injections = detect_code_injection(s)
        report["findings"]["code_injection"] = injections
        print(f"[+] Code injections detected: {len(injections)}")

    if args.action in ("netscan", "full_analysis"):
        conns = list_network_connections(s)
        report["findings"]["network_connections"] = conns
        print(f"[+] Network connections: {len(conns)}")

    if args.action in ("dlls", "full_analysis"):
        drivers = check_drivers(s)
        report["findings"]["kernel_drivers"] = drivers
        print(f"[+] Kernel drivers: {len(drivers)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
