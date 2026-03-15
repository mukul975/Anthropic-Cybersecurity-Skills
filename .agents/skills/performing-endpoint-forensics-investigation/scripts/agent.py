#!/usr/bin/env python3
"""Agent for performing endpoint forensics investigation on Windows systems."""

import json
import argparse
import subprocess
import os
import hashlib
from datetime import datetime
from pathlib import Path


def collect_system_info():
    """Collect basic system information for forensic context."""
    info = {}
    commands = {
        "hostname": ["hostname"],
        "os_version": ["wmic", "os", "get", "Caption,Version,BuildNumber", "/format:list"],
        "network_config": ["ipconfig", "/all"],
        "logged_users": ["query", "user"],
        "uptime": ["wmic", "os", "get", "LastBootUpTime", "/format:list"],
    }
    for key, cmd in commands.items():
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            info[key] = result.stdout.strip()[:1000]
        except Exception as e:
            info[key] = f"Error: {e}"
    return {"timestamp": datetime.utcnow().isoformat(), "system_info": info}


def collect_running_processes():
    """Collect running processes with parent PIDs and command lines."""
    try:
        result = subprocess.run(
            ["wmic", "process", "get", "Name,ProcessId,ParentProcessId,CommandLine,ExecutablePath", "/format:csv"],
            capture_output=True, text=True, timeout=30
        )
    except Exception as e:
        return {"error": str(e)}
    import csv
    from io import StringIO
    processes = []
    reader = csv.DictReader(StringIO(result.stdout))
    for row in reader:
        if row.get("Name"):
            processes.append({
                "name": row.get("Name", ""),
                "pid": row.get("ProcessId", ""),
                "ppid": row.get("ParentProcessId", ""),
                "path": row.get("ExecutablePath", ""),
                "cmdline": row.get("CommandLine", "")[:500],
            })
    return {"total": len(processes), "processes": processes}


def collect_network_connections():
    """Collect active network connections."""
    try:
        result = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        return {"error": str(e)}
    connections = []
    for line in result.stdout.split("\n")[4:]:
        parts = line.split()
        if len(parts) >= 5:
            connections.append({
                "protocol": parts[0],
                "local_addr": parts[1],
                "remote_addr": parts[2],
                "state": parts[3] if len(parts) > 4 else "",
                "pid": parts[-1],
            })
    established = [c for c in connections if c.get("state") == "ESTABLISHED"]
    listening = [c for c in connections if c.get("state") == "LISTENING"]
    return {
        "total": len(connections),
        "established": len(established),
        "listening": len(listening),
        "connections": connections,
    }


def collect_autoruns():
    """Collect common persistence locations."""
    autoruns = {}
    reg_keys = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    ]
    for key in reg_keys:
        try:
            result = subprocess.run(["reg", "query", key], capture_output=True, text=True, timeout=10)
            autoruns[key] = result.stdout.strip()[:1000]
        except Exception:
            continue
    try:
        result = subprocess.run(["schtasks", "/query", "/fo", "CSV"], capture_output=True, text=True, timeout=30)
        autoruns["scheduled_tasks_count"] = result.stdout.count("\n") - 1
    except Exception:
        pass
    return autoruns


def hash_file(filepath):
    """Calculate MD5, SHA1, SHA256 hashes of a file for evidence integrity."""
    hashes = {}
    algos = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                for algo in algos.values():
                    algo.update(chunk)
        for name, algo in algos.items():
            hashes[name] = algo.hexdigest()
        hashes["file"] = str(filepath)
        hashes["size"] = os.path.getsize(filepath)
    except Exception as e:
        hashes["error"] = str(e)
    return hashes


def full_triage():
    """Run full endpoint forensic triage collection."""
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "system_info": collect_system_info(),
        "processes": collect_running_processes(),
        "network": collect_network_connections(),
        "autoruns": collect_autoruns(),
    }


def main():
    parser = argparse.ArgumentParser(description="Endpoint Forensics Investigation Agent")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("triage", help="Full forensic triage collection")
    sub.add_parser("processes", help="Collect running processes")
    sub.add_parser("network", help="Collect network connections")
    sub.add_parser("autoruns", help="Collect autorun/persistence entries")
    h = sub.add_parser("hash", help="Hash a file for evidence")
    h.add_argument("--file", required=True)
    args = parser.parse_args()
    if args.command == "triage":
        result = full_triage()
    elif args.command == "processes":
        result = collect_running_processes()
    elif args.command == "network":
        result = collect_network_connections()
    elif args.command == "autoruns":
        result = collect_autoruns()
    elif args.command == "hash":
        result = hash_file(args.file)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
