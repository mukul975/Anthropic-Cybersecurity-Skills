#!/usr/bin/env python3
"""Agent for Linux memory forensics using LiME acquisition and Volatility 3."""

import os
import json
import subprocess
import argparse
from datetime import datetime
from pathlib import Path


def acquire_memory_lime(output_path, lime_format="lime"):
    """Acquire memory using LiME kernel module."""
    kernel_version = subprocess.run(
        ["uname", "-r"], capture_output=True, text=True
    ).stdout.strip()
    lime_module = f"lime-{kernel_version}.ko"
    if not Path(lime_module).exists():
        lime_module = "lime.ko"
    cmd = ["insmod", lime_module, f"path={output_path}", f"format={lime_format}"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "status": "success" if result.returncode == 0 else "failed",
        "output_path": output_path,
        "format": lime_format,
        "kernel": kernel_version,
        "stderr": result.stderr,
    }


def run_vol3_plugin(image_path, plugin_name, extra_args=None):
    """Run a Volatility 3 plugin and capture output."""
    cmd = ["vol3", "-f", image_path, plugin_name]
    if extra_args:
        cmd.extend(extra_args)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
        )
        lines = result.stdout.strip().splitlines()
        return {"plugin": plugin_name, "output": lines, "error": result.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"plugin": plugin_name, "output": [], "error": "Timeout"}


def parse_pslist_output(lines):
    """Parse Volatility linux.pslist output into structured data."""
    processes = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 4 and parts[0].isdigit():
            processes.append({
                "pid": int(parts[0]),
                "ppid": int(parts[1]) if parts[1].isdigit() else 0,
                "name": parts[-1],
            })
    return processes


def list_processes(image_path):
    """List all processes from memory image."""
    result = run_vol3_plugin(image_path, "linux.pslist")
    return parse_pslist_output(result.get("output", []))


def extract_bash_history(image_path):
    """Extract bash command history from memory."""
    result = run_vol3_plugin(image_path, "linux.bash")
    commands = []
    for line in result.get("output", []):
        parts = line.split(None, 3)
        if len(parts) >= 4 and parts[0].isdigit():
            commands.append({
                "pid": int(parts[0]),
                "name": parts[1],
                "timestamp": parts[2] if len(parts) > 2 else "",
                "command": parts[3] if len(parts) > 3 else "",
            })
    return commands


def list_network_connections(image_path):
    """List network connections from memory."""
    result = run_vol3_plugin(image_path, "linux.sockstat")
    connections = []
    for line in result.get("output", []):
        if "TCP" in line or "UDP" in line:
            connections.append(line.strip())
    return connections


def list_kernel_modules(image_path):
    """List loaded kernel modules to detect rootkits."""
    result = run_vol3_plugin(image_path, "linux.lsmod")
    modules = []
    for line in result.get("output", []):
        parts = line.split()
        if parts and not parts[0].startswith("Offset"):
            modules.append({"name": parts[-1] if parts else line.strip()})
    return modules


def detect_hidden_processes(image_path):
    """Compare pslist vs psscan to find hidden processes."""
    pslist = run_vol3_plugin(image_path, "linux.pslist")
    psscan = run_vol3_plugin(image_path, "linux.psscan")
    pslist_pids = set()
    for line in pslist.get("output", []):
        parts = line.split()
        if parts and parts[0].isdigit():
            pslist_pids.add(int(parts[0]))
    hidden = []
    for line in psscan.get("output", []):
        parts = line.split()
        if parts and parts[0].isdigit():
            pid = int(parts[0])
            if pid not in pslist_pids and pid > 0:
                hidden.append({"pid": pid, "line": line.strip()})
    return hidden


def detect_suspicious_commands(bash_history):
    """Flag suspicious commands in bash history."""
    suspicious_patterns = [
        "curl.*|.*sh", "wget.*&&.*chmod", "base64.*-d",
        "nc.*-e", "python.*-c.*import.*socket",
        "nohup", "rm.*-rf.*/var/log", "history.*-c",
        "iptables.*-F", "chmod.*777", "chattr.*-i",
    ]
    import re
    findings = []
    for entry in bash_history:
        cmd = entry.get("command", "")
        for pattern in suspicious_patterns:
            if re.search(pattern, cmd, re.IGNORECASE):
                findings.append({
                    "pid": entry["pid"],
                    "command": cmd,
                    "pattern": pattern,
                    "severity": "HIGH",
                })
                break
    return findings


def check_malfind(image_path):
    """Run malfind to detect injected code."""
    result = run_vol3_plugin(image_path, "linux.malfind")
    return result.get("output", [])


def main():
    parser = argparse.ArgumentParser(description="LiME + Volatility 3 Forensics Agent")
    parser.add_argument("--image", help="Path to memory image")
    parser.add_argument("--acquire", help="Output path for LiME acquisition")
    parser.add_argument("--output", default="memory_forensics_report.json")
    parser.add_argument("--action", choices=[
        "acquire", "pslist", "bash", "network", "modules",
        "hidden", "malfind", "full_analysis"
    ], default="full_analysis")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.action == "acquire" and args.acquire:
        result = acquire_memory_lime(args.acquire)
        report["findings"]["acquisition"] = result
        print(f"[+] Memory acquisition: {result['status']}")
        return

    if not args.image:
        print("[-] --image required for analysis actions")
        return

    if args.action in ("pslist", "full_analysis"):
        procs = list_processes(args.image)
        report["findings"]["processes"] = procs
        print(f"[+] Processes: {len(procs)}")

    if args.action in ("bash", "full_analysis"):
        history = extract_bash_history(args.image)
        report["findings"]["bash_history"] = history
        suspicious = detect_suspicious_commands(history)
        report["findings"]["suspicious_commands"] = suspicious
        print(f"[+] Bash commands: {len(history)}, Suspicious: {len(suspicious)}")

    if args.action in ("network", "full_analysis"):
        conns = list_network_connections(args.image)
        report["findings"]["connections"] = conns
        print(f"[+] Network connections: {len(conns)}")

    if args.action in ("modules", "full_analysis"):
        modules = list_kernel_modules(args.image)
        report["findings"]["kernel_modules"] = modules
        print(f"[+] Kernel modules: {len(modules)}")

    if args.action in ("hidden", "full_analysis"):
        hidden = detect_hidden_processes(args.image)
        report["findings"]["hidden_processes"] = hidden
        print(f"[+] Hidden processes: {len(hidden)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
