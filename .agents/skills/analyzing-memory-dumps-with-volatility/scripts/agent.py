#!/usr/bin/env python3
"""Memory forensics agent using Volatility 3 for malware detection in RAM dumps."""

import subprocess
import os
import sys
import json
import csv
import re
import io


def run_vol3(memory_dump, plugin, extra_args=""):
    """Execute a Volatility 3 plugin and return output."""
    cmd = f"vol3 -f {memory_dump} {plugin} {extra_args}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def get_os_info(memory_dump):
    """Identify the OS from the memory dump."""
    stdout, _, rc = run_vol3(memory_dump, "windows.info")
    if rc == 0:
        return {"os": "windows", "info": stdout}
    stdout, _, rc = run_vol3(memory_dump, "linux.info")
    if rc == 0:
        return {"os": "linux", "info": stdout}
    return {"os": "unknown", "info": ""}


def list_processes(memory_dump):
    """List all running processes using pslist."""
    stdout, _, rc = run_vol3(memory_dump, "windows.pslist")
    processes = []
    if rc == 0:
        for line in stdout.splitlines()[2:]:
            parts = line.split()
            if len(parts) >= 6 and parts[0].isdigit():
                processes.append({
                    "pid": int(parts[0]),
                    "ppid": int(parts[1]),
                    "name": parts[4] if len(parts) > 4 else "",
                    "offset": parts[0] if not parts[0].isdigit() else "",
                })
    return processes


def scan_hidden_processes(memory_dump):
    """Scan for hidden/unlinked processes using psscan."""
    stdout, _, rc = run_vol3(memory_dump, "windows.psscan")
    processes = []
    if rc == 0:
        for line in stdout.splitlines()[2:]:
            parts = line.split()
            if len(parts) >= 5 and parts[1].isdigit():
                processes.append({
                    "offset": parts[0],
                    "pid": int(parts[1]),
                    "ppid": int(parts[2]) if parts[2].isdigit() else 0,
                    "name": parts[4] if len(parts) > 4 else "",
                })
    return processes


def find_hidden_processes(pslist_procs, psscan_procs):
    """Compare pslist and psscan to identify DKOM-hidden processes."""
    pslist_pids = {p["pid"] for p in pslist_procs}
    hidden = [p for p in psscan_procs if p["pid"] not in pslist_pids and p["pid"] > 4]
    return hidden


def detect_code_injection(memory_dump, pid=None):
    """Detect injected code using malfind plugin."""
    extra = f"--pid {pid}" if pid else ""
    stdout, _, rc = run_vol3(memory_dump, "windows.malfind", extra)
    injections = []
    if rc == 0:
        current = {}
        for line in stdout.splitlines():
            if "PID" in line and "Process" in line:
                continue
            parts = line.split()
            if len(parts) >= 4 and parts[0].isdigit():
                if current:
                    injections.append(current)
                current = {
                    "pid": int(parts[0]),
                    "process": parts[1] if len(parts) > 1 else "",
                    "address": parts[2] if len(parts) > 2 else "",
                    "protection": parts[3] if len(parts) > 3 else "",
                }
            elif current and line.strip():
                current["data_preview"] = current.get("data_preview", "") + line.strip() + " "
        if current:
            injections.append(current)
    return injections


def get_network_connections(memory_dump):
    """Extract network connections using netscan."""
    stdout, _, rc = run_vol3(memory_dump, "windows.netscan")
    connections = []
    if rc == 0:
        for line in stdout.splitlines()[2:]:
            parts = line.split()
            if len(parts) >= 7:
                connections.append({
                    "protocol": parts[1] if len(parts) > 1 else "",
                    "local_addr": parts[2] if len(parts) > 2 else "",
                    "local_port": parts[3] if len(parts) > 3 else "",
                    "foreign_addr": parts[4] if len(parts) > 4 else "",
                    "foreign_port": parts[5] if len(parts) > 5 else "",
                    "state": parts[6] if len(parts) > 6 else "",
                    "pid": parts[7] if len(parts) > 7 else "",
                    "owner": parts[8] if len(parts) > 8 else "",
                })
    return connections


def get_command_lines(memory_dump):
    """Extract process command lines."""
    stdout, _, rc = run_vol3(memory_dump, "windows.cmdline")
    cmdlines = []
    if rc == 0:
        for line in stdout.splitlines()[2:]:
            parts = line.split(None, 2)
            if len(parts) >= 3 and parts[0].isdigit():
                cmdlines.append({
                    "pid": int(parts[0]),
                    "process": parts[1],
                    "cmdline": parts[2],
                })
    return cmdlines


def dump_credentials(memory_dump):
    """Extract cached credentials using hashdump and lsadump."""
    results = {}
    stdout, _, rc = run_vol3(memory_dump, "windows.hashdump")
    if rc == 0:
        results["hashdump"] = stdout
    stdout, _, rc = run_vol3(memory_dump, "windows.cachedump")
    if rc == 0:
        results["cachedump"] = stdout
    stdout, _, rc = run_vol3(memory_dump, "windows.lsadump")
    if rc == 0:
        results["lsadump"] = stdout
    return results


def scan_with_yara(memory_dump, yara_file=None, yara_rule=None, pid=None):
    """Scan memory with YARA rules."""
    extra = ""
    if yara_file:
        extra += f"--yara-file {yara_file}"
    elif yara_rule:
        extra += f'--yara-rules "{yara_rule}"'
    if pid:
        extra += f" --pid {pid}"
    stdout, _, rc = run_vol3(memory_dump, "yarascan.YaraScan", extra)
    return stdout if rc == 0 else ""


def check_suspicious_processes(pslist_procs):
    """Check process list for common suspicious indicators."""
    findings = []
    expected_parents = {
        "svchost.exe": ["services.exe"],
        "csrss.exe": ["smss.exe"],
        "lsass.exe": ["wininit.exe"],
        "smss.exe": ["System"],
    }
    name_counts = {}
    for p in pslist_procs:
        name = p["name"].lower()
        name_counts[name] = name_counts.get(name, 0) + 1

    if name_counts.get("lsass.exe", 0) > 1:
        findings.append({"severity": "CRITICAL",
                         "finding": "Multiple lsass.exe instances detected"})

    misspellings = {
        "scvhost.exe": "svchost.exe", "svch0st.exe": "svchost.exe",
        "lssas.exe": "lsass.exe", "csrs.exe": "csrss.exe",
    }
    for p in pslist_procs:
        if p["name"].lower() in misspellings:
            findings.append({
                "severity": "HIGH",
                "finding": f"Misspelled process: {p['name']} (PID {p['pid']}) "
                           f"mimicking {misspellings[p['name'].lower()]}",
            })
    return findings


if __name__ == "__main__":
    print("=" * 60)
    print("Memory Forensics Agent (Volatility 3)")
    print("Process analysis, injection detection, credential extraction")
    print("=" * 60)

    dump_file = sys.argv[1] if len(sys.argv) > 1 else None

    if dump_file and os.path.exists(dump_file):
        print(f"\n[*] Analyzing memory dump: {dump_file}")
        print(f"[*] Size: {os.path.getsize(dump_file) / (1024**3):.1f} GB")

        print("\n--- OS Identification ---")
        os_info = get_os_info(dump_file)
        print(f"  OS: {os_info['os']}")

        print("\n--- Process Analysis ---")
        procs = list_processes(dump_file)
        print(f"  Active processes: {len(procs)}")
        suspicious = check_suspicious_processes(procs)
        for s in suspicious:
            print(f"  [{s['severity']}] {s['finding']}")

        print("\n--- Hidden Process Detection ---")
        psscan = scan_hidden_processes(dump_file)
        hidden = find_hidden_processes(procs, psscan)
        if hidden:
            for h in hidden:
                print(f"  [!] Hidden process: {h['name']} PID={h['pid']}")
        else:
            print("  No hidden processes detected")

        print("\n--- Code Injection Detection ---")
        injections = detect_code_injection(dump_file)
        print(f"  Injected regions: {len(injections)}")
        for inj in injections[:5]:
            print(f"  [!] PID {inj['pid']} ({inj.get('process', '')}): {inj.get('protection', '')}")

        print("\n--- Network Connections ---")
        conns = get_network_connections(dump_file)
        established = [c for c in conns if "ESTABLISHED" in c.get("state", "")]
        print(f"  Total: {len(conns)}, Established: {len(established)}")
        for c in established[:10]:
            print(f"  {c.get('owner', '?')} (PID {c.get('pid', '?')}): "
                  f"{c['local_addr']}:{c['local_port']} -> "
                  f"{c['foreign_addr']}:{c['foreign_port']}")
    else:
        print(f"\n[DEMO] Usage: python agent.py <memory.dmp>")
        print("[*] Provide a memory dump for forensic analysis.")
