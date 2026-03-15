#!/usr/bin/env python3
"""Agent for performing memory forensics with Volatility3 plugins."""

import json
import argparse
import subprocess
from datetime import datetime
from pathlib import Path


VOL3_PLUGINS = {
    "pslist": "windows.pslist.PsList",
    "pstree": "windows.pstree.PsTree",
    "psscan": "windows.psscan.PsScan",
    "dlllist": "windows.dlllist.DllList",
    "handles": "windows.handles.Handles",
    "netscan": "windows.netscan.NetScan",
    "netstat": "windows.netstat.NetStat",
    "malfind": "windows.malfind.Malfind",
    "cmdline": "windows.cmdline.CmdLine",
    "filescan": "windows.filescan.FileScan",
    "hivelist": "windows.registry.hivelist.HiveList",
    "hashdump": "windows.hashdump.Hashdump",
    "lsadump": "windows.lsadump.Lsadump",
    "svcscan": "windows.svcscan.SvcScan",
    "ssdt": "windows.ssdt.SSDT",
    "callbacks": "windows.callbacks.Callbacks",
    "vadinfo": "windows.vadinfo.VadInfo",
    "envars": "windows.envars.Envars",
}


def run_vol3_plugin(memory_dump, plugin_name, extra_args=None):
    """Execute a Volatility3 plugin against a memory dump."""
    plugin_class = VOL3_PLUGINS.get(plugin_name, plugin_name)
    cmd = ["vol", "-f", memory_dump, "-r", "json", plugin_class]
    if extra_args:
        cmd += extra_args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            return {"error": result.stderr[:500], "plugin": plugin_name}
        data = json.loads(result.stdout)
        return {"plugin": plugin_name, "memory_dump": memory_dump, "results": data, "count": len(data) if isinstance(data, list) else 1}
    except FileNotFoundError:
        return {"error": "Volatility3 (vol) not found — pip install volatility3"}
    except json.JSONDecodeError:
        return {"plugin": plugin_name, "raw_output": result.stdout[:2000]}
    except subprocess.TimeoutExpired:
        return {"error": f"Plugin {plugin_name} timed out after 300s"}


def detect_malicious_processes(memory_dump):
    """Run process analysis plugins to detect suspicious processes."""
    suspicious_names = ["mimikatz", "procdump", "psexec", "cobalt", "beacon",
                        "meterpreter", "nc.exe", "ncat", "powercat", "lazagne",
                        "bloodhound", "rubeus", "certify", "seatbelt", "sharphound"]
    pslist = run_vol3_plugin(memory_dump, "pslist")
    cmdline = run_vol3_plugin(memory_dump, "cmdline")
    suspicious = []
    if isinstance(pslist.get("results"), list):
        for proc in pslist["results"]:
            name = str(proc.get("ImageFileName", proc.get("Name", ""))).lower()
            pid = proc.get("PID", proc.get("pid", ""))
            ppid = proc.get("PPID", proc.get("ppid", ""))
            if any(s in name for s in suspicious_names):
                suspicious.append({"pid": pid, "name": name, "ppid": ppid, "reason": "KNOWN_ATTACK_TOOL"})
            if name == "cmd.exe" and str(ppid) not in ("0", "1"):
                suspicious.append({"pid": pid, "name": name, "ppid": ppid, "reason": "CMD_SPAWNED"})
            if name in ("powershell.exe", "pwsh.exe"):
                suspicious.append({"pid": pid, "name": name, "ppid": ppid, "reason": "POWERSHELL_EXECUTION"})
    return {
        "memory_dump": memory_dump,
        "total_processes": len(pslist.get("results", [])) if isinstance(pslist.get("results"), list) else 0,
        "suspicious_processes": suspicious,
        "timestamp": datetime.utcnow().isoformat(),
    }


def detect_injected_code(memory_dump):
    """Run malfind to detect code injection."""
    malfind = run_vol3_plugin(memory_dump, "malfind")
    findings = []
    if isinstance(malfind.get("results"), list):
        for entry in malfind["results"]:
            findings.append({
                "pid": entry.get("PID", entry.get("pid")),
                "process": entry.get("Process", entry.get("process", "")),
                "address": entry.get("Start VPN", entry.get("start", "")),
                "protection": entry.get("Protection", entry.get("protection", "")),
                "tag": entry.get("Tag", ""),
            })
    return {
        "memory_dump": memory_dump,
        "injections_found": len(findings),
        "findings": findings[:30],
        "severity": "HIGH" if findings else "INFO",
    }


def analyze_network_connections(memory_dump):
    """Extract network connections from memory."""
    netscan = run_vol3_plugin(memory_dump, "netscan")
    connections = []
    if isinstance(netscan.get("results"), list):
        for conn in netscan["results"]:
            connections.append({
                "pid": conn.get("PID", conn.get("pid")),
                "process": conn.get("Owner", conn.get("process", "")),
                "local_addr": conn.get("LocalAddr", conn.get("local_addr", "")),
                "local_port": conn.get("LocalPort", conn.get("local_port", "")),
                "remote_addr": conn.get("ForeignAddr", conn.get("remote_addr", "")),
                "remote_port": conn.get("ForeignPort", conn.get("remote_port", "")),
                "state": conn.get("State", conn.get("state", "")),
            })
    external = [c for c in connections if c.get("remote_addr") and not c["remote_addr"].startswith(("0.0", "127.", "10.", "192.168.", "172."))]
    return {
        "total_connections": len(connections),
        "external_connections": len(external),
        "connections": connections[:30],
        "external_only": external[:20],
    }


def full_triage(memory_dump):
    """Run full memory triage with key plugins."""
    return {
        "memory_dump": memory_dump,
        "timestamp": datetime.utcnow().isoformat(),
        "processes": detect_malicious_processes(memory_dump),
        "injections": detect_injected_code(memory_dump),
        "network": analyze_network_connections(memory_dump),
    }


def main():
    parser = argparse.ArgumentParser(description="Volatility3 Memory Forensics Agent")
    sub = parser.add_subparsers(dest="command")
    p = sub.add_parser("plugin", help="Run specific Volatility3 plugin")
    p.add_argument("--dump", required=True, help="Memory dump file path")
    p.add_argument("--name", required=True, help="Plugin name or class", choices=list(VOL3_PLUGINS.keys()))
    p.add_argument("--args", nargs="*", help="Extra plugin arguments")
    m = sub.add_parser("malproc", help="Detect malicious processes")
    m.add_argument("--dump", required=True)
    i = sub.add_parser("inject", help="Detect code injection")
    i.add_argument("--dump", required=True)
    n = sub.add_parser("network", help="Analyze network connections")
    n.add_argument("--dump", required=True)
    t = sub.add_parser("triage", help="Full memory triage")
    t.add_argument("--dump", required=True)
    args = parser.parse_args()
    if args.command == "plugin":
        result = run_vol3_plugin(args.dump, args.name, args.args)
    elif args.command == "malproc":
        result = detect_malicious_processes(args.dump)
    elif args.command == "inject":
        result = detect_injected_code(args.dump)
    elif args.command == "network":
        result = analyze_network_connections(args.dump)
    elif args.command == "triage":
        result = full_triage(args.dump)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
