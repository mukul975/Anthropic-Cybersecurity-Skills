#!/usr/bin/env python3
"""Memory Forensics Agent - Automates Volatility 3 analysis of memory dumps for incident response."""

import json
import logging
import argparse
import subprocess
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def run_volatility(memory_file, plugin, extra_args=None):
    """Execute a Volatility 3 plugin and return parsed output."""
    cmd = ["vol", "-f", memory_file, plugin]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        logger.error("Volatility plugin %s failed: %s", plugin, result.stderr[:200])
        return []
    lines = result.stdout.strip().split("\n")
    if len(lines) < 2:
        return []
    headers = [h.strip() for h in lines[0].split("\t")]
    rows = []
    for line in lines[1:]:
        if line.strip() and not line.startswith("*"):
            fields = [f.strip() for f in line.split("\t")]
            if len(fields) == len(headers):
                rows.append(dict(zip(headers, fields)))
    logger.info("Plugin %s returned %d rows", plugin, len(rows))
    return rows


def analyze_processes(memory_file):
    """List running processes and identify suspicious ones."""
    processes = run_volatility(memory_file, "windows.pslist")
    suspicious = []
    suspicious_names = [
        "mimikatz", "procdump", "psexec", "cobalt", "beacon", "meterpreter",
        "nc.exe", "ncat", "powershell", "cmd.exe", "wscript", "cscript",
        "certutil", "bitsadmin", "mshta", "regsvr32",
    ]
    for proc in processes:
        name = proc.get("ImageFileName", "").lower()
        if any(s in name for s in suspicious_names):
            proc["suspicious_reason"] = "Known offensive tool"
            suspicious.append(proc)
    logger.info("Processes: %d total, %d suspicious", len(processes), len(suspicious))
    return processes, suspicious


def analyze_network_connections(memory_file):
    """Extract network connections and identify C2 communication."""
    connections = run_volatility(memory_file, "windows.netscan")
    established = [c for c in connections if c.get("State") == "ESTABLISHED"]
    logger.info("Network connections: %d total, %d established", len(connections), len(established))
    return connections, established


def detect_process_injection(memory_file):
    """Detect process injection using malfind plugin."""
    malfind_results = run_volatility(memory_file, "windows.malfind")
    injected = []
    for entry in malfind_results:
        injected.append({
            "pid": entry.get("PID", ""),
            "process": entry.get("Process", ""),
            "start_vpn": entry.get("Start VPN", ""),
            "protection": entry.get("Protection", ""),
            "tag": entry.get("Tag", ""),
        })
    logger.info("Malfind: %d potential injections detected", len(injected))
    return injected


def analyze_dlls(memory_file, pid=None):
    """List loaded DLLs for a process or all processes."""
    args = ["--pid", str(pid)] if pid else None
    dlls = run_volatility(memory_file, "windows.dlllist", args)
    return dlls


def extract_command_history(memory_file):
    """Extract command line history from process memory."""
    cmdline = run_volatility(memory_file, "windows.cmdline")
    suspicious_cmds = []
    indicators = [
        "powershell -enc", "invoke-expression", "downloadstring", "net user",
        "mimikatz", "sekurlsa", "lsadump", "reg save", "vssadmin",
        "certutil -urlcache", "bitsadmin /transfer",
    ]
    for entry in cmdline:
        args = entry.get("Args", "").lower()
        if any(ind in args for ind in indicators):
            entry["suspicious_reason"] = "Suspicious command pattern"
            suspicious_cmds.append(entry)
    logger.info("Command lines: %d total, %d suspicious", len(cmdline), len(suspicious_cmds))
    return cmdline, suspicious_cmds


def extract_registry_hives(memory_file):
    """List registry hives in memory."""
    hives = run_volatility(memory_file, "windows.registry.hivelist")
    logger.info("Registry hives: %d found", len(hives))
    return hives


def check_kernel_modules(memory_file):
    """List kernel modules and detect potential rootkits."""
    modules = run_volatility(memory_file, "windows.modules")
    drivers = run_volatility(memory_file, "windows.driverscan")
    hidden = []
    module_names = {m.get("Name", "").lower() for m in modules}
    for driver in drivers:
        if driver.get("Name", "").lower() not in module_names:
            hidden.append(driver)
            logger.warning("Hidden driver detected: %s", driver.get("Name"))
    return modules, hidden


def generate_forensics_report(memory_file, processes, suspicious_procs, connections,
                               injections, suspicious_cmds, hidden_drivers):
    """Generate memory forensics analysis report."""
    report = {
        "memory_image": memory_file,
        "analysis_timestamp": datetime.utcnow().isoformat(),
        "process_summary": {
            "total": len(processes),
            "suspicious": len(suspicious_procs),
            "details": suspicious_procs[:20],
        },
        "network_connections": {
            "established": len(connections),
            "details": connections[:20],
        },
        "process_injection": {
            "count": len(injections),
            "details": injections[:20],
        },
        "suspicious_commands": suspicious_cmds[:20],
        "hidden_drivers": hidden_drivers,
    }
    total_findings = len(suspicious_procs) + len(injections) + len(suspicious_cmds) + len(hidden_drivers)
    print(f"MEMORY FORENSICS REPORT - {total_findings} findings")
    return report


def main():
    parser = argparse.ArgumentParser(description="Memory Forensics Agent (Volatility 3)")
    parser.add_argument("--memory-file", required=True, help="Path to memory dump file")
    parser.add_argument("--output", default="memory_forensics_report.json")
    args = parser.parse_args()

    processes, suspicious = analyze_processes(args.memory_file)
    connections, established = analyze_network_connections(args.memory_file)
    injections = detect_process_injection(args.memory_file)
    cmdlines, suspicious_cmds = extract_command_history(args.memory_file)
    modules, hidden = check_kernel_modules(args.memory_file)

    report = generate_forensics_report(
        args.memory_file, processes, suspicious, established,
        injections, suspicious_cmds, hidden,
    )
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
