#!/usr/bin/env python3
"""DEP/ASLR Memory Protection Agent - audits processes and binaries for memory protection mitigations."""

import json
import argparse
import logging
import subprocess
import re
import os
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def check_windows_dep_policy():
    """Check Windows DEP/NX policy via bcdedit."""
    cmd = ["bcdedit", "/enum", "{current}"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    dep_policy = "unknown"
    for line in result.stdout.split("\n"):
        if "nx" in line.lower():
            dep_policy = line.split()[-1] if line.split() else "unknown"
    return {"dep_policy": dep_policy, "recommended": "AlwaysOn"}


def check_windows_process_mitigations():
    """Check process mitigation policies using PowerShell Get-ProcessMitigation."""
    cmd = ["powershell", "-Command",
           "Get-Process | ForEach-Object { try { $m = Get-ProcessMitigation -Id $_.Id -ErrorAction Stop; "
           "[PSCustomObject]@{Name=$_.Name;PID=$_.Id;DEP=$m.DEP.Enable;ASLR=$m.ASLR.ForceRelocateImages;"
           "CFG=$m.CFG.Enable;StrictHandle=$m.StrictHandle.Enable} } catch {} } | ConvertTo-Json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        processes = json.loads(result.stdout) if result.stdout else []
        if isinstance(processes, dict):
            processes = [processes]
        return processes
    except json.JSONDecodeError:
        return []


def check_linux_aslr():
    """Check Linux ASLR configuration."""
    try:
        with open("/proc/sys/kernel/randomize_va_space") as f:
            value = int(f.read().strip())
        levels = {0: "disabled", 1: "partial", 2: "full"}
        return {"aslr_level": value, "status": levels.get(value, "unknown"), "recommended": 2}
    except (FileNotFoundError, ValueError):
        return {"aslr_level": -1, "status": "unknown"}


def check_linux_nx_support():
    """Check NX bit support on Linux."""
    result = subprocess.run(["grep", "nx", "/proc/cpuinfo"], capture_output=True, text=True)
    return {"nx_supported": "nx" in result.stdout.lower()}


def check_elf_pie_relro(binary_path):
    """Check ELF binary for PIE, RELRO, stack canary, and NX using readelf/checksec."""
    findings = {"binary": binary_path, "pie": False, "relro": "none", "nx": False, "canary": False}
    readelf_cmd = subprocess.run(["readelf", "-h", binary_path], capture_output=True, text=True)
    if "DYN" in readelf_cmd.stdout:
        findings["pie"] = True
    readelf_d = subprocess.run(["readelf", "-d", binary_path], capture_output=True, text=True)
    if "BIND_NOW" in readelf_d.stdout:
        findings["relro"] = "full"
    elif "GNU_RELRO" in readelf_d.stdout:
        findings["relro"] = "partial"
    readelf_s = subprocess.run(["readelf", "-s", binary_path], capture_output=True, text=True)
    if "__stack_chk_fail" in readelf_s.stdout:
        findings["canary"] = True
    readelf_l = subprocess.run(["readelf", "-l", binary_path], capture_output=True, text=True)
    for line in readelf_l.stdout.split("\n"):
        if "GNU_STACK" in line and "RWE" not in line:
            findings["nx"] = True
    score = sum([findings["pie"], findings["relro"] == "full", findings["nx"], findings["canary"]])
    findings["protection_score"] = f"{score}/4"
    return findings


def scan_directory_binaries(directory, extensions=None):
    """Scan directory for binaries and check protections."""
    if extensions is None:
        extensions = [""]
    results = []
    for root, dirs, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            if os.path.isfile(fpath) and os.access(fpath, os.X_OK):
                try:
                    result = check_elf_pie_relro(fpath)
                    results.append(result)
                except Exception:
                    continue
        if len(results) >= 100:
            break
    return results


def generate_report(system_checks, binary_checks):
    weak_binaries = [b for b in binary_checks if not b.get("pie") or b.get("relro") == "none"]
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "system_protections": system_checks,
        "binaries_scanned": len(binary_checks),
        "weak_binaries": len(weak_binaries),
        "protection_summary": {
            "pie_enabled": sum(1 for b in binary_checks if b.get("pie")),
            "full_relro": sum(1 for b in binary_checks if b.get("relro") == "full"),
            "nx_enabled": sum(1 for b in binary_checks if b.get("nx")),
            "canary_present": sum(1 for b in binary_checks if b.get("canary")),
        },
        "weak_binary_details": weak_binaries[:20],
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="DEP/ASLR Memory Protection Audit Agent")
    parser.add_argument("--scan-dir", default="/usr/bin", help="Directory to scan binaries")
    parser.add_argument("--platform", choices=["linux", "windows", "auto"], default="auto")
    parser.add_argument("--output", default="memory_protection_report.json")
    args = parser.parse_args()

    platform = args.platform
    if platform == "auto":
        platform = "windows" if os.name == "nt" else "linux"

    system_checks = {}
    if platform == "linux":
        system_checks["aslr"] = check_linux_aslr()
        system_checks["nx"] = check_linux_nx_support()
        binary_checks = scan_directory_binaries(args.scan_dir)
    else:
        system_checks["dep"] = check_windows_dep_policy()
        process_mitigations = check_windows_process_mitigations()
        binary_checks = []
        for proc in process_mitigations:
            binary_checks.append({
                "binary": proc.get("Name", ""),
                "pid": proc.get("PID", 0),
                "pie": bool(proc.get("ASLR")),
                "nx": bool(proc.get("DEP")),
                "canary": False,
                "relro": "n/a",
            })

    report = generate_report(system_checks, binary_checks)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Scanned %d binaries, %d with weak protections",
                report["binaries_scanned"], report["weak_binaries"])
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
