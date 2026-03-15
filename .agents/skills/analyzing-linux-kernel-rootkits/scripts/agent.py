#!/usr/bin/env python3
"""Linux Kernel Rootkit Detection Agent - analyzes memory dumps with Volatility3 and live system with rkhunter."""

import json
import argparse
import logging
import subprocess
import os
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def run_vol3_plugin(memory_dump, plugin, isf_url=None):
    """Run a Volatility3 Linux plugin and return parsed output."""
    cmd = ["vol", "-f", memory_dump, plugin, "-r", "json"]
    if isf_url:
        cmd.extend(["--isf", isf_url])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    try:
        return json.loads(result.stdout) if result.stdout else []
    except json.JSONDecodeError:
        logger.error("Volatility3 %s output parse failed", plugin)
        return []


def check_syscall_hooks(memory_dump, isf_url=None):
    """Detect hooked system calls using linux.check_syscall."""
    results = run_vol3_plugin(memory_dump, "linux.check_syscall.Check_syscall", isf_url)
    hooked = []
    for entry in results:
        row = entry.get("__children", [entry]) if isinstance(entry, dict) else [entry]
        for item in row:
            symbol = item.get("Symbol", item.get("symbol", ""))
            module = item.get("Module", item.get("module", ""))
            if module and module != "kernel":
                hooked.append({
                    "syscall_number": item.get("Index", item.get("index", "")),
                    "expected_handler": symbol,
                    "actual_module": module,
                    "severity": "critical",
                    "indicator": "syscall_hook",
                })
    return hooked


def detect_hidden_modules(memory_dump, isf_url=None):
    """Detect hidden kernel modules using cross-view analysis."""
    lsmod_results = run_vol3_plugin(memory_dump, "linux.lsmod.Lsmod", isf_url)
    hidden_results = run_vol3_plugin(memory_dump, "linux.hidden_modules.Hidden_modules", isf_url)
    lsmod_names = set()
    for entry in lsmod_results:
        name = entry.get("Name", entry.get("name", ""))
        if name:
            lsmod_names.add(name)
    hidden = []
    for entry in hidden_results:
        name = entry.get("Name", entry.get("name", ""))
        if name:
            hidden.append({
                "module_name": name,
                "in_lsmod": name in lsmod_names,
                "severity": "critical",
                "indicator": "hidden_kernel_module",
                "detail": f"Module '{name}' hidden from standard listing",
            })
    return hidden


def check_idt_hooks(memory_dump, isf_url=None):
    """Check Interrupt Descriptor Table for hooks."""
    results = run_vol3_plugin(memory_dump, "linux.check_idt.Check_idt", isf_url)
    hooked = []
    for entry in results:
        module = entry.get("Module", entry.get("module", ""))
        if module and module != "kernel":
            hooked.append({
                "interrupt": entry.get("Index", ""),
                "handler_module": module,
                "severity": "critical",
                "indicator": "idt_hook",
            })
    return hooked


def run_rkhunter():
    """Run rkhunter rootkit scanner on live system."""
    cmd = ["rkhunter", "--check", "--skip-keypress", "--report-warnings-only", "--nocolors"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    findings = []
    for line in result.stdout.split("\n"):
        line = line.strip()
        if "Warning:" in line or "[ Warning ]" in line:
            findings.append({
                "tool": "rkhunter",
                "finding": line.replace("Warning:", "").strip(),
                "severity": "high",
            })
    return findings


def check_proc_sys_discrepancy():
    """Compare /proc/modules with /sys/module for hidden modules."""
    findings = []
    proc_modules = set()
    sys_modules = set()
    try:
        with open("/proc/modules") as f:
            for line in f:
                proc_modules.add(line.split()[0])
    except (FileNotFoundError, PermissionError):
        return findings
    try:
        sys_modules = set(os.listdir("/sys/module"))
    except (FileNotFoundError, PermissionError):
        return findings
    only_in_sys = sys_modules - proc_modules
    for mod in only_in_sys:
        if not os.path.exists(f"/sys/module/{mod}/initstate"):
            continue
        findings.append({
            "module": mod, "indicator": "proc_sys_discrepancy",
            "severity": "high",
            "detail": f"Module '{mod}' in /sys/module but missing from /proc/modules",
        })
    return findings


def generate_report(syscall_hooks, hidden_mods, idt_hooks, rkhunter_findings, proc_findings, source):
    all_findings = syscall_hooks + hidden_mods + idt_hooks + rkhunter_findings + proc_findings
    critical = sum(1 for f in all_findings if f.get("severity") == "critical")
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "analysis_source": source,
        "syscall_hooks": syscall_hooks,
        "hidden_modules": hidden_mods,
        "idt_hooks": idt_hooks,
        "rkhunter_warnings": rkhunter_findings,
        "proc_sys_discrepancies": proc_findings,
        "total_findings": len(all_findings),
        "critical_findings": critical,
        "rootkit_detected": critical > 0,
    }


def main():
    parser = argparse.ArgumentParser(description="Linux Kernel Rootkit Detection Agent")
    parser.add_argument("--memory-dump", help="Path to Linux memory dump for Volatility3 analysis")
    parser.add_argument("--isf-url", help="Volatility3 ISF symbol table URL")
    parser.add_argument("--live-scan", action="store_true", help="Run rkhunter + /proc analysis on live system")
    parser.add_argument("--output", default="rootkit_detection_report.json")
    args = parser.parse_args()

    syscall_hooks, hidden_mods, idt_hooks = [], [], []
    rkhunter_findings, proc_findings = [], []
    source = "none"
    if args.memory_dump:
        source = f"memory_dump:{args.memory_dump}"
        syscall_hooks = check_syscall_hooks(args.memory_dump, args.isf_url)
        hidden_mods = detect_hidden_modules(args.memory_dump, args.isf_url)
        idt_hooks = check_idt_hooks(args.memory_dump, args.isf_url)
    if args.live_scan:
        source = "live_system" if source == "none" else source + "+live_system"
        rkhunter_findings = run_rkhunter()
        proc_findings = check_proc_sys_discrepancy()
    report = generate_report(syscall_hooks, hidden_mods, idt_hooks, rkhunter_findings, proc_findings, source)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Rootkit scan: %d findings (%d critical), rootkit detected: %s",
                report["total_findings"], report["critical_findings"], report["rootkit_detected"])
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
