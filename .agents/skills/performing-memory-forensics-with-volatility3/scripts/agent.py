#!/usr/bin/env python3
"""Agent for performing memory forensics with Volatility 3.

Automates memory dump analysis including process enumeration,
network connection extraction, malware detection, and credential
extraction using Volatility 3 framework via subprocess.
"""

import subprocess
import json
import sys
import re
from pathlib import Path
from collections import defaultdict


class MemoryForensicsAgent:
    """Automates Volatility 3 memory forensics analysis."""

    def __init__(self, memory_dump, output_dir):
        self.memory_dump = memory_dump
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _run_vol(self, plugin, extra_args=None):
        """Execute a Volatility 3 plugin and return output."""
        cmd = ["vol", "-f", self.memory_dump, plugin]
        if extra_args:
            cmd.extend(extra_args)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {"output": result.stdout, "stderr": result.stderr, "rc": result.returncode}

    def get_os_info(self):
        """Identify the operating system from the memory dump."""
        result = self._run_vol("windows.info")
        if result["rc"] != 0:
            result = self._run_vol("linux.info")
        return result

    def list_processes(self):
        """List all running processes."""
        return self._run_vol("windows.pslist")

    def get_process_tree(self):
        """Show process tree with parent-child relationships."""
        return self._run_vol("windows.pstree")

    def scan_hidden_processes(self):
        """Scan for hidden/unlinked processes via pool scanning."""
        return self._run_vol("windows.psscan")

    def detect_injected_code(self):
        """Detect process injection via malfind plugin."""
        return self._run_vol("windows.malfind")

    def get_network_connections(self):
        """Extract active network connections."""
        return self._run_vol("windows.netscan")

    def get_command_lines(self):
        """Extract command lines for all processes."""
        return self._run_vol("windows.cmdline")

    def dump_process_memory(self, pid):
        """Dump memory of a specific process."""
        dump_dir = self.output_dir / "process_dumps"
        dump_dir.mkdir(exist_ok=True)
        return self._run_vol("windows.memmap", [
            "--pid", str(pid), "--dump", "-o", str(dump_dir)
        ])

    def extract_hashes(self):
        """Extract cached password hashes."""
        return self._run_vol("windows.hashdump")

    def scan_with_yara(self, yara_file):
        """Scan memory with YARA rules."""
        return self._run_vol("yarascan", ["--yara-file", yara_file])

    def get_registry_keys(self, key_path):
        """Extract specific registry keys from memory."""
        return self._run_vol("windows.registry.printkey", ["--key", key_path])

    def list_services(self):
        """List Windows services from memory."""
        return self._run_vol("windows.svcscan")

    def list_loaded_modules(self):
        """List loaded kernel modules."""
        return self._run_vol("windows.modules")

    def scan_hidden_modules(self):
        """Scan for hidden kernel modules."""
        return self._run_vol("windows.modscan")

    def get_dll_list(self, pid=None):
        """List DLLs loaded by processes."""
        args = ["--pid", str(pid)] if pid else []
        return self._run_vol("windows.dlllist", args if args else None)

    def detect_anomalies(self):
        """Compare pslist vs psscan to find hidden processes."""
        pslist = self._run_vol("windows.pslist")
        psscan = self._run_vol("windows.psscan")

        pslist_pids = set(re.findall(r"^\s*(\d+)\s", pslist["output"], re.MULTILINE))
        psscan_pids = set(re.findall(r"^\s*(\d+)\s", psscan["output"], re.MULTILINE))

        hidden = psscan_pids - pslist_pids
        return {
            "pslist_count": len(pslist_pids),
            "psscan_count": len(psscan_pids),
            "hidden_pids": sorted(hidden),
            "hidden_count": len(hidden),
        }

    def generate_report(self, yara_file=None):
        """Run comprehensive memory analysis and generate report."""
        report = {
            "memory_dump": self.memory_dump,
            "os_info": self.get_os_info()["output"][:500],
        }

        report["process_list"] = self.list_processes()["output"]
        report["process_tree"] = self.get_process_tree()["output"]
        report["malfind"] = self.detect_injected_code()["output"]
        report["network"] = self.get_network_connections()["output"]
        report["cmdline"] = self.get_command_lines()["output"]
        report["hashes"] = self.extract_hashes()["output"]
        report["services"] = self.list_services()["output"][:2000]
        report["hidden_processes"] = self.detect_anomalies()

        if yara_file:
            report["yara_hits"] = self.scan_with_yara(yara_file)["output"]

        report_path = self.output_dir / "memory_forensics_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"Memory Forensics Report: {report_path}")
        print(f"Hidden processes: {report['hidden_processes']['hidden_count']}")
        if report["malfind"]["output"].strip():
            print("Malfind detections found - check report for details")
        return report


def main():
    if len(sys.argv) < 3:
        print("Usage: agent.py <memory_dump> <output_dir> [yara_rules]")
        sys.exit(1)

    memory_dump = sys.argv[1]
    output_dir = sys.argv[2]
    yara_file = sys.argv[3] if len(sys.argv) > 3 else None

    agent = MemoryForensicsAgent(memory_dump, output_dir)
    agent.generate_report(yara_file)


if __name__ == "__main__":
    main()
