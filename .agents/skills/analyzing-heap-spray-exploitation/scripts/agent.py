#!/usr/bin/env python3
"""Agent for analyzing heap spray exploitation in memory dumps.

Detects heap spray artifacts using Volatility3 by scanning for
NOP sled patterns, large contiguous allocations, and injected
executable regions in process virtual address space.
"""
# For authorized forensic analysis only

import argparse
import hashlib
import json
import os
import re
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path

NOP_PATTERNS = {
    "x86_nop": b"\x90" * 16,
    "heap_spray_0c": b"\x0c" * 16,
    "heap_spray_0d": b"\x0d" * 16,
    "heap_spray_0a": b"\x0a" * 16,
    "heap_spray_04": b"\x04" * 16,
    "heap_spray_41": b"\x41" * 16,
}

SHELLCODE_MARKERS = [
    b"\xfc\xe8",              # CLD; CALL
    b"\x60\xe8",              # PUSHAD; CALL
    b"\xeb\x10\x5a",         # JMP SHORT; POP EDX
    b"\x31\xc0\x50\x68",     # XOR EAX; PUSH; PUSH
    b"\xe8\xff\xff\xff\xff",  # CALL $+5 (self-locating)
]

SUSPICIOUS_ALLOC_THRESHOLD = 0x100000  # 1 MB


class HeapSprayAnalyzer:
    """Detects heap spray exploitation artifacts in memory dumps."""

    def __init__(self, memory_dump, output_dir="./heap_spray_analysis"):
        self.memory_dump = memory_dump
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def _run_vol3(self, plugin, extra_args=None):
        """Run a Volatility3 plugin and return stdout."""
        cmd = ["vol", "-f", self.memory_dump, plugin]
        if extra_args:
            cmd.extend(extra_args)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return ""

    def run_malfind(self):
        """Run windows.malfind to detect injected executable memory."""
        output = self._run_vol3("windows.malfind")
        entries = []
        current = {}
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 6 and parts[0].isdigit():
                if current:
                    entries.append(current)
                current = {
                    "pid": int(parts[0]),
                    "process": parts[1],
                    "start_addr": parts[2],
                    "end_addr": parts[3],
                    "protection": parts[5] if len(parts) > 5 else "",
                }
            elif current and line.strip().startswith("0x"):
                hex_match = re.findall(r"[0-9a-fA-F]{2}", line.split("  ")[0] if "  " in line else line)
                if "hex_bytes" not in current:
                    current["hex_bytes"] = ""
                current["hex_bytes"] += "".join(hex_match)
        if current:
            entries.append(current)
        return entries

    def run_vadinfo(self):
        """Run windows.vadinfo to find large suspicious allocations."""
        output = self._run_vol3("windows.vadinfo")
        large_allocs = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0].isdigit():
                try:
                    pid = int(parts[0])
                    start = int(parts[2], 16) if parts[2].startswith("0x") else 0
                    end = int(parts[3], 16) if parts[3].startswith("0x") else 0
                    size = end - start
                    if size >= SUSPICIOUS_ALLOC_THRESHOLD:
                        large_allocs.append({
                            "pid": pid, "process": parts[1],
                            "start": hex(start), "end": hex(end),
                            "size_bytes": size, "size_mb": round(size / (1024 * 1024), 2),
                        })
                except (ValueError, IndexError):
                    continue
        return large_allocs

    def scan_dump_for_patterns(self, dump_path):
        """Scan a memory dump file for NOP sled and shellcode patterns."""
        matches = {"nop_sleds": [], "shellcode_markers": []}
        try:
            with open(dump_path, "rb") as f:
                data = f.read()
        except (FileNotFoundError, PermissionError):
            return matches

        for name, pattern in NOP_PATTERNS.items():
            offset = 0
            count = 0
            while True:
                idx = data.find(pattern, offset)
                if idx == -1:
                    break
                count += 1
                offset = idx + len(pattern)
                if count > 100:
                    break
            if count > 0:
                matches["nop_sleds"].append({"pattern": name, "occurrences": count})

        for marker in SHELLCODE_MARKERS:
            idx = data.find(marker)
            if idx != -1:
                context = data[idx:idx + 64]
                matches["shellcode_markers"].append({
                    "offset": hex(idx),
                    "bytes": context.hex()[:128],
                    "sha256": hashlib.sha256(context).hexdigest(),
                })
        return matches

    def dump_process_memory(self, pid):
        """Dump a process's memory using Volatility3 memmap."""
        dump_dir = self.output_dir / f"pid_{pid}"
        dump_dir.mkdir(exist_ok=True)
        self._run_vol3("windows.memmap", ["--pid", str(pid), "--dump",
                                           "--output-dir", str(dump_dir)])
        dumps = list(dump_dir.glob("*.dmp"))
        return [str(d) for d in dumps]

    def analyze(self):
        """Run full heap spray analysis pipeline."""
        malfind_results = self.run_malfind()
        large_allocs = self.run_vadinfo()

        spray_candidates = defaultdict(list)
        for alloc in large_allocs:
            spray_candidates[alloc["pid"]].append(alloc)

        for pid, allocs in spray_candidates.items():
            total_mb = sum(a["size_mb"] for a in allocs)
            if total_mb > 50:
                self.findings.append({
                    "severity": "high", "type": "Heap Spray Indicator",
                    "detail": f"PID {pid}: {total_mb:.1f} MB in {len(allocs)} large allocations",
                })

        for entry in malfind_results:
            hex_bytes = entry.get("hex_bytes", "")
            if hex_bytes.count("90") > 20 or hex_bytes.count("0c") > 20:
                self.findings.append({
                    "severity": "critical", "type": "NOP Sled in Injected Region",
                    "detail": f"PID {entry['pid']} ({entry['process']}): "
                              f"NOP sled at {entry['start_addr']}",
                })

        return {
            "malfind_entries": malfind_results,
            "large_allocations": large_allocs,
            "spray_candidate_pids": list(spray_candidates.keys()),
        }

    def generate_report(self):
        analysis = self.analyze()

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "memory_dump": self.memory_dump,
            "malfind_count": len(analysis["malfind_entries"]),
            "large_allocation_count": len(analysis["large_allocations"]),
            **analysis,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "heap_spray_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    parser = argparse.ArgumentParser(
        description="Analyze memory dumps for heap spray exploitation artifacts"
    )
    parser.add_argument("memory_dump", help="Path to memory dump file (.raw, .vmem, .dmp)")
    parser.add_argument("--output-dir", default="./heap_spray_analysis",
                        help="Output directory for report and dumps")
    parser.add_argument("--alloc-threshold", type=int, default=0x100000,
                        help="Minimum allocation size in bytes to flag (default: 1MB)")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    analyzer = HeapSprayAnalyzer(args.memory_dump, output_dir=args.output_dir)
    analyzer.generate_report()


if __name__ == "__main__":
    main()
