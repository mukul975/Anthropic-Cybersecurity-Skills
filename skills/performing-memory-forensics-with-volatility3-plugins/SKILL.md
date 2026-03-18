---
name: performing-memory-forensics-with-volatility3-plugins
description: Analyze memory dumps using Volatility3 plugins to detect injected code, rootkits, credential theft, and malware artifacts in Windows, Linux, and macOS memory images.
domain: cybersecurity
subdomain: malware-analysis
tags: [memory-forensics, volatility3, malware-analysis, incident-response, process-injection, rootkit-detection, dfir]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Memory Forensics with Volatility3 Plugins

## Overview

Volatility3 (v2.26.0+, feature parity release May 2025) is the standard framework for memory forensics, replacing the deprecated Volatility2. It analyzes RAM dumps from Windows, Linux, and macOS to detect malicious processes, code injection, rootkits, credential harvesting, and network connections that disk-based forensics cannot reveal. Key plugins include `windows.malfind` (detecting RWX memory regions indicating injection), `windows.psscan` (finding hidden processes), `windows.dlllist` (enumerating loaded modules), `windows.netscan` (active network connections), and `windows.handles` (open file/registry handles). The 2024 Plugin Contest introduced ETW Scan for extracting Event Tracing for Windows data from memory.

## Prerequisites

- Python 3.9+ with `volatility3` framework installed
- Memory dump files (`.raw`, `.dmp`, `.vmem`, `.lime`)
- Windows symbol tables (ISF files, auto-downloaded)
- Understanding of Windows process memory architecture
- YARA integration for in-memory pattern scanning

## Practical Steps

### Step 1: Process Analysis for Malware Detection

```python
#!/usr/bin/env python3
"""Volatility3-based memory forensics automation for malware analysis."""
import subprocess
import json
import sys
import os


class Vol3Analyzer:
    """Automate Volatility3 plugin execution for malware analysis."""

    def __init__(self, dump_path, vol3_path="vol"):
        self.dump_path = dump_path
        self.vol3 = vol3_path
        self.results = {}

    def run_plugin(self, plugin, extra_args=None):
        """Execute a Volatility3 plugin and capture output."""
        cmd = [
            self.vol3, "-f", self.dump_path,
            "-r", "json", plugin,
        ]
        if extra_args:
            cmd.extend(extra_args)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            print(f"  [!] {plugin} failed: {e}")
        return None

    def detect_process_injection(self):
        """Use malfind to detect injected code regions."""
        print("[+] Running windows.malfind (code injection detection)")
        results = self.run_plugin("windows.malfind")

        injected = []
        if results:
            for entry in results:
                injected.append({
                    "pid": entry.get("PID"),
                    "process": entry.get("Process"),
                    "address": entry.get("Start VPN"),
                    "protection": entry.get("Protection"),
                    "hexdump": entry.get("Hexdump", "")[:200],
                })
                print(f"  [!] Injection in PID {entry.get('PID')} "
                      f"({entry.get('Process')}) at {entry.get('Start VPN')}")

        self.results["injected_processes"] = injected
        return injected

    def find_hidden_processes(self):
        """Compare pslist vs psscan to find hidden processes."""
        print("[+] Running process comparison (pslist vs psscan)")

        pslist = self.run_plugin("windows.pslist")
        psscan = self.run_plugin("windows.psscan")

        if not pslist or not psscan:
            return []

        list_pids = {e.get("PID") for e in pslist}
        scan_pids = {e.get("PID") for e in psscan}

        hidden = scan_pids - list_pids
        if hidden:
            print(f"  [!] {len(hidden)} hidden processes found!")
            for entry in psscan:
                if entry.get("PID") in hidden:
                    print(f"    PID {entry['PID']}: {entry.get('ImageFileName')}")

        self.results["hidden_processes"] = list(hidden)
        return list(hidden)

    def analyze_network(self):
        """Extract active network connections."""
        print("[+] Running windows.netscan")
        results = self.run_plugin("windows.netscan")

        connections = []
        if results:
            for entry in results:
                conn = {
                    "pid": entry.get("PID"),
                    "process": entry.get("Owner"),
                    "local": f"{entry.get('LocalAddr')}:{entry.get('LocalPort')}",
                    "remote": f"{entry.get('ForeignAddr')}:{entry.get('ForeignPort')}",
                    "state": entry.get("State"),
                    "protocol": entry.get("Proto"),
                }
                connections.append(conn)

        self.results["network_connections"] = connections
        return connections

    def extract_dlls(self, pid=None):
        """List loaded DLLs per process."""
        print(f"[+] Running windows.dlllist{f' (PID {pid})' if pid else ''}")
        args = ["--pid", str(pid)] if pid else None
        results = self.run_plugin("windows.dlllist", args)

        dlls = []
        if results:
            for entry in results:
                dlls.append({
                    "pid": entry.get("PID"),
                    "process": entry.get("Process"),
                    "base": entry.get("Base"),
                    "name": entry.get("Name"),
                    "path": entry.get("Path"),
                    "size": entry.get("Size"),
                })

        self.results["loaded_dlls"] = dlls
        return dlls

    def scan_with_yara(self, rules_path):
        """Scan memory with YARA rules."""
        print(f"[+] Running windows.yarascan with {rules_path}")
        results = self.run_plugin(
            "windows.yarascan",
            ["--yara-file", rules_path]
        )

        matches = []
        if results:
            for entry in results:
                matches.append({
                    "rule": entry.get("Rule"),
                    "pid": entry.get("PID"),
                    "process": entry.get("Process"),
                    "offset": entry.get("Offset"),
                })

        self.results["yara_matches"] = matches
        return matches

    def full_triage(self):
        """Run full malware-focused memory triage."""
        print(f"[*] Full memory triage: {self.dump_path}")
        print("=" * 60)

        self.detect_process_injection()
        self.find_hidden_processes()
        self.analyze_network()

        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <memory_dump>")
        sys.exit(1)

    analyzer = Vol3Analyzer(sys.argv[1])
    results = analyzer.full_triage()
    print(json.dumps(results, indent=2, default=str))
```

## Validation Criteria

- Memory dump successfully parsed with correct OS profile
- Injected processes detected via malfind with RWX regions
- Hidden processes identified through pslist/psscan comparison
- Network connections reveal C2 communication endpoints
- YARA rules match known malware signatures in memory
- Credential artifacts extracted from lsass process memory

## References

- [Volatility Foundation](https://volatilityfoundation.org/)
- [Volatility3 GitHub](https://github.com/volatilityfoundation/volatility3)
- [2024 Volatility Plugin Contest](https://volatilityfoundation.org/the-2024-volatility-plugin-contest-results-are-in/)
- [Memory Forensics with Volatility 3](https://newtonpaul.com/malware-analysis-memory-forensics-with-volatility-3/)
- [MITRE ATT&CK T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)
