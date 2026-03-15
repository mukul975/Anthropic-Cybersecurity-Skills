#!/usr/bin/env python3
"""
Android Dynamic Analysis Automation

Automates common Frida/Objection dynamic analysis tasks on Android applications.
Enumerates attack surface, hooks sensitive methods, and extracts runtime data.

Usage:
    python process.py --package com.target.app [--device-id DEVICE] [--output report.json]
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


class AndroidDynamicAnalyzer:
    """Automates Android dynamic analysis using Frida and Objection."""

    def __init__(self, package: str, device_id: str = None):
        self.package = package
        self.device_id = device_id
        self.findings = []

    def _adb(self, cmd: str, timeout: int = 15) -> str:
        """Run ADB command."""
        full_cmd = ["adb"]
        if self.device_id:
            full_cmd.extend(["-s", self.device_id])
        full_cmd.extend(["shell"] + cmd.split())
        try:
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    def _objection(self, cmd: str, timeout: int = 20) -> str:
        """Run Objection command."""
        full_cmd = ["objection", "--gadget", self.package, "run", cmd]
        try:
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout + result.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    def _frida_script(self, script: str, timeout: int = 15) -> str:
        """Execute Frida JavaScript snippet."""
        cmd = ["frida", "-U", "-n", self.package, "-e", script, "--no-pause"]
        if self.device_id:
            cmd.extend(["-D", self.device_id])
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    def check_frida_server(self) -> bool:
        """Verify Frida server is running on device."""
        try:
            result = subprocess.run(
                ["frida-ps", "-U"] + (["-D", self.device_id] if self.device_id else []),
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def enumerate_components(self) -> dict:
        """Enumerate app exported components."""
        activities = self._objection("android hooking list activities")
        services = self._objection("android hooking list services")
        receivers = self._objection("android hooking list receivers")

        components = {
            "activities": [l.strip() for l in activities.split("\n") if l.strip() and not l.startswith("[")],
            "services": [l.strip() for l in services.split("\n") if l.strip() and not l.startswith("[")],
            "receivers": [l.strip() for l in receivers.split("\n") if l.strip() and not l.startswith("[")],
        }

        self.findings.append({
            "check": "component_enumeration",
            "category": "MASVS-PLATFORM",
            "total_activities": len(components["activities"]),
            "total_services": len(components["services"]),
            "total_receivers": len(components["receivers"]),
            "severity": "INFO",
        })
        return components

    def test_root_detection(self) -> dict:
        """Test root detection implementation."""
        output = self._objection("android root disable")
        detection_found = "hook" in output.lower() or "bypass" in output.lower()

        finding = {
            "check": "root_detection",
            "category": "MASVS-RESILIENCE",
            "owasp_mobile": "M7",
            "detection_present": detection_found,
            "bypass_successful": detection_found,
            "severity": "MEDIUM" if not detection_found else "INFO",
            "description": "Root detection " + ("found and bypassed" if detection_found else "not implemented"),
        }
        self.findings.append(finding)
        return finding

    def test_ssl_pinning(self) -> dict:
        """Test SSL certificate pinning."""
        output = self._objection("android sslpinning disable")
        pinning_found = "hook" in output.lower()

        finding = {
            "check": "ssl_pinning",
            "category": "MASVS-NETWORK",
            "owasp_mobile": "M5",
            "pinning_present": pinning_found,
            "severity": "MEDIUM" if not pinning_found else "INFO",
            "description": "SSL pinning " + ("detected" if pinning_found else "not detected"),
        }
        self.findings.append(finding)
        return finding

    def search_memory_secrets(self) -> dict:
        """Search process memory for sensitive strings."""
        patterns = ["password", "api_key", "secret", "Bearer ", "eyJ"]
        memory_hits = []

        for pattern in patterns:
            output = self._objection(f'memory search "{pattern}" --string')
            if "Found" in output:
                count = output.count("Found")
                memory_hits.append({"pattern": pattern, "matches": count})

        finding = {
            "check": "memory_secrets",
            "category": "MASVS-STORAGE",
            "owasp_mobile": "M9",
            "patterns_found": len(memory_hits),
            "details": memory_hits,
            "severity": "HIGH" if memory_hits else "PASS",
        }
        self.findings.append(finding)
        return finding

    def check_debug_mode(self) -> dict:
        """Check if app is running in debuggable mode."""
        output = self._adb(f"run-as {self.package} id")
        debuggable = "uid=" in output

        # Also check via package info
        pkg_info = self._adb(f"dumpsys package {self.package}")
        flag_debuggable = "FLAG_DEBUGGABLE" in pkg_info

        finding = {
            "check": "debug_mode",
            "category": "MASVS-RESILIENCE",
            "owasp_mobile": "M8",
            "run_as_works": debuggable,
            "flag_debuggable": flag_debuggable,
            "severity": "HIGH" if flag_debuggable else "PASS",
            "description": "App " + ("IS" if flag_debuggable else "is NOT") + " flagged as debuggable",
        }
        self.findings.append(finding)
        return finding

    def dump_keystore(self) -> dict:
        """Dump Android Keystore entries."""
        output = self._objection("android keystore list")

        finding = {
            "check": "keystore_dump",
            "category": "MASVS-CRYPTO",
            "owasp_mobile": "M10",
            "output": output[:2000],
            "severity": "INFO",
        }
        self.findings.append(finding)
        return finding

    def generate_report(self) -> dict:
        """Generate assessment report."""
        severity_counts = {}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "assessment": {
                "target": self.package,
                "type": "Android Dynamic Analysis",
                "date": datetime.now().isoformat(),
                "tools": ["Frida", "Objection", "ADB"],
            },
            "summary": {
                "total_checks": len(self.findings),
                "severity_breakdown": severity_counts,
            },
            "findings": self.findings,
        }


def main():
    parser = argparse.ArgumentParser(description="Android Dynamic Analysis Automation")
    parser.add_argument("--package", required=True, help="Target package name")
    parser.add_argument("--device-id", help="ADB device serial")
    parser.add_argument("--output", default="dynamic_analysis.json", help="Output report")
    args = parser.parse_args()

    analyzer = AndroidDynamicAnalyzer(args.package, args.device_id)

    if not analyzer.check_frida_server():
        print("[-] Frida server not reachable. Ensure it's running on the device.")
        sys.exit(1)

    print(f"[+] Starting dynamic analysis of {args.package}")

    print("[*] Enumerating components...")
    analyzer.enumerate_components()

    print("[*] Testing root detection...")
    analyzer.test_root_detection()

    print("[*] Testing SSL pinning...")
    analyzer.test_ssl_pinning()

    print("[*] Checking debug mode...")
    analyzer.check_debug_mode()

    print("[*] Searching memory for secrets...")
    analyzer.search_memory_secrets()

    print("[*] Dumping keystore...")
    analyzer.dump_keystore()

    report = analyzer.generate_report()
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[+] Report saved: {args.output}")
    print(f"[*] Findings: {report['summary']['severity_breakdown']}")


if __name__ == "__main__":
    main()
