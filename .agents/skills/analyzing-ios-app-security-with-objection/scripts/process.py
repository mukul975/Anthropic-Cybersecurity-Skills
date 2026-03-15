#!/usr/bin/env python3
"""
Objection iOS Security Assessment Automation

Automates common Objection commands for iOS app security testing.
Runs keychain dump, storage inspection, SSL pinning check, and jailbreak detection analysis.

Usage:
    python process.py --bundle-id com.target.app [--device-id UDID] [--output report.json]
"""

import argparse
import json
import subprocess
import sys
import re
from datetime import datetime
from pathlib import Path


class ObjectionAssessor:
    """Automates Objection-based iOS security assessment tasks."""

    def __init__(self, bundle_id: str, device_id: str = None):
        self.bundle_id = bundle_id
        self.device_id = device_id
        self.findings = []

    def _run_objection_command(self, command: str, timeout: int = 30) -> str:
        """Execute an Objection command and return output."""
        cmd = ["objection", "--gadget", self.bundle_id, "run", command]
        if self.device_id:
            cmd.insert(1, "--serial")
            cmd.insert(2, self.device_id)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return f"TIMEOUT: Command '{command}' exceeded {timeout}s"
        except FileNotFoundError:
            return "ERROR: Objection not found. Install with: pip install objection"

    def _run_frida_command(self, script: str, timeout: int = 15) -> str:
        """Execute a Frida script snippet."""
        cmd = ["frida", "-U", "-n", self.bundle_id, "-e", script]
        if self.device_id:
            cmd.extend(["-D", self.device_id])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    def check_frida_connectivity(self) -> dict:
        """Verify Frida can connect to the device."""
        cmd = ["frida-ps", "-U"]
        if self.device_id:
            cmd.extend(["-D", self.device_id])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            connected = result.returncode == 0
            processes = len(result.stdout.strip().split("\n")) - 1 if connected else 0
            return {
                "connected": connected,
                "process_count": processes,
                "target_running": self.bundle_id in result.stdout,
            }
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return {"connected": False, "process_count": 0, "target_running": False}

    def dump_keychain(self) -> dict:
        """Dump keychain items accessible to the app."""
        output = self._run_objection_command("ios keychain dump")
        items = []
        current_item = {}

        for line in output.split("\n"):
            line = line.strip()
            if "Service" in line and ":" in line:
                if current_item:
                    items.append(current_item)
                current_item = {"service": line.split(":", 1)[-1].strip()}
            elif "Account" in line and ":" in line:
                current_item["account"] = line.split(":", 1)[-1].strip()
            elif "Data" in line and ":" in line:
                data = line.split(":", 1)[-1].strip()
                current_item["data_preview"] = data[:50] + "..." if len(data) > 50 else data
                current_item["data_length"] = len(data)

        if current_item:
            items.append(current_item)

        finding = {
            "check": "keychain_dump",
            "category": "MASVS-STORAGE",
            "owasp_mobile": "M9",
            "items_found": len(items),
            "items": items[:20],
            "severity": "HIGH" if items else "INFO",
            "description": f"Found {len(items)} keychain items accessible to the application",
        }
        self.findings.append(finding)
        return finding

    def check_nsuserdefaults(self) -> dict:
        """Inspect NSUserDefaults for sensitive data."""
        output = self._run_objection_command("ios nsuserdefaults get")
        sensitive_patterns = [
            "password", "token", "secret", "key", "auth",
            "session", "credential", "api_key", "apikey",
        ]

        sensitive_entries = []
        for line in output.split("\n"):
            line_lower = line.lower()
            for pattern in sensitive_patterns:
                if pattern in line_lower:
                    sensitive_entries.append(line.strip())
                    break

        finding = {
            "check": "nsuserdefaults",
            "category": "MASVS-STORAGE",
            "owasp_mobile": "M9",
            "sensitive_entries": len(sensitive_entries),
            "entries": sensitive_entries[:10],
            "severity": "HIGH" if sensitive_entries else "PASS",
            "description": f"Found {len(sensitive_entries)} potentially sensitive NSUserDefaults entries",
        }
        self.findings.append(finding)
        return finding

    def check_ssl_pinning(self) -> dict:
        """Assess SSL pinning implementation."""
        output = self._run_objection_command("ios sslpinning disable")
        pinning_detected = "pinning" in output.lower() or "hook" in output.lower()

        finding = {
            "check": "ssl_pinning",
            "category": "MASVS-NETWORK",
            "owasp_mobile": "M5",
            "pinning_detected": pinning_detected,
            "bypass_output": output[:500],
            "severity": "MEDIUM" if not pinning_detected else "INFO",
            "description": "SSL pinning " + ("detected and bypassed" if pinning_detected else "not detected"),
        }
        self.findings.append(finding)
        return finding

    def check_jailbreak_detection(self) -> dict:
        """Assess jailbreak detection implementation."""
        output = self._run_objection_command("ios jailbreak disable")
        detection_found = "hook" in output.lower() or "bypass" in output.lower()

        finding = {
            "check": "jailbreak_detection",
            "category": "MASVS-RESILIENCE",
            "owasp_mobile": "M7",
            "detection_implemented": detection_found,
            "bypass_output": output[:500],
            "severity": "MEDIUM" if not detection_found else "INFO",
            "description": "Jailbreak detection " + ("found" if detection_found else "not found or not implemented"),
        }
        self.findings.append(finding)
        return finding

    def search_sensitive_memory(self) -> dict:
        """Search app memory for sensitive strings."""
        patterns = ["password", "Bearer ", "eyJ", "api_key", "secret"]
        memory_findings = []

        for pattern in patterns:
            output = self._run_objection_command(f'memory search "{pattern}" --string')
            matches = output.count("Found")
            if matches > 0:
                memory_findings.append({
                    "pattern": pattern,
                    "matches": matches,
                })

        finding = {
            "check": "memory_search",
            "category": "MASVS-STORAGE",
            "owasp_mobile": "M9",
            "patterns_with_matches": len(memory_findings),
            "details": memory_findings,
            "severity": "HIGH" if memory_findings else "PASS",
            "description": f"Found sensitive patterns in memory for {len(memory_findings)} search terms",
        }
        self.findings.append(finding)
        return finding

    def get_app_info(self) -> dict:
        """Gather basic app information."""
        output = self._run_objection_command("ios info binary")
        env_output = self._run_objection_command("env")

        return {
            "bundle_id": self.bundle_id,
            "binary_info": output[:1000],
            "environment": env_output[:1000],
        }

    def generate_report(self) -> dict:
        """Generate consolidated assessment report."""
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "PASS": 0}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "assessment": {
                "target": self.bundle_id,
                "date": datetime.now().isoformat(),
                "tool": "Objection (Frida-powered)",
                "type": "iOS Runtime Security Assessment",
            },
            "summary": {
                "total_checks": len(self.findings),
                "severity_breakdown": severity_counts,
                "critical_findings": [
                    f for f in self.findings if f.get("severity") in ("HIGH", "CRITICAL")
                ],
            },
            "findings": self.findings,
        }


def main():
    parser = argparse.ArgumentParser(
        description="Objection iOS Security Assessment Automation"
    )
    parser.add_argument("--bundle-id", required=True, help="iOS app bundle identifier")
    parser.add_argument("--device-id", help="Device UDID for targeting specific device")
    parser.add_argument("--output", default="objection_report.json", help="Output report path")
    parser.add_argument("--checks", nargs="+",
                        default=["keychain", "nsuserdefaults", "ssl", "jailbreak", "memory"],
                        help="Checks to run")
    args = parser.parse_args()

    assessor = ObjectionAssessor(args.bundle_id, args.device_id)

    # Verify connectivity
    connectivity = assessor.check_frida_connectivity()
    if not connectivity["connected"]:
        print("[-] ERROR: Cannot connect to device via Frida")
        print("    Ensure Frida server is running on device or IPA is patched")
        sys.exit(1)

    print(f"[+] Connected to device. Target running: {connectivity['target_running']}")

    # Run selected checks
    check_map = {
        "keychain": assessor.dump_keychain,
        "nsuserdefaults": assessor.check_nsuserdefaults,
        "ssl": assessor.check_ssl_pinning,
        "jailbreak": assessor.check_jailbreak_detection,
        "memory": assessor.search_sensitive_memory,
    }

    for check in args.checks:
        if check in check_map:
            print(f"[*] Running check: {check}")
            result = check_map[check]()
            print(f"    Severity: {result['severity']} - {result['description']}")

    # Generate report
    report = assessor.generate_report()

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Report saved: {args.output}")

    # Summary
    high_count = report["summary"]["severity_breakdown"].get("HIGH", 0)
    if high_count > 0:
        print(f"[!] {high_count} HIGH severity findings require attention")


if __name__ == "__main__":
    main()
