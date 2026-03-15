#!/usr/bin/env python3
"""Agent for performing privilege escalation assessment.

Enumerates potential privilege escalation vectors on Linux systems
including SUID binaries, sudo misconfigurations, writable cron jobs,
capabilities, and kernel version checks.
"""

import subprocess
import json
import sys
import re
import platform
from pathlib import Path
from datetime import datetime


class PrivescAssessmentAgent:
    """Enumerates privilege escalation vectors on Linux systems."""

    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def _run(self, cmd, timeout=30):
        """Execute a shell command and return output."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    def get_system_info(self):
        """Gather system information for kernel exploit matching."""
        return {
            "hostname": self._run("hostname"),
            "kernel": self._run("uname -r"),
            "arch": self._run("uname -m"),
            "os_release": self._run("cat /etc/os-release 2>/dev/null | head -5"),
            "current_user": self._run("whoami"),
            "user_id": self._run("id"),
            "groups": self._run("groups"),
        }

    def check_sudo(self):
        """Check sudo configuration for escalation vectors."""
        sudo_l = self._run("sudo -l 2>/dev/null")
        findings = []

        gtfobins_dangerous = [
            "vim", "vi", "nano", "less", "more", "find", "nmap", "python",
            "python3", "perl", "ruby", "awk", "gawk", "env", "ftp",
            "man", "mount", "strace", "ltrace", "zip", "tar",
            "bash", "sh", "dash", "ash", "zsh", "tclsh",
        ]

        if "NOPASSWD" in sudo_l:
            for line in sudo_l.splitlines():
                if "NOPASSWD" in line:
                    for binary in gtfobins_dangerous:
                        if binary in line.lower():
                            finding = {
                                "type": "sudo_nopasswd",
                                "severity": "Critical",
                                "binary": binary,
                                "line": line.strip(),
                                "technique": "T1548.003",
                                "exploit": f"sudo {binary} (see GTFOBins)",
                            }
                            findings.append(finding)
                            self.findings.append(finding)
        return {"sudo_output": sudo_l, "dangerous_entries": findings}

    def find_suid_binaries(self):
        """Find SUID binaries that may allow escalation."""
        suid_output = self._run("find / -perm -4000 -type f 2>/dev/null")
        binaries = suid_output.splitlines()

        gtfobins_suid = [
            "nmap", "vim", "find", "bash", "more", "less", "nano",
            "cp", "mv", "python", "perl", "ruby", "env",
            "pkexec", "at", "strace", "taskset",
        ]

        findings = []
        for binary in binaries:
            name = Path(binary).name
            is_exploitable = name in gtfobins_suid
            if is_exploitable:
                finding = {
                    "type": "suid_binary",
                    "severity": "High",
                    "path": binary,
                    "name": name,
                    "technique": "T1548.001",
                    "exploit": f"SUID {name} (see GTFOBins)",
                }
                findings.append(finding)
                self.findings.append(finding)

        return {"total_suid": len(binaries), "exploitable": findings, "all_suid": binaries}

    def check_capabilities(self):
        """Find binaries with elevated Linux capabilities."""
        cap_output = self._run("getcap -r / 2>/dev/null")
        findings = []
        dangerous_caps = ["cap_setuid", "cap_dac_override", "cap_sys_admin",
                         "cap_sys_ptrace", "cap_net_raw"]

        for line in cap_output.splitlines():
            for cap in dangerous_caps:
                if cap in line:
                    finding = {
                        "type": "capability",
                        "severity": "High",
                        "line": line.strip(),
                        "capability": cap,
                        "technique": "T1548",
                    }
                    findings.append(finding)
                    self.findings.append(finding)
                    break
        return findings

    def check_writable_cron(self):
        """Check for writable cron jobs or scripts."""
        findings = []
        cron_paths = [
            "/etc/crontab", "/etc/cron.d", "/etc/cron.daily",
            "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly",
            "/var/spool/cron/crontabs",
        ]

        for cpath in cron_paths:
            p = Path(cpath)
            if p.is_file() and os.access(str(p), os.W_OK):
                finding = {
                    "type": "writable_cron",
                    "severity": "Critical",
                    "path": cpath,
                    "technique": "T1053.003",
                }
                findings.append(finding)
                self.findings.append(finding)
            elif p.is_dir():
                for f in p.iterdir():
                    if f.is_file():
                        content = f.read_text(errors="ignore")
                        for line in content.splitlines():
                            if line.strip() and not line.startswith("#"):
                                parts = line.split()
                                if len(parts) >= 6:
                                    script = parts[5]
                                    if Path(script).exists() and os.access(script, os.W_OK):
                                        finding = {
                                            "type": "writable_cron_script",
                                            "severity": "Critical",
                                            "cron_file": str(f),
                                            "script": script,
                                            "technique": "T1053.003",
                                        }
                                        findings.append(finding)
                                        self.findings.append(finding)
        return findings

    def check_writable_passwd(self):
        """Check if /etc/passwd or /etc/shadow is writable."""
        findings = []
        import os
        for path in ["/etc/passwd", "/etc/shadow"]:
            if os.path.exists(path) and os.access(path, os.W_OK):
                finding = {
                    "type": "writable_auth_file",
                    "severity": "Critical",
                    "path": path,
                    "technique": "T1078.003",
                    "exploit": f"Add root user to {path}",
                }
                findings.append(finding)
                self.findings.append(finding)
        return findings

    def check_kernel_exploits(self):
        """Match kernel version against known exploits."""
        kernel = self._run("uname -r")
        exploits = []

        known_vulns = [
            ("5.8", "5.16.11", "CVE-2022-0847", "DirtyPipe"),
            ("2.6.22", "4.8.3", "CVE-2016-5195", "DirtyCow"),
            ("4.6", "5.13", "CVE-2021-22555", "Netfilter heap OOB"),
        ]

        try:
            parts = kernel.split(".")
            major, minor = int(parts[0]), int(parts[1])
            patch = int(parts[2].split("-")[0]) if len(parts) > 2 else 0
        except (ValueError, IndexError):
            return exploits

        for min_ver, max_ver, cve, name in known_vulns:
            exploits.append({
                "cve": cve,
                "name": name,
                "affected_range": f"{min_ver} - {max_ver}",
                "kernel": kernel,
                "note": "Verify applicability before testing",
            })
        return exploits

    def generate_report(self):
        """Run all enumeration checks and generate report."""
        import os
        report = {
            "report_date": datetime.utcnow().isoformat(),
            "system_info": self.get_system_info(),
            "sudo_check": self.check_sudo(),
            "suid_binaries": self.find_suid_binaries(),
            "capabilities": self.check_capabilities(),
            "writable_cron": self.check_writable_cron(),
            "writable_auth": self.check_writable_passwd(),
            "kernel_exploits": self.check_kernel_exploits(),
            "total_findings": len(self.findings),
            "critical_findings": len([f for f in self.findings if f.get("severity") == "Critical"]),
            "high_findings": len([f for f in self.findings if f.get("severity") == "High"]),
        }

        report_path = self.output_dir / "privesc_assessment.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "./privesc_output"
    agent = PrivescAssessmentAgent(output_dir)
    agent.generate_report()


if __name__ == "__main__":
    main()
