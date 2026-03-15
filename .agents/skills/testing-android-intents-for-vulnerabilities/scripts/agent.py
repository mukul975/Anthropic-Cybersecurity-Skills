#!/usr/bin/env python3
"""Agent for testing Android intents for vulnerabilities.

Uses ADB and Drozer to enumerate exported components, test
intent injection, content provider SQL injection, broadcast
receiver abuse, and pending intent hijacking vulnerabilities.
"""

import json
import subprocess
import re
import sys
from pathlib import Path
from datetime import datetime


class AndroidIntentTestAgent:
    """Tests Android app IPC through intents for security flaws."""

    def __init__(self, package_name, output_dir="./android_intent_test"):
        self.package = package_name
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def _adb(self, args, timeout=15):
        cmd = ["adb", "shell"] + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout.strip(), result.returncode
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return "", -1

    def _drozer(self, module, args=""):
        cmd_str = f"run {module} -a {self.package} {args}".strip()
        cmd = ["drozer", "console", "connect", "-c", cmd_str]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return ""

    def enumerate_attack_surface(self):
        """Enumerate exported components via Drozer."""
        output = self._drozer("app.package.attacksurface")
        surface = {"activities": 0, "services": 0, "receivers": 0, "providers": 0}

        for m in re.finditer(r"(\d+)\s+(activities|broadcast receivers|content providers|services)\s+exported", output):
            count = int(m.group(1))
            comp_type = m.group(2)
            if "activities" in comp_type:
                surface["activities"] = count
            elif "services" in comp_type:
                surface["services"] = count
            elif "receivers" in comp_type:
                surface["receivers"] = count
            elif "providers" in comp_type:
                surface["providers"] = count

        total = sum(surface.values())
        if total > 0:
            self.findings.append({
                "severity": "info",
                "type": "Attack Surface",
                "detail": f"{total} exported components found",
                "breakdown": surface,
            })
        return surface

    def list_exported_activities(self):
        """List exported activities."""
        output = self._drozer("app.activity.info")
        activities = []
        for m in re.finditer(r"([\w.]+/[\w.$]+)", output):
            activities.append(m.group(1))
        return activities

    def test_activity_access(self, activity_name):
        """Test if an exported activity is accessible without auth."""
        output, rc = self._adb(["am", "start", "-n", f"{self.package}/{activity_name}"])
        accessible = "Error" not in output and rc == 0
        if accessible:
            self.findings.append({
                "severity": "high",
                "type": "Exported Activity Access",
                "detail": f"Activity {activity_name} accessible without authentication",
            })
        return {"activity": activity_name, "accessible": accessible, "output": output[:200]}

    def test_content_provider_query(self, uri):
        """Test content provider for data leakage."""
        output = self._drozer("app.provider.query", uri)
        has_data = bool(output) and "No results" not in output and "error" not in output.lower()
        if has_data:
            self.findings.append({
                "severity": "high",
                "type": "Content Provider Data Leakage",
                "detail": f"Data accessible via {uri}",
            })
        return {"uri": uri, "has_data": has_data, "preview": output[:300]}

    def test_sql_injection(self, uri):
        """Test content provider for SQL injection."""
        output = self._drozer("scanner.provider.injection")
        injectable = "Injectable" in output or "injection" in output.lower()
        if injectable:
            self.findings.append({
                "severity": "critical",
                "type": "Content Provider SQL Injection",
                "detail": f"SQL injection possible in {self.package}",
            })
        return {"package": self.package, "injectable": injectable}

    def test_path_traversal(self):
        """Test content providers for path traversal."""
        output = self._drozer("scanner.provider.traversal")
        vulnerable = "Vulnerable" in output or "traversal" in output.lower()
        if vulnerable:
            self.findings.append({
                "severity": "critical",
                "type": "Content Provider Path Traversal",
                "detail": f"Path traversal in {self.package}",
            })
        return {"vulnerable": vulnerable}

    def send_broadcast(self, action, extras=None):
        """Send broadcast to test exported receivers."""
        cmd = ["am", "broadcast", "-a", action, "-p", self.package]
        if extras:
            for key, val in extras.items():
                cmd.extend(["--es", key, val])
        output, rc = self._adb(cmd)
        return {"action": action, "result": output[:200], "returncode": rc}

    def check_debuggable(self):
        """Check if app is debuggable."""
        output, _ = self._adb(["run-as", self.package, "id"])
        debuggable = "uid=" in output
        if debuggable:
            self.findings.append({
                "severity": "high",
                "type": "Debuggable Application",
                "detail": f"{self.package} is debuggable",
            })
        return debuggable

    def generate_report(self):
        surface = self.enumerate_attack_surface()
        activities = self.list_exported_activities()
        self.check_debuggable()
        self.test_sql_injection("")
        self.test_path_traversal()

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "package": self.package,
            "attack_surface": surface,
            "exported_activities": activities,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "android_intent_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <package_name>")
        sys.exit(1)
    agent = AndroidIntentTestAgent(sys.argv[1])
    agent.generate_report()


if __name__ == "__main__":
    main()
