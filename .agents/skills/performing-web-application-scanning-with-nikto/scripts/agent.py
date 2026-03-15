#!/usr/bin/env python3
"""Agent for web application scanning with Nikto.

Runs Nikto via subprocess for web server vulnerability scanning,
parses XML/JSON output, classifies findings by OSVDB/CVE, and
generates a structured security assessment report.
"""

import subprocess
import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path


class NiktoScanAgent:
    """Automates Nikto web vulnerability scanning and reporting."""

    def __init__(self, target, output_dir="./nikto_scans"):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def run_scan(self, ports="80,443", tuning=None, plugins=None,
                 ssl_mode=False, timeout=600):
        """Execute Nikto scan against the target."""
        xml_output = self.output_dir / f"nikto_{self.target.replace('/', '_')}.xml"
        cmd = ["nikto", "-h", self.target, "-port", ports,
               "-Format", "xml", "-output", str(xml_output), "-nointeractive"]
        if ssl_mode:
            cmd.extend(["-ssl"])
        if tuning:
            cmd.extend(["-Tuning", tuning])
        if plugins:
            cmd.extend(["-Plugins", plugins])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=timeout)
            return {"return_code": result.returncode,
                    "xml_output": str(xml_output),
                    "stderr": result.stderr[:500] if result.stderr else ""}
        except FileNotFoundError:
            return {"error": "nikto not installed. Install: apt install nikto"}
        except subprocess.TimeoutExpired:
            return {"error": f"Scan timed out after {timeout}s"}

    def parse_xml_results(self, xml_path=None):
        """Parse Nikto XML output into structured findings."""
        if xml_path is None:
            xml_path = self.output_dir / f"nikto_{self.target.replace('/', '_')}.xml"
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
        except (ET.ParseError, FileNotFoundError) as exc:
            return {"error": str(exc)}

        for item in root.iter("item"):
            finding = {
                "id": item.get("id", ""),
                "osvdb": item.get("osvdbid", ""),
                "method": item.get("method", "GET"),
                "uri": "",
                "description": "",
                "references": [],
            }
            uri_elem = item.find("uri")
            if uri_elem is not None:
                finding["uri"] = uri_elem.text or ""
            desc_elem = item.find("description")
            if desc_elem is not None:
                finding["description"] = desc_elem.text or ""

            desc_lower = finding["description"].lower()
            if any(kw in desc_lower for kw in ["remote code", "rce", "command injection"]):
                finding["severity"] = "Critical"
            elif any(kw in desc_lower for kw in ["sql injection", "xss", "file inclusion"]):
                finding["severity"] = "High"
            elif any(kw in desc_lower for kw in ["directory listing", "information disclosure"]):
                finding["severity"] = "Medium"
            else:
                finding["severity"] = "Low"

            self.findings.append(finding)
        return self.findings

    def run_quick_scan(self, timeout=300):
        """Run a fast Nikto scan with essential checks only."""
        cmd = ["nikto", "-h", self.target, "-Tuning", "123", "-maxtime",
               str(timeout) + "s", "-nointeractive"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=timeout + 30)
            lines = result.stdout.splitlines()
            for line in lines:
                if "+ " in line and "OSVDB" in line:
                    self.findings.append({
                        "description": line.strip().lstrip("+ "),
                        "severity": "Medium", "source": "stdout",
                    })
            return {"lines": len(lines), "findings": len(self.findings)}
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return {"error": str(exc)}

    def generate_report(self):
        """Generate scan report with severity distribution."""
        severity_counts = {}
        for f in self.findings:
            sev = f.get("severity", "Info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        report = {
            "target": self.target,
            "scan_date": datetime.utcnow().isoformat(),
            "total_findings": len(self.findings),
            "severity_distribution": severity_counts,
            "findings": self.findings[:100],
        }
        report_path = self.output_dir / "nikto_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost"
    agent = NiktoScanAgent(target)
    result = agent.run_scan()
    if "error" not in result:
        agent.parse_xml_results()
    else:
        agent.run_quick_scan()
    agent.generate_report()


if __name__ == "__main__":
    main()
