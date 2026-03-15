#!/usr/bin/env python3
"""Agent for scanning container images with Anchore Grype.

Runs Grype CLI against container images, parses JSON results,
applies severity thresholds, and generates vulnerability reports
with remediation guidance.
"""

import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime


class GrypeScanAgent:
    """Scans container images for vulnerabilities using Grype."""

    def __init__(self, output_dir="./grype_scan"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results = []

    def _run_grype(self, target, extra_args=None):
        """Execute grype CLI and return parsed JSON output."""
        cmd = ["grype", target, "-o", "json", "--quiet"]
        if extra_args:
            cmd.extend(extra_args)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode not in (0, 1):
                return {"error": result.stderr.strip()}
            return json.loads(result.stdout) if result.stdout.strip() else {}
        except FileNotFoundError:
            return {"error": "grype not found. Install: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh"}
        except subprocess.TimeoutExpired:
            return {"error": "Scan timed out after 300 seconds"}
        except json.JSONDecodeError:
            return {"error": "Failed to parse grype JSON output"}

    def scan_image(self, image_ref, fail_on=None, only_fixed=False):
        """Scan a container image for vulnerabilities."""
        args = []
        if only_fixed:
            args.append("--only-fixed")
        raw = self._run_grype(image_ref, args)
        if "error" in raw:
            return raw

        matches = raw.get("matches", [])
        vulns = []
        for m in matches:
            vuln = m.get("vulnerability", {})
            artifact = m.get("artifact", {})
            vulns.append({
                "id": vuln.get("id", ""),
                "severity": vuln.get("severity", "Unknown"),
                "package": artifact.get("name", ""),
                "version": artifact.get("version", ""),
                "fixed_in": vuln.get("fix", {}).get("versions", []),
                "type": artifact.get("type", ""),
            })

        summary = self._summarize(vulns)
        scan_result = {
            "image": image_ref,
            "scan_date": datetime.utcnow().isoformat(),
            "total_vulnerabilities": len(vulns),
            "summary": summary,
            "vulnerabilities": vulns,
        }

        if fail_on:
            sev_order = ["Critical", "High", "Medium", "Low", "Negligible"]
            threshold_idx = sev_order.index(fail_on) if fail_on in sev_order else -1
            for sev in sev_order[:threshold_idx + 1]:
                if summary.get(sev, 0) > 0:
                    scan_result["gate_status"] = "FAILED"
                    break
            else:
                scan_result["gate_status"] = "PASSED"

        self.results.append(scan_result)
        return scan_result

    def scan_sbom(self, sbom_path):
        """Scan a pre-generated SBOM file."""
        return self._run_grype(f"sbom:{sbom_path}")

    def scan_directory(self, dir_path):
        """Scan a local directory for vulnerabilities."""
        return self._run_grype(f"dir:{dir_path}")

    def check_db_status(self):
        """Check Grype vulnerability database status."""
        try:
            result = subprocess.run(
                ["grype", "db", "status"], capture_output=True, text=True, timeout=30
            )
            return {"status": result.stdout.strip()}
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return {"error": str(e)}

    def _summarize(self, vulns):
        summary = {}
        for v in vulns:
            sev = v["severity"]
            summary[sev] = summary.get(sev, 0) + 1
        return summary

    def generate_report(self):
        report = {
            "report_date": datetime.utcnow().isoformat(),
            "scans": self.results,
            "total_images": len(self.results),
        }
        out = self.output_dir / "grype_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <image_ref> [--fail-on critical|high|medium]")
        sys.exit(1)

    image = sys.argv[1]
    fail_on = None
    if "--fail-on" in sys.argv:
        idx = sys.argv.index("--fail-on")
        if idx + 1 < len(sys.argv):
            fail_on = sys.argv[idx + 1].capitalize()

    agent = GrypeScanAgent()
    result = agent.scan_image(image, fail_on=fail_on)
    agent.generate_report()

    if result.get("gate_status") == "FAILED":
        sys.exit(1)


if __name__ == "__main__":
    main()
