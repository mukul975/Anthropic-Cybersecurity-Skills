#!/usr/bin/env python3
"""Agent for scanning containers with Trivy in CI/CD pipelines.

Runs Trivy vulnerability and misconfiguration scans against
container images and Dockerfiles, enforces severity-based
quality gates, and generates CI/CD-compatible reports.
"""

import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime


class TrivyCICDAgent:
    """Integrates Trivy scanning into CI/CD workflows."""

    def __init__(self, output_dir="./trivy_cicd"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.scan_results = []

    def _run_trivy(self, subcmd, target, extra_args=None):
        """Execute trivy CLI and return parsed results."""
        cmd = ["trivy", subcmd, "--format", "json", "--quiet"]
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(target)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.stdout.strip():
                return json.loads(result.stdout)
            return {"error": result.stderr.strip() or "No output"}
        except FileNotFoundError:
            return {"error": "trivy not found. Install from https://trivy.dev"}
        except subprocess.TimeoutExpired:
            return {"error": "Trivy scan timed out after 600 seconds"}
        except json.JSONDecodeError:
            return {"error": "Failed to parse trivy JSON output"}

    def scan_image(self, image_ref, severity="CRITICAL,HIGH", ignore_unfixed=True):
        """Scan a container image for vulnerabilities."""
        args = ["--severity", severity]
        if ignore_unfixed:
            args.append("--ignore-unfixed")
        raw = self._run_trivy("image", image_ref, args)
        if "error" in raw:
            return raw

        vulns = []
        for result in raw.get("Results", []):
            for v in result.get("Vulnerabilities", []):
                vulns.append({
                    "id": v.get("VulnerabilityID", ""),
                    "severity": v.get("Severity", "UNKNOWN"),
                    "package": v.get("PkgName", ""),
                    "installed": v.get("InstalledVersion", ""),
                    "fixed": v.get("FixedVersion", ""),
                    "title": v.get("Title", ""),
                })

        summary = {}
        for v in vulns:
            summary[v["severity"]] = summary.get(v["severity"], 0) + 1

        scan = {
            "image": image_ref,
            "scan_type": "vulnerability",
            "scan_date": datetime.utcnow().isoformat(),
            "total": len(vulns),
            "summary": summary,
            "vulnerabilities": vulns,
        }
        self.scan_results.append(scan)
        return scan

    def scan_config(self, path, severity="CRITICAL,HIGH"):
        """Scan Dockerfiles or IaC for misconfigurations."""
        args = ["--severity", severity]
        raw = self._run_trivy("config", path, args)
        if "error" in raw:
            return raw

        misconfigs = []
        for result in raw.get("Results", []):
            for mc in result.get("Misconfigurations", []):
                misconfigs.append({
                    "id": mc.get("ID", ""),
                    "severity": mc.get("Severity", "UNKNOWN"),
                    "title": mc.get("Title", ""),
                    "message": mc.get("Message", ""),
                    "resolution": mc.get("Resolution", ""),
                })

        scan = {
            "path": path,
            "scan_type": "misconfiguration",
            "scan_date": datetime.utcnow().isoformat(),
            "total": len(misconfigs),
            "misconfigurations": misconfigs,
        }
        self.scan_results.append(scan)
        return scan

    def generate_sbom(self, image_ref, sbom_format="cyclonedx"):
        """Generate an SBOM for a container image."""
        out_file = self.output_dir / f"sbom.{sbom_format}.json"
        cmd = ["trivy", "image", "--format", sbom_format,
               "--output", str(out_file), image_ref]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {"sbom_path": str(out_file)}
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return {"error": str(e)}

    def enforce_quality_gate(self, severity_threshold="HIGH"):
        """Check if any scan result exceeds the severity threshold."""
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        threshold_idx = sev_order.index(severity_threshold) if severity_threshold in sev_order else 0
        blocking_sevs = sev_order[:threshold_idx + 1]

        for scan in self.scan_results:
            summary = scan.get("summary", {})
            for sev in blocking_sevs:
                if summary.get(sev, 0) > 0:
                    return {"gate": "FAILED", "reason": f"{summary[sev]} {sev} findings in {scan.get('image', scan.get('path', ''))}"}
        return {"gate": "PASSED"}

    def generate_report(self):
        gate = self.enforce_quality_gate()
        report = {
            "report_date": datetime.utcnow().isoformat(),
            "scans": self.scan_results,
            "quality_gate": gate,
        }
        out = self.output_dir / "trivy_cicd_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <image_ref> [--config <path>] [--severity CRITICAL,HIGH]")
        sys.exit(1)

    agent = TrivyCICDAgent()
    image = sys.argv[1]
    severity = "CRITICAL,HIGH"
    if "--severity" in sys.argv:
        idx = sys.argv.index("--severity")
        if idx + 1 < len(sys.argv):
            severity = sys.argv[idx + 1]

    agent.scan_image(image, severity=severity)

    if "--config" in sys.argv:
        idx = sys.argv.index("--config")
        if idx + 1 < len(sys.argv):
            agent.scan_config(sys.argv[idx + 1], severity=severity)

    report = agent.generate_report()
    if report["quality_gate"]["gate"] == "FAILED":
        sys.exit(1)


if __name__ == "__main__":
    main()
