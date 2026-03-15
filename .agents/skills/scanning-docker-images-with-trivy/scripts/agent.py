#!/usr/bin/env python3
"""Agent for scanning Docker images with Trivy.

Performs comprehensive vulnerability scanning of Docker images
including OS packages, language dependencies, misconfigurations,
secrets, and license compliance using Trivy CLI.
"""

import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime


class TrivyDockerAgent:
    """Scans Docker images using Trivy for vulnerabilities and misconfigs."""

    def __init__(self, output_dir="./trivy_docker"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.scan_results = []

    def _run(self, cmd, timeout=300):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout, result.stderr, result.returncode
        except FileNotFoundError:
            return "", "trivy not found", -1
        except subprocess.TimeoutExpired:
            return "", "timeout", -2

    def scan_image(self, image_ref, scanners="vuln", severity=None,
                   ignore_unfixed=False):
        """Scan a Docker image with specified scanners."""
        cmd = ["trivy", "image", "--format", "json", "--quiet",
               "--scanners", scanners]
        if severity:
            cmd.extend(["--severity", severity])
        if ignore_unfixed:
            cmd.append("--ignore-unfixed")
        cmd.append(image_ref)

        stdout, stderr, rc = self._run(cmd)
        if rc < 0:
            return {"error": stderr}

        try:
            raw = json.loads(stdout) if stdout.strip() else {}
        except json.JSONDecodeError:
            return {"error": "Failed to parse trivy output"}

        vulns = []
        misconfigs = []
        secrets = []
        for result in raw.get("Results", []):
            target = result.get("Target", "")
            for v in result.get("Vulnerabilities", []):
                vulns.append({
                    "id": v.get("VulnerabilityID"),
                    "severity": v.get("Severity"),
                    "package": v.get("PkgName"),
                    "installed": v.get("InstalledVersion"),
                    "fixed": v.get("FixedVersion", ""),
                    "target": target,
                })
            for mc in result.get("Misconfigurations", []):
                misconfigs.append({
                    "id": mc.get("ID"),
                    "severity": mc.get("Severity"),
                    "title": mc.get("Title"),
                    "target": target,
                })
            for s in result.get("Secrets", []):
                secrets.append({
                    "rule_id": s.get("RuleID"),
                    "severity": s.get("Severity"),
                    "title": s.get("Title"),
                    "target": target,
                })

        summary = {}
        for v in vulns:
            sev = v["severity"] or "UNKNOWN"
            summary[sev] = summary.get(sev, 0) + 1

        scan = {
            "image": image_ref,
            "scan_date": datetime.utcnow().isoformat(),
            "scanners": scanners,
            "vulnerability_count": len(vulns),
            "misconfig_count": len(misconfigs),
            "secret_count": len(secrets),
            "severity_summary": summary,
            "vulnerabilities": vulns,
            "misconfigurations": misconfigs,
            "secrets": secrets,
        }
        self.scan_results.append(scan)
        return scan

    def scan_tar(self, tar_path, severity=None):
        """Scan a saved Docker image tar archive."""
        cmd = ["trivy", "image", "--format", "json", "--quiet",
               "--input", tar_path]
        if severity:
            cmd.extend(["--severity", severity])
        stdout, stderr, rc = self._run(cmd)
        if rc < 0:
            return {"error": stderr}
        try:
            return json.loads(stdout) if stdout.strip() else {}
        except json.JSONDecodeError:
            return {"error": "Parse error"}

    def generate_sbom(self, image_ref, fmt="cyclonedx"):
        """Generate SBOM for image in CycloneDX or SPDX format."""
        trivy_fmt = "cyclonedx" if fmt == "cyclonedx" else "spdx-json"
        ext = "cdx" if fmt == "cyclonedx" else "spdx"
        out_file = self.output_dir / f"sbom.{ext}.json"
        cmd = ["trivy", "image", "--format", trivy_fmt,
               "--output", str(out_file), image_ref]
        _, stderr, rc = self._run(cmd)
        if rc == 0:
            return {"sbom_path": str(out_file), "format": fmt}
        return {"error": stderr}

    def check_version(self):
        """Return Trivy version info."""
        stdout, _, _ = self._run(["trivy", "version"], timeout=15)
        return {"version": stdout.strip()}

    def generate_report(self):
        report = {
            "report_date": datetime.utcnow().isoformat(),
            "images_scanned": len(self.scan_results),
            "scans": self.scan_results,
        }
        out = self.output_dir / "trivy_docker_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <image_ref> [--scanners vuln,misconfig,secret]")
        sys.exit(1)

    image = sys.argv[1]
    scanners = "vuln"
    if "--scanners" in sys.argv:
        idx = sys.argv.index("--scanners")
        if idx + 1 < len(sys.argv):
            scanners = sys.argv[idx + 1]

    agent = TrivyDockerAgent()
    agent.scan_image(image, scanners=scanners)
    agent.generate_report()


if __name__ == "__main__":
    main()
