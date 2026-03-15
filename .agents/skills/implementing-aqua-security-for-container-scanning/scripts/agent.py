#!/usr/bin/env python3
"""Container image vulnerability scanning agent using Trivy CLI via subprocess."""

import argparse
import json
import logging
import os
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def check_trivy_installed() -> bool:
    """Check if Trivy CLI is available."""
    try:
        result = subprocess.run(["trivy", "--version"], capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def scan_image(image: str, severity: str = "CRITICAL,HIGH",
               ignore_unfixed: bool = True) -> dict:
    """Scan a container image for vulnerabilities using Trivy."""
    cmd = ["trivy", "image", "--format", "json", "--severity", severity, image]
    if ignore_unfixed:
        cmd.append("--ignore-unfixed")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.stdout:
            return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        logger.error("Trivy scan failed for %s: %s", image, exc)
    return {}


def scan_image_misconfig(image: str) -> dict:
    """Scan a container image for misconfigurations."""
    cmd = ["trivy", "image", "--format", "json", "--scanners", "misconfig", image]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.stdout:
            return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        logger.error("Misconfig scan failed: %s", exc)
    return {}


def scan_image_secrets(image: str) -> dict:
    """Scan a container image for embedded secrets."""
    cmd = ["trivy", "image", "--format", "json", "--scanners", "secret", image]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.stdout:
            return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        logger.error("Secret scan failed: %s", exc)
    return {}


def generate_sbom(image: str, output_path: str) -> bool:
    """Generate SBOM in CycloneDX format for an image."""
    cmd = ["trivy", "image", "--format", "cyclonedx", "--output", output_path, image]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def parse_vuln_results(scan_data: dict) -> List[dict]:
    """Parse Trivy JSON output into structured vulnerability list."""
    vulns = []
    for result in scan_data.get("Results", []):
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []):
            vulns.append({
                "target": target,
                "vuln_id": vuln.get("VulnerabilityID", ""),
                "pkg_name": vuln.get("PkgName", ""),
                "installed": vuln.get("InstalledVersion", ""),
                "fixed": vuln.get("FixedVersion", ""),
                "severity": vuln.get("Severity", ""),
                "title": vuln.get("Title", ""),
            })
    return vulns


def compute_summary(vulns: List[dict]) -> dict:
    """Compute severity summary from vulnerability list."""
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulns:
        sev = v.get("severity", "").upper()
        if sev in summary:
            summary[sev] += 1
    summary["total"] = len(vulns)
    fixable = sum(1 for v in vulns if v.get("fixed"))
    summary["fixable"] = fixable
    return summary


def scan_multiple_images(images: List[str], severity: str) -> dict:
    """Scan multiple container images and aggregate results."""
    report = {"scan_date": datetime.utcnow().isoformat(), "images": []}
    for image in images:
        logger.info("Scanning %s...", image)
        scan_data = scan_image(image, severity)
        vulns = parse_vuln_results(scan_data)
        report["images"].append({
            "image": image, "vulnerabilities": vulns,
            "summary": compute_summary(vulns),
        })
    totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0}
    for img in report["images"]:
        for k in totals:
            totals[k] += img["summary"].get(k, 0)
    report["overall_summary"] = totals
    return report


def main():
    parser = argparse.ArgumentParser(description="Container Image Vulnerability Scanner (Trivy)")
    parser.add_argument("--images", nargs="+", required=True, help="Container images to scan")
    parser.add_argument("--severity", default="CRITICAL,HIGH", help="Severity filter")
    parser.add_argument("--sbom", action="store_true", help="Generate SBOM for each image")
    parser.add_argument("--output-dir", default=".", help="Output directory")
    parser.add_argument("--output", default="trivy_report.json")
    args = parser.parse_args()

    if not check_trivy_installed():
        logger.error("Trivy CLI not found. Install: https://aquasecurity.github.io/trivy/")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)
    report = scan_multiple_images(args.images, args.severity)

    if args.sbom:
        for image in args.images:
            sbom_name = image.replace("/", "_").replace(":", "_") + "_sbom.json"
            sbom_path = os.path.join(args.output_dir, sbom_name)
            generate_sbom(image, sbom_path)

    out_path = os.path.join(args.output_dir, args.output)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", out_path)
    print(json.dumps(report["overall_summary"], indent=2))


if __name__ == "__main__":
    main()
