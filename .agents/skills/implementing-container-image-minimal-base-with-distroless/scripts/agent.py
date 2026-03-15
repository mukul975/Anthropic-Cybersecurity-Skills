#!/usr/bin/env python3
"""Distroless container image analysis agent using Trivy for comparing image security posture."""

import argparse
import json
import logging
import os
import subprocess
import sys
from datetime import datetime
from typing import Dict, List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def run_trivy_scan(image: str) -> dict:
    """Scan image with Trivy and return JSON results."""
    cmd = ["trivy", "image", "--format", "json", "--severity", "CRITICAL,HIGH,MEDIUM", image]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.stdout:
            return json.loads(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        logger.error("Trivy scan failed for %s: %s", image, exc)
    return {}


def get_image_size(image: str) -> int:
    """Get image size using docker inspect."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.Size}}", image],
            capture_output=True, text=True, timeout=30)
        return int(result.stdout.strip()) if result.stdout.strip() else 0
    except (FileNotFoundError, ValueError):
        return 0


def count_packages(scan_data: dict) -> int:
    """Count total packages found in Trivy scan."""
    count = 0
    for result in scan_data.get("Results", []):
        count += len(result.get("Vulnerabilities", []))
    return count


def count_vulns_by_severity(scan_data: dict) -> dict:
    """Count vulnerabilities by severity from Trivy results."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for result in scan_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "").upper()
            if sev in counts:
                counts[sev] += 1
    counts["total"] = sum(counts.values())
    return counts


def compare_images(base_image: str, distroless_image: str) -> dict:
    """Compare a standard base image against its distroless equivalent."""
    base_scan = run_trivy_scan(base_image)
    distroless_scan = run_trivy_scan(distroless_image)
    base_vulns = count_vulns_by_severity(base_scan)
    distroless_vulns = count_vulns_by_severity(distroless_scan)
    base_size = get_image_size(base_image)
    distroless_size = get_image_size(distroless_image)
    size_reduction = ((base_size - distroless_size) / base_size * 100) if base_size else 0
    vuln_reduction = ((base_vulns["total"] - distroless_vulns["total"]) / base_vulns["total"] * 100) if base_vulns["total"] else 0
    return {
        "base_image": {"image": base_image, "size_bytes": base_size, "vulnerabilities": base_vulns},
        "distroless_image": {"image": distroless_image, "size_bytes": distroless_size, "vulnerabilities": distroless_vulns},
        "size_reduction_pct": round(size_reduction, 1),
        "vuln_reduction_pct": round(vuln_reduction, 1),
    }


def check_distroless_properties(image: str) -> dict:
    """Check if an image exhibits distroless properties (no shell, no package manager)."""
    checks = {"has_shell": False, "has_package_manager": False, "has_user": False}
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "", image, "sh", "-c", "echo shell_exists"],
            capture_output=True, text=True, timeout=10)
        checks["has_shell"] = "shell_exists" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    try:
        for pm in ["apt", "apk", "yum", "dnf"]:
            result = subprocess.run(
                ["docker", "run", "--rm", "--entrypoint", "", image, "which", pm],
                capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                checks["has_package_manager"] = True
                break
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return checks


def generate_report(images: List[str], distroless_pairs: Dict[str, str] = None) -> dict:
    """Generate distroless adoption report."""
    report = {"analysis_date": datetime.utcnow().isoformat(), "image_scans": [], "comparisons": []}
    for image in images:
        scan = run_trivy_scan(image)
        vulns = count_vulns_by_severity(scan)
        props = check_distroless_properties(image)
        report["image_scans"].append({
            "image": image, "vulnerabilities": vulns, "properties": props,
            "is_minimal": not props["has_shell"] and not props["has_package_manager"],
        })
    if distroless_pairs:
        for base, distroless in distroless_pairs.items():
            report["comparisons"].append(compare_images(base, distroless))
    report["summary"] = {
        "images_scanned": len(images),
        "minimal_images": sum(1 for s in report["image_scans"] if s["is_minimal"]),
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="Distroless Container Image Analysis Agent")
    parser.add_argument("--images", nargs="+", required=True, help="Images to analyze")
    parser.add_argument("--compare", nargs=2, action="append", metavar=("BASE", "DISTROLESS"),
                        help="Compare base vs distroless pairs")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--output", default="distroless_report.json")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    pairs = {c[0]: c[1] for c in args.compare} if args.compare else None
    report = generate_report(args.images, pairs)
    out_path = os.path.join(args.output_dir, args.output)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", out_path)
    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
