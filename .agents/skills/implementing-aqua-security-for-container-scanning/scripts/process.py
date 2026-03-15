#!/usr/bin/env python3
"""
Trivy Container Scanning Report Aggregator

Processes Trivy JSON scan results and generates consolidated
vulnerability reports across multiple container images.
"""

import json
import os
import sys
import subprocess
from datetime import datetime
from collections import defaultdict


def run_trivy_scan(image: str, output_file: str) -> dict:
    cmd = [
        "trivy", "image",
        "--format", "json",
        "--output", output_file,
        "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
        image,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode not in (0, 1):
        print(f"Trivy scan failed for {image}: {result.stderr}")
        return {}
    with open(output_file) as f:
        return json.load(f)


def parse_trivy_results(scan_data: dict) -> dict:
    summary = {
        "vulnerabilities": [],
        "severity_counts": defaultdict(int),
        "fixable_count": 0,
        "packages_affected": set(),
    }
    for result in scan_data.get("Results", []):
        target = result.get("Target", "")
        target_type = result.get("Type", "")
        for vuln in result.get("Vulnerabilities", []):
            entry = {
                "id": vuln.get("VulnerabilityID"),
                "severity": vuln.get("Severity", "UNKNOWN"),
                "package": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version": vuln.get("FixedVersion"),
                "title": vuln.get("Title", ""),
                "target": target,
                "target_type": target_type,
            }
            summary["vulnerabilities"].append(entry)
            summary["severity_counts"][entry["severity"]] += 1
            summary["packages_affected"].add(entry["package"])
            if entry["fixed_version"]:
                summary["fixable_count"] += 1

    summary["packages_affected"] = list(summary["packages_affected"])
    summary["severity_counts"] = dict(summary["severity_counts"])
    return summary


def generate_fleet_report(images: list) -> dict:
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_images": len(images),
        "total_vulnerabilities": 0,
        "total_critical": 0,
        "total_fixable": 0,
        "severity_summary": defaultdict(int),
        "top_cves": defaultdict(int),
        "image_reports": [],
    }

    for i, image in enumerate(images):
        print(f"Scanning {i+1}/{len(images)}: {image}")
        output_file = f"/tmp/trivy_scan_{i}.json"
        scan_data = run_trivy_scan(image, output_file)
        if not scan_data:
            continue

        parsed = parse_trivy_results(scan_data)
        vuln_count = len(parsed["vulnerabilities"])
        report["total_vulnerabilities"] += vuln_count
        report["total_critical"] += parsed["severity_counts"].get("CRITICAL", 0)
        report["total_fixable"] += parsed["fixable_count"]

        for sev, count in parsed["severity_counts"].items():
            report["severity_summary"][sev] += count

        for vuln in parsed["vulnerabilities"]:
            report["top_cves"][vuln["id"]] += 1

        report["image_reports"].append({
            "image": image,
            "total_vulnerabilities": vuln_count,
            "severity_counts": parsed["severity_counts"],
            "fixable": parsed["fixable_count"],
            "critical_vulns": [
                v for v in parsed["vulnerabilities"] if v["severity"] == "CRITICAL"
            ],
        })

    report["severity_summary"] = dict(report["severity_summary"])
    top_sorted = sorted(report["top_cves"].items(), key=lambda x: x[1], reverse=True)[:20]
    report["top_cves"] = dict(top_sorted)
    return report


def print_fleet_report(report: dict) -> None:
    print(f"\n{'='*60}")
    print(f"Container Fleet Vulnerability Report")
    print(f"Generated: {report['generated_at']}")
    print(f"{'='*60}")
    print(f"Images scanned: {report['total_images']}")
    print(f"Total vulnerabilities: {report['total_vulnerabilities']}")
    print(f"Total critical: {report['total_critical']}")
    print(f"Total fixable: {report['total_fixable']}")
    print(f"\nSeverity Breakdown:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        count = report["severity_summary"].get(sev, 0)
        if count:
            print(f"  {sev:12s}: {count}")
    print(f"\nImages by Risk (sorted by critical count):")
    for img in sorted(
        report["image_reports"],
        key=lambda x: x["severity_counts"].get("CRITICAL", 0),
        reverse=True,
    ):
        crits = img["severity_counts"].get("CRITICAL", 0)
        print(f"  {img['image']:50s} | Critical: {crits} | Total: {img['total_vulnerabilities']}")


def main():
    images_env = os.environ.get("SCAN_IMAGES", "")
    if images_env:
        images = [i.strip() for i in images_env.split(",") if i.strip()]
    else:
        images = [
            "python:3.11-slim",
            "node:20-alpine",
            "nginx:latest",
            "golang:1.22-alpine",
        ]
        print("No SCAN_IMAGES env var set, using default image list")

    report = generate_fleet_report(images)
    print_fleet_report(report)

    output = f"container_scan_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\nReport saved to: {output}")


if __name__ == "__main__":
    main()
