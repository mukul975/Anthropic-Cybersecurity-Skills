#!/usr/bin/env python3
"""
Trivy Container Scanning Pipeline Script

Scans Docker images with Trivy, evaluates quality gates, generates reports,
and optionally uploads results. Supports both local scanning and CI/CD integration.

Usage:
    python process.py --image myapp:latest --severity-threshold high
    python process.py --image myapp:latest --output report.json --fail-on-findings
    python process.py --dockerfile ./Dockerfile --scan-config
"""

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


@dataclass
class Vulnerability:
    vuln_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str
    severity: str
    title: str
    description: str
    cvss_score: float = 0.0
    references: list = field(default_factory=list)


@dataclass
class Misconfiguration:
    misconfig_id: str
    title: str
    severity: str
    message: str
    resolution: str
    file_path: str = ""


@dataclass
class ScanResult:
    image: str
    vulnerabilities: list = field(default_factory=list)
    misconfigurations: list = field(default_factory=list)
    scan_duration: float = 0.0
    db_version: str = ""
    trivy_version: str = ""
    error: str = ""


def run_trivy_scan(image: str, severity: str = "CRITICAL,HIGH,MEDIUM,LOW",
                   ignore_unfixed: bool = True, scan_type: str = "image",
                   cache_dir: Optional[str] = None, skip_db_update: bool = False) -> dict:
    """Execute Trivy scan and return JSON results."""
    cmd = ["trivy", scan_type]

    if scan_type == "image":
        cmd.extend([
            "--format", "json",
            "--severity", severity,
        ])
        if ignore_unfixed:
            cmd.append("--ignore-unfixed")
        if cache_dir:
            cmd.extend(["--cache-dir", cache_dir])
        if skip_db_update:
            cmd.append("--skip-db-update")
        cmd.append(image)
    elif scan_type == "config":
        cmd.extend([
            "--format", "json",
            "--severity", severity,
            image
        ])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600
        )

        if proc.stdout:
            return json.loads(proc.stdout)
        else:
            return {"error": proc.stderr[:500]}

    except subprocess.TimeoutExpired:
        return {"error": "Trivy scan timed out after 600 seconds"}
    except FileNotFoundError:
        return {"error": "trivy binary not found. Install from https://trivy.dev"}
    except json.JSONDecodeError:
        return {"error": "Failed to parse Trivy JSON output"}


def parse_vulnerabilities(trivy_json: dict) -> list:
    """Extract vulnerability findings from Trivy JSON output."""
    vulns = []
    for result in trivy_json.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vulns.append(Vulnerability(
                vuln_id=vuln.get("VulnerabilityID", ""),
                pkg_name=vuln.get("PkgName", ""),
                installed_version=vuln.get("InstalledVersion", ""),
                fixed_version=vuln.get("FixedVersion", ""),
                severity=vuln.get("Severity", "UNKNOWN"),
                title=vuln.get("Title", ""),
                description=vuln.get("Description", "")[:300],
                cvss_score=vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 0.0),
                references=vuln.get("References", [])[:3]
            ))
    return vulns


def parse_misconfigurations(trivy_json: dict) -> list:
    """Extract misconfiguration findings from Trivy JSON output."""
    misconfigs = []
    for result in trivy_json.get("Results", []):
        for mc in result.get("Misconfigurations", []):
            if mc.get("Status") == "FAIL":
                misconfigs.append(Misconfiguration(
                    misconfig_id=mc.get("ID", ""),
                    title=mc.get("Title", ""),
                    severity=mc.get("Severity", "UNKNOWN"),
                    message=mc.get("Message", ""),
                    resolution=mc.get("Resolution", ""),
                    file_path=result.get("Target", "")
                ))
    return misconfigs


def generate_sarif(scan_result: ScanResult) -> dict:
    """Generate SARIF format output for GitHub Security tab integration."""
    rules = []
    results = []
    rule_ids_seen = set()

    for vuln in scan_result.vulnerabilities:
        if vuln.vuln_id not in rule_ids_seen:
            rule_ids_seen.add(vuln.vuln_id)
            severity_map = {"CRITICAL": "9.5", "HIGH": "7.5", "MEDIUM": "5.0", "LOW": "2.5"}
            rules.append({
                "id": vuln.vuln_id,
                "shortDescription": {"text": vuln.title or vuln.vuln_id},
                "fullDescription": {"text": vuln.description[:500]},
                "properties": {
                    "security-severity": str(vuln.cvss_score or severity_map.get(vuln.severity, "5.0")),
                    "tags": ["security", "vulnerability", vuln.severity.lower()]
                }
            })

        level_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
        results.append({
            "ruleId": vuln.vuln_id,
            "level": level_map.get(vuln.severity, "warning"),
            "message": {
                "text": f"{vuln.pkg_name} {vuln.installed_version} -> {vuln.fixed_version}: {vuln.title}"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "Dockerfile"},
                    "region": {"startLine": 1}
                }
            }]
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Trivy",
                    "informationUri": "https://trivy.dev",
                    "rules": rules
                }
            },
            "results": results
        }]
    }


def evaluate_quality_gate(scan_result: ScanResult, threshold: str) -> dict:
    """Evaluate whether scan results pass the quality gate."""
    threshold_level = SEVERITY_ORDER.get(threshold.upper(), 1)

    blocking_vulns = [
        v for v in scan_result.vulnerabilities
        if SEVERITY_ORDER.get(v.severity, 4) <= threshold_level
    ]

    blocking_misconfigs = [
        m for m in scan_result.misconfigurations
        if SEVERITY_ORDER.get(m.severity, 4) <= threshold_level
    ]

    severity_counts = {}
    for v in scan_result.vulnerabilities:
        severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1

    return {
        "passed": len(blocking_vulns) == 0 and len(blocking_misconfigs) == 0,
        "threshold": threshold.upper(),
        "total_vulnerabilities": len(scan_result.vulnerabilities),
        "total_misconfigurations": len(scan_result.misconfigurations),
        "blocking_vulnerabilities": len(blocking_vulns),
        "blocking_misconfigurations": len(blocking_misconfigs),
        "severity_counts": severity_counts,
        "blocking_details": [
            {"id": v.vuln_id, "pkg": v.pkg_name, "severity": v.severity,
             "installed": v.installed_version, "fixed": v.fixed_version}
            for v in blocking_vulns[:20]
        ]
    }


def main():
    parser = argparse.ArgumentParser(description="Trivy Container Scanning Pipeline")
    parser.add_argument("--image", required=True, help="Docker image to scan (e.g., myapp:latest)")
    parser.add_argument("--output", default="trivy-report.json", help="Output report file path")
    parser.add_argument("--sarif-output", default=None, help="SARIF output file path")
    parser.add_argument("--severity-threshold", default="high",
                        choices=["critical", "high", "medium", "low"],
                        help="Minimum severity to block pipeline")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="Exit non-zero if quality gate fails")
    parser.add_argument("--ignore-unfixed", action="store_true", default=True,
                        help="Ignore vulnerabilities without fixes")
    parser.add_argument("--scan-config", action="store_true",
                        help="Also scan for misconfigurations")
    parser.add_argument("--dockerfile", default=None,
                        help="Path to Dockerfile for misconfiguration scanning")
    parser.add_argument("--cache-dir", default=None, help="Trivy cache directory")
    parser.add_argument("--skip-db-update", action="store_true", help="Skip DB update")
    args = parser.parse_args()

    scan_result = ScanResult(image=args.image)
    start_time = datetime.now(timezone.utc)

    print(f"[*] Scanning image: {args.image}")
    trivy_json = run_trivy_scan(
        args.image,
        ignore_unfixed=args.ignore_unfixed,
        cache_dir=args.cache_dir,
        skip_db_update=args.skip_db_update
    )

    if "error" in trivy_json:
        print(f"[ERROR] {trivy_json['error']}")
        sys.exit(2)

    scan_result.vulnerabilities = parse_vulnerabilities(trivy_json)
    scan_result.db_version = trivy_json.get("Metadata", {}).get("DB", {}).get("UpdatedAt", "unknown")

    if args.scan_config and args.dockerfile:
        print(f"[*] Scanning configuration: {args.dockerfile}")
        config_path = os.path.dirname(args.dockerfile) or "."
        config_json = run_trivy_scan(config_path, scan_type="config")
        if "error" not in config_json:
            scan_result.misconfigurations = parse_misconfigurations(config_json)

    scan_result.scan_duration = (datetime.now(timezone.utc) - start_time).total_seconds()

    quality_gate = evaluate_quality_gate(scan_result, args.severity_threshold)

    report = {
        "scan_metadata": {
            "image": args.image,
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": scan_result.scan_duration,
            "db_version": scan_result.db_version
        },
        "quality_gate": quality_gate,
        "vulnerabilities": [
            {
                "id": v.vuln_id, "package": v.pkg_name, "severity": v.severity,
                "installed": v.installed_version, "fixed": v.fixed_version,
                "title": v.title, "cvss": v.cvss_score
            }
            for v in sorted(scan_result.vulnerabilities,
                            key=lambda x: SEVERITY_ORDER.get(x.severity, 4))
        ],
        "misconfigurations": [
            {"id": m.misconfig_id, "title": m.title, "severity": m.severity,
             "message": m.message, "resolution": m.resolution}
            for m in scan_result.misconfigurations
        ]
    }

    with open(os.path.abspath(args.output), "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Report: {os.path.abspath(args.output)}")

    if args.sarif_output:
        sarif = generate_sarif(scan_result)
        with open(os.path.abspath(args.sarif_output), "w") as f:
            json.dump(sarif, f, indent=2)
        print(f"[*] SARIF: {os.path.abspath(args.sarif_output)}")

    print(f"\n[*] Vulnerabilities: {len(scan_result.vulnerabilities)} "
          f"| Misconfigs: {len(scan_result.misconfigurations)}")

    if quality_gate["passed"]:
        print(f"[PASS] Quality gate passed.")
    else:
        print(f"[FAIL] Quality gate failed. {quality_gate['blocking_vulnerabilities']} blocking vulns.")
        for d in quality_gate["blocking_details"][:10]:
            print(f"  - [{d['severity']}] {d['id']} in {d['pkg']} ({d['installed']} -> {d['fixed']})")

    if args.fail_on_findings and not quality_gate["passed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
