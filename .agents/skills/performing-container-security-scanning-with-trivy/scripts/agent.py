#!/usr/bin/env python3
"""Trivy Container Security Agent - scans images for vulnerabilities, misconfigs, and secrets."""

import json
import argparse
import logging
import subprocess
import os
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def run_trivy_scan(image, scanners="vuln,secret", severity="CRITICAL,HIGH,MEDIUM"):
    """Run Trivy image scan and return JSON results."""
    cmd = [
        "trivy", "image", "--format", "json", "--scanners", scanners,
        "--severity", severity, "--quiet", image,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0 and not result.stdout:
        logger.error("Trivy scan failed: %s", result.stderr)
        return {}
    return json.loads(result.stdout) if result.stdout else {}


def run_trivy_misconfig(target_path):
    """Run Trivy misconfiguration scan on Dockerfile/K8s manifests."""
    cmd = [
        "trivy", "config", "--format", "json", "--severity", "CRITICAL,HIGH,MEDIUM",
        "--quiet", target_path,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return json.loads(result.stdout) if result.stdout else {}


def generate_sbom(image, sbom_format="cyclonedx"):
    """Generate SBOM from container image."""
    cmd = ["trivy", "image", "--format", sbom_format, "--quiet", image]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return result.stdout if result.returncode == 0 else ""


def analyze_vulnerabilities(scan_results):
    """Analyze vulnerability scan results and produce summary."""
    by_severity = defaultdict(int)
    by_pkg_type = defaultdict(int)
    fixable = 0
    total = 0
    cve_list = []
    for target in scan_results.get("Results", []):
        pkg_type = target.get("Type", "unknown")
        for vuln in target.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "UNKNOWN")
            by_severity[severity] += 1
            by_pkg_type[pkg_type] += 1
            total += 1
            if vuln.get("FixedVersion"):
                fixable += 1
            if severity in ("CRITICAL", "HIGH"):
                cve_list.append({
                    "cve_id": vuln.get("VulnerabilityID", ""),
                    "package": vuln.get("PkgName", ""),
                    "installed": vuln.get("InstalledVersion", ""),
                    "fixed": vuln.get("FixedVersion", ""),
                    "severity": severity,
                    "cvss_score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 0),
                    "title": vuln.get("Title", "")[:100],
                })
    return {
        "total_vulnerabilities": total,
        "by_severity": dict(by_severity),
        "by_package_type": dict(by_pkg_type),
        "fixable_count": fixable,
        "fix_rate": round(fixable / max(total, 1) * 100, 1),
        "critical_high_cves": sorted(cve_list, key=lambda x: x.get("cvss_score", 0), reverse=True)[:20],
    }


def analyze_secrets(scan_results):
    """Analyze secret detection results."""
    secrets = []
    for target in scan_results.get("Results", []):
        for secret in target.get("Secrets", []):
            secrets.append({
                "rule_id": secret.get("RuleID", ""),
                "category": secret.get("Category", ""),
                "title": secret.get("Title", ""),
                "severity": secret.get("Severity", ""),
                "target_file": target.get("Target", ""),
            })
    return {"total_secrets": len(secrets), "secrets": secrets[:15]}


def analyze_misconfigs(misconfig_results):
    """Analyze misconfiguration scan results."""
    findings = []
    for target in misconfig_results.get("Results", []):
        for mc in target.get("Misconfigurations", []):
            findings.append({
                "avd_id": mc.get("AVDID", ""),
                "title": mc.get("Title", ""),
                "severity": mc.get("Severity", ""),
                "target": target.get("Target", ""),
                "resolution": mc.get("Resolution", "")[:150],
            })
    by_sev = defaultdict(int)
    for f in findings:
        by_sev[f["severity"]] += 1
    return {"total_misconfigs": len(findings), "by_severity": dict(by_sev), "findings": findings[:15]}


def generate_report(image, vuln_analysis, secret_analysis, misconfig_analysis):
    critical = vuln_analysis["by_severity"].get("CRITICAL", 0)
    high = vuln_analysis["by_severity"].get("HIGH", 0)
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "image": image,
        "vulnerability_summary": vuln_analysis,
        "secret_summary": secret_analysis,
        "misconfiguration_summary": misconfig_analysis,
        "gate_result": "FAIL" if critical > 0 else "WARN" if high > 0 else "PASS",
    }


def main():
    parser = argparse.ArgumentParser(description="Trivy Container Security Scanning Agent")
    parser.add_argument("--image", required=True, help="Container image to scan (e.g., nginx:latest)")
    parser.add_argument("--config-path", help="Path to Dockerfile/K8s manifests for misconfig scan")
    parser.add_argument("--severity", default="CRITICAL,HIGH,MEDIUM", help="Severity filter")
    parser.add_argument("--sbom", action="store_true", help="Generate CycloneDX SBOM")
    parser.add_argument("--output", default="trivy_scan_report.json")
    args = parser.parse_args()

    scan_results = run_trivy_scan(args.image, severity=args.severity)
    vuln_analysis = analyze_vulnerabilities(scan_results)
    secret_analysis = analyze_secrets(scan_results)
    misconfig_analysis = {}
    if args.config_path:
        misconfig_results = run_trivy_misconfig(args.config_path)
        misconfig_analysis = analyze_misconfigs(misconfig_results)
    if args.sbom:
        sbom_data = generate_sbom(args.image)
        if sbom_data:
            with open(args.output.replace(".json", "_sbom.json"), "w") as f:
                f.write(sbom_data)
    report = generate_report(args.image, vuln_analysis, secret_analysis, misconfig_analysis)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Trivy: %s - %d vulns (%d critical), %d secrets, gate: %s",
                args.image, vuln_analysis["total_vulnerabilities"],
                vuln_analysis["by_severity"].get("CRITICAL", 0),
                secret_analysis["total_secrets"], report["gate_result"])
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
