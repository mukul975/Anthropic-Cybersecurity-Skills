#!/usr/bin/env python3
"""
Trivy Docker Image Scanner - Automated scanning and reporting tool.

Scans Docker images with Trivy, parses results, enforces severity gates,
and generates actionable reports.
"""

import subprocess
import json
import sys
import os
import argparse
from datetime import datetime
from dataclasses import dataclass, field


@dataclass
class ScanPolicy:
    fail_on_critical: bool = True
    fail_on_high: bool = True
    fail_on_medium: bool = False
    max_critical: int = 0
    max_high: int = 5
    max_medium: int = 20
    ignore_unfixed: bool = False
    scanners: list = field(default_factory=lambda: ["vuln", "secret"])


@dataclass
class VulnSummary:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0
    total: int = 0


def check_trivy_installed() -> bool:
    """Verify Trivy is installed."""
    try:
        result = subprocess.run(
            ["trivy", "version"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            version_line = result.stdout.strip().split("\n")[0]
            print(f"[*] {version_line}")
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    print("[!] Trivy is not installed. Install from https://trivy.dev")
    return False


def update_db():
    """Update Trivy vulnerability database."""
    print("[*] Updating vulnerability database...")
    result = subprocess.run(
        ["trivy", "image", "--download-db-only"],
        capture_output=True, text=True, timeout=300
    )
    if result.returncode == 0:
        print("[+] Database updated successfully")
    else:
        print(f"[!] Database update warning: {result.stderr}")


def scan_image(image: str, policy: ScanPolicy) -> dict:
    """Scan a Docker image with Trivy and return JSON results."""
    cmd = [
        "trivy", "image",
        "--format", "json",
        "--scanners", ",".join(policy.scanners),
    ]

    if policy.ignore_unfixed:
        cmd.append("--ignore-unfixed")

    cmd.append(image)

    print(f"[*] Scanning image: {image}")
    print(f"[*] Scanners: {', '.join(policy.scanners)}")

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=600
    )

    if result.returncode != 0 and not result.stdout:
        print(f"[!] Scan failed: {result.stderr}")
        return {}

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print("[!] Failed to parse Trivy JSON output")
        return {}


def parse_results(scan_data: dict) -> tuple:
    """Parse Trivy JSON results into vulnerability summary and details."""
    summary = VulnSummary()
    vulnerabilities = []
    secrets = []
    misconfigs = []

    results = scan_data.get("Results", [])

    for result in results:
        target = result.get("Target", "unknown")
        result_class = result.get("Class", "")
        result_type = result.get("Type", "")

        # Parse vulnerabilities
        for vuln in result.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "UNKNOWN").upper()

            if severity == "CRITICAL":
                summary.critical += 1
            elif severity == "HIGH":
                summary.high += 1
            elif severity == "MEDIUM":
                summary.medium += 1
            elif severity == "LOW":
                summary.low += 1
            else:
                summary.unknown += 1

            summary.total += 1

            vulnerabilities.append({
                "target": target,
                "type": result_type,
                "vuln_id": vuln.get("VulnerabilityID", ""),
                "pkg_name": vuln.get("PkgName", ""),
                "installed_version": vuln.get("InstalledVersion", ""),
                "fixed_version": vuln.get("FixedVersion", ""),
                "severity": severity,
                "title": vuln.get("Title", ""),
                "description": vuln.get("Description", "")[:200],
                "cvss_score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 0),
                "references": vuln.get("References", [])[:3],
            })

        # Parse secrets
        for secret in result.get("Secrets", []):
            secrets.append({
                "target": target,
                "rule_id": secret.get("RuleID", ""),
                "category": secret.get("Category", ""),
                "severity": secret.get("Severity", ""),
                "title": secret.get("Title", ""),
                "match": secret.get("Match", "")[:50] + "...",
            })

        # Parse misconfigurations
        for misconfig in result.get("Misconfigurations", []):
            misconfigs.append({
                "target": target,
                "type": misconfig.get("Type", ""),
                "id": misconfig.get("ID", ""),
                "title": misconfig.get("Title", ""),
                "severity": misconfig.get("Severity", ""),
                "message": misconfig.get("Message", ""),
                "resolution": misconfig.get("Resolution", ""),
            })

    return summary, vulnerabilities, secrets, misconfigs


def evaluate_policy(summary: VulnSummary, policy: ScanPolicy) -> tuple:
    """Evaluate scan results against policy. Returns (passed, reasons)."""
    passed = True
    reasons = []

    if policy.fail_on_critical and summary.critical > policy.max_critical:
        passed = False
        reasons.append(
            f"CRITICAL vulnerabilities ({summary.critical}) exceed threshold ({policy.max_critical})"
        )

    if policy.fail_on_high and summary.high > policy.max_high:
        passed = False
        reasons.append(
            f"HIGH vulnerabilities ({summary.high}) exceed threshold ({policy.max_high})"
        )

    if policy.fail_on_medium and summary.medium > policy.max_medium:
        passed = False
        reasons.append(
            f"MEDIUM vulnerabilities ({summary.medium}) exceed threshold ({policy.max_medium})"
        )

    return passed, reasons


def generate_report(image: str, summary: VulnSummary, vulnerabilities: list,
                    secrets: list, misconfigs: list, policy_passed: bool,
                    policy_reasons: list) -> dict:
    """Generate comprehensive scan report."""
    return {
        "scan_metadata": {
            "tool": "Trivy",
            "image": image,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "policy_result": "PASS" if policy_passed else "FAIL",
        },
        "summary": {
            "total_vulnerabilities": summary.total,
            "critical": summary.critical,
            "high": summary.high,
            "medium": summary.medium,
            "low": summary.low,
            "unknown": summary.unknown,
            "secrets_found": len(secrets),
            "misconfigurations_found": len(misconfigs),
        },
        "policy_evaluation": {
            "passed": policy_passed,
            "failure_reasons": policy_reasons,
        },
        "critical_vulnerabilities": [
            v for v in vulnerabilities if v["severity"] == "CRITICAL"
        ],
        "high_vulnerabilities": [
            v for v in vulnerabilities if v["severity"] == "HIGH"
        ],
        "secrets": secrets,
        "misconfigurations": misconfigs,
        "all_vulnerabilities": vulnerabilities,
    }


def print_report(report: dict):
    """Print human-readable scan report."""
    meta = report["scan_metadata"]
    summary = report["summary"]

    print("\n" + "=" * 70)
    print("TRIVY IMAGE SCAN REPORT")
    print("=" * 70)
    print(f"Image:     {meta['image']}")
    print(f"Timestamp: {meta['timestamp']}")
    print(f"Policy:    {meta['policy_result']}")
    print("=" * 70)

    print(f"\nVulnerability Summary:")
    print(f"  CRITICAL:  {summary['critical']}")
    print(f"  HIGH:      {summary['high']}")
    print(f"  MEDIUM:    {summary['medium']}")
    print(f"  LOW:       {summary['low']}")
    print(f"  UNKNOWN:   {summary['unknown']}")
    print(f"  TOTAL:     {summary['total_vulnerabilities']}")

    if summary["secrets_found"] > 0:
        print(f"\n  Secrets Found: {summary['secrets_found']}")

    if summary["misconfigurations_found"] > 0:
        print(f"  Misconfigs Found: {summary['misconfigurations_found']}")

    # Print critical/high details
    for severity in ["critical", "high"]:
        vulns = report.get(f"{severity}_vulnerabilities", [])
        if vulns:
            print(f"\n{severity.upper()} VULNERABILITIES:")
            print("-" * 70)
            for v in vulns:
                fixed = v.get("fixed_version", "not fixed")
                print(f"  {v['vuln_id']} | {v['pkg_name']} {v['installed_version']} -> {fixed}")
                if v.get("title"):
                    print(f"    {v['title']}")

    # Print policy result
    policy = report["policy_evaluation"]
    if not policy["passed"]:
        print(f"\nPOLICY FAILURES:")
        for reason in policy["failure_reasons"]:
            print(f"  - {reason}")

    print()


def main():
    parser = argparse.ArgumentParser(description="Trivy Docker Image Scanner")
    parser.add_argument("image", help="Docker image to scan (e.g., nginx:latest)")
    parser.add_argument("--output", "-o", default="trivy_report.json", help="Output JSON file")
    parser.add_argument("--max-critical", type=int, default=0, help="Max allowed CRITICAL vulns")
    parser.add_argument("--max-high", type=int, default=5, help="Max allowed HIGH vulns")
    parser.add_argument("--ignore-unfixed", action="store_true", help="Ignore unfixed vulns")
    parser.add_argument("--scanners", default="vuln,secret",
                        help="Comma-separated scanners: vuln,misconfig,secret,license")
    parser.add_argument("--update-db", action="store_true", help="Update DB before scan")
    args = parser.parse_args()

    if not check_trivy_installed():
        sys.exit(1)

    if args.update_db:
        update_db()

    policy = ScanPolicy(
        max_critical=args.max_critical,
        max_high=args.max_high,
        ignore_unfixed=args.ignore_unfixed,
        scanners=args.scanners.split(","),
    )

    scan_data = scan_image(args.image, policy)
    if not scan_data:
        sys.exit(1)

    summary, vulnerabilities, secrets, misconfigs = parse_results(scan_data)
    policy_passed, policy_reasons = evaluate_policy(summary, policy)

    report = generate_report(
        args.image, summary, vulnerabilities, secrets, misconfigs,
        policy_passed, policy_reasons
    )

    print_report(report)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Full report saved to {args.output}")

    if not policy_passed:
        print("[!] Policy check FAILED - image should not be deployed")
        sys.exit(1)

    print("[+] Policy check PASSED - image approved for deployment")


if __name__ == "__main__":
    main()
