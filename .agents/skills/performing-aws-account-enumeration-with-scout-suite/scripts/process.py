#!/usr/bin/env python3
"""
ScoutSuite AWS Security Assessment Automation Script

Automates ScoutSuite scanning, parses results, and generates
summary reports for AWS security posture assessment.
"""

import json
import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path
from collections import defaultdict


def run_scoutsuite_scan(
    services=None,
    regions=None,
    profile=None,
    report_dir=None
):
    """Execute ScoutSuite scan against AWS account."""
    cmd = ["scout", "aws", "--no-browser"]

    if services:
        cmd.extend(["--services"] + services)
    if regions:
        cmd.extend(["--regions"] + regions)
    if profile:
        cmd.extend(["--profile", profile])
    if report_dir:
        cmd.extend(["--report-dir", report_dir])

    print(f"[*] Running ScoutSuite scan: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[!] ScoutSuite scan failed: {result.stderr}")
        return False

    print("[+] ScoutSuite scan completed successfully")
    return True


def parse_scoutsuite_results(report_dir):
    """Parse ScoutSuite JSON results and extract findings."""
    results_file = Path(report_dir) / "scoutsuite-results" / "scoutsuite_results.json"

    if not results_file.exists():
        # Try alternative path structure
        for path in Path(report_dir).rglob("scoutsuite_results*.json"):
            results_file = path
            break

    if not results_file.exists():
        print(f"[!] Results file not found in {report_dir}")
        return None

    with open(results_file, "r") as f:
        return json.load(f)


def extract_findings(results):
    """Extract and categorize findings from ScoutSuite results."""
    findings_summary = {
        "danger": [],
        "warning": [],
        "good": []
    }
    service_summary = defaultdict(lambda: {"danger": 0, "warning": 0, "good": 0})

    services = results.get("services", {})
    for service_name, service_data in services.items():
        findings = service_data.get("findings", {})
        for finding_id, finding in findings.items():
            level = finding.get("level", "warning")
            flagged = finding.get("flagged_items", 0)
            total = finding.get("checked_items", 0)
            description = finding.get("description", "No description")
            rationale = finding.get("rationale", "")

            entry = {
                "id": finding_id,
                "service": service_name,
                "description": description,
                "rationale": rationale,
                "flagged_items": flagged,
                "checked_items": total,
                "level": level
            }

            if flagged > 0:
                if level == "danger":
                    findings_summary["danger"].append(entry)
                    service_summary[service_name]["danger"] += flagged
                elif level == "warning":
                    findings_summary["warning"].append(entry)
                    service_summary[service_name]["warning"] += flagged
            else:
                findings_summary["good"].append(entry)
                service_summary[service_name]["good"] += 1

    return findings_summary, dict(service_summary)


def generate_report(findings_summary, service_summary, output_file=None):
    """Generate a text-based summary report."""
    report_lines = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report_lines.append("=" * 70)
    report_lines.append("ScoutSuite AWS Security Assessment Report")
    report_lines.append(f"Generated: {timestamp}")
    report_lines.append("=" * 70)

    # Executive summary
    danger_count = len(findings_summary["danger"])
    warning_count = len(findings_summary["warning"])
    good_count = len(findings_summary["good"])

    report_lines.append(f"\n## Executive Summary")
    report_lines.append(f"  Critical Findings : {danger_count}")
    report_lines.append(f"  Warning Findings  : {warning_count}")
    report_lines.append(f"  Passing Checks    : {good_count}")

    # Service breakdown
    report_lines.append(f"\n## Service Breakdown")
    report_lines.append(f"{'Service':<20} {'Danger':<10} {'Warning':<10} {'Good':<10}")
    report_lines.append("-" * 50)
    for service, counts in sorted(service_summary.items()):
        report_lines.append(
            f"{service:<20} {counts['danger']:<10} {counts['warning']:<10} {counts['good']:<10}"
        )

    # Critical findings detail
    if findings_summary["danger"]:
        report_lines.append(f"\n## Critical Findings (Requires Immediate Action)")
        report_lines.append("-" * 50)
        for finding in sorted(findings_summary["danger"], key=lambda x: x["flagged_items"], reverse=True):
            report_lines.append(f"\n  [{finding['service'].upper()}] {finding['id']}")
            report_lines.append(f"  Description: {finding['description']}")
            report_lines.append(f"  Flagged Items: {finding['flagged_items']}/{finding['checked_items']}")
            if finding["rationale"]:
                report_lines.append(f"  Rationale: {finding['rationale']}")

    # Warning findings
    if findings_summary["warning"]:
        report_lines.append(f"\n## Warning Findings")
        report_lines.append("-" * 50)
        for finding in sorted(findings_summary["warning"], key=lambda x: x["flagged_items"], reverse=True)[:20]:
            report_lines.append(f"\n  [{finding['service'].upper()}] {finding['id']}")
            report_lines.append(f"  Description: {finding['description']}")
            report_lines.append(f"  Flagged Items: {finding['flagged_items']}/{finding['checked_items']}")

    report = "\n".join(report_lines)

    if output_file:
        with open(output_file, "w") as f:
            f.write(report)
        print(f"[+] Report saved to {output_file}")
    else:
        print(report)

    return report


def check_compliance_gate(findings_summary, max_danger=0, max_warning=10):
    """Check if findings meet compliance gate thresholds for CI/CD."""
    danger_count = len(findings_summary["danger"])
    warning_count = len(findings_summary["warning"])

    passed = True

    if danger_count > max_danger:
        print(f"[FAIL] {danger_count} critical findings exceed threshold of {max_danger}")
        passed = False
    else:
        print(f"[PASS] Critical findings ({danger_count}) within threshold ({max_danger})")

    if warning_count > max_warning:
        print(f"[WARN] {warning_count} warning findings exceed threshold of {max_warning}")

    return passed


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ScoutSuite AWS Security Assessment")
    parser.add_argument("--scan", action="store_true", help="Run ScoutSuite scan")
    parser.add_argument("--parse", type=str, help="Parse existing ScoutSuite results directory")
    parser.add_argument("--services", nargs="+", default=None, help="AWS services to scan")
    parser.add_argument("--regions", nargs="+", default=None, help="AWS regions to scan")
    parser.add_argument("--profile", type=str, default=None, help="AWS profile name")
    parser.add_argument("--report-dir", type=str, default="./scoutsuite-report", help="Report output directory")
    parser.add_argument("--output", type=str, default=None, help="Output file for summary report")
    parser.add_argument("--gate", action="store_true", help="Run compliance gate check")
    parser.add_argument("--max-danger", type=int, default=0, help="Max allowed danger findings")

    args = parser.parse_args()

    if args.scan:
        success = run_scoutsuite_scan(
            services=args.services,
            regions=args.regions,
            profile=args.profile,
            report_dir=args.report_dir
        )
        if not success:
            sys.exit(1)

    report_dir = args.parse or args.report_dir
    results = parse_scoutsuite_results(report_dir)

    if results:
        findings_summary, service_summary = extract_findings(results)
        generate_report(findings_summary, service_summary, args.output)

        if args.gate:
            passed = check_compliance_gate(findings_summary, max_danger=args.max_danger)
            sys.exit(0 if passed else 1)
