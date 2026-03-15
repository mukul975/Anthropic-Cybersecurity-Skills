#!/usr/bin/env python3
"""
Grype Container Image Scanner - Automated scanning and reporting utility.

Scans container images using Grype, parses results, and generates
summary reports with severity breakdowns and remediation guidance.
"""

import json
import subprocess
import sys
import argparse
from datetime import datetime
from pathlib import Path


def run_grype_scan(image: str, output_format: str = "json", fail_on: str = None) -> dict:
    """Run grype scan on a container image and return parsed results."""
    cmd = ["grype", image, "-o", output_format, "--quiet"]
    if fail_on:
        cmd.extend(["--fail-on", fail_on])

    result = subprocess.run(cmd, capture_output=True, text=True)

    if output_format == "json":
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            print(f"Error parsing Grype output: {result.stderr}", file=sys.stderr)
            sys.exit(1)
    return {"raw": result.stdout, "returncode": result.returncode}


def parse_vulnerabilities(scan_data: dict) -> list:
    """Extract and structure vulnerability matches from scan results."""
    matches = scan_data.get("matches", [])
    vulns = []
    for match in matches:
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        fix_info = vuln.get("fix", {})
        vulns.append({
            "id": vuln.get("id", "UNKNOWN"),
            "severity": vuln.get("severity", "Unknown"),
            "package": artifact.get("name", "unknown"),
            "version": artifact.get("version", "unknown"),
            "type": artifact.get("type", "unknown"),
            "fix_versions": fix_info.get("versions", []),
            "fix_state": fix_info.get("state", "unknown"),
            "data_source": vuln.get("dataSource", ""),
            "description": vuln.get("description", ""),
        })
    return vulns


def severity_summary(vulns: list) -> dict:
    """Generate severity count summary."""
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}
    for v in vulns:
        sev = v["severity"]
        if sev in summary:
            summary[sev] += 1
        else:
            summary["Unknown"] += 1
    return summary


def fixable_summary(vulns: list) -> dict:
    """Count fixable vs non-fixable vulnerabilities."""
    fixable = sum(1 for v in vulns if v["fix_state"] == "fixed")
    not_fixable = sum(1 for v in vulns if v["fix_state"] != "fixed")
    return {"fixable": fixable, "not_fixable": not_fixable, "total": len(vulns)}


def generate_report(image: str, vulns: list, output_path: str = None) -> str:
    """Generate a markdown vulnerability report."""
    summary = severity_summary(vulns)
    fix_info = fixable_summary(vulns)
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    report = f"""# Vulnerability Scan Report

**Image:** `{image}`
**Scan Date:** {timestamp}
**Scanner:** Grype (Anchore)
**Total Vulnerabilities:** {len(vulns)}

## Severity Summary

| Severity | Count |
|----------|-------|
| Critical | {summary['Critical']} |
| High | {summary['High']} |
| Medium | {summary['Medium']} |
| Low | {summary['Low']} |
| Negligible | {summary['Negligible']} |

## Fix Availability

- **Fixable:** {fix_info['fixable']}
- **Not Fixable:** {fix_info['not_fixable']}

## Critical and High Findings

| CVE | Severity | Package | Version | Fix Available |
|-----|----------|---------|---------|---------------|
"""
    critical_high = [v for v in vulns if v["severity"] in ("Critical", "High")]
    critical_high.sort(key=lambda x: (0 if x["severity"] == "Critical" else 1, x["id"]))

    for v in critical_high:
        fix = ", ".join(v["fix_versions"]) if v["fix_versions"] else "No fix"
        report += f"| {v['id']} | {v['severity']} | {v['package']} | {v['version']} | {fix} |\n"

    report += f"\n## All Vulnerabilities ({len(vulns)} total)\n\n"
    report += "| CVE | Severity | Package | Version | Type | Fix State |\n"
    report += "|-----|----------|---------|---------|------|----------|\n"

    for v in sorted(vulns, key=lambda x: (
        {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Negligible": 4}.get(x["severity"], 5),
        x["id"]
    )):
        report += f"| {v['id']} | {v['severity']} | {v['package']} | {v['version']} | {v['type']} | {v['fix_state']} |\n"

    if output_path:
        Path(output_path).write_text(report)
        print(f"Report written to {output_path}")

    return report


def gate_check(vulns: list, max_critical: int = 0, max_high: int = 0) -> bool:
    """Evaluate vulnerabilities against gate thresholds. Returns True if pass."""
    summary = severity_summary(vulns)
    passed = True

    if summary["Critical"] > max_critical:
        print(f"GATE FAIL: {summary['Critical']} critical vulnerabilities (max: {max_critical})")
        passed = False
    if summary["High"] > max_high:
        print(f"GATE FAIL: {summary['High']} high vulnerabilities (max: {max_high})")
        passed = False

    if passed:
        print("GATE PASS: Vulnerability thresholds met")

    return passed


def main():
    parser = argparse.ArgumentParser(description="Grype Container Image Scanner Utility")
    parser.add_argument("image", help="Container image reference to scan")
    parser.add_argument("--report", "-r", help="Output report file path (markdown)")
    parser.add_argument("--json-output", "-j", help="Output raw JSON results to file")
    parser.add_argument("--max-critical", type=int, default=0, help="Max allowed critical vulns (default: 0)")
    parser.add_argument("--max-high", type=int, default=0, help="Max allowed high vulns (default: 0)")
    parser.add_argument("--gate", action="store_true", help="Enable gate check mode")

    args = parser.parse_args()

    print(f"Scanning {args.image}...")
    scan_data = run_grype_scan(args.image)
    vulns = parse_vulnerabilities(scan_data)

    if args.json_output:
        Path(args.json_output).write_text(json.dumps(scan_data, indent=2))
        print(f"JSON results written to {args.json_output}")

    report = generate_report(args.image, vulns, args.report)

    if not args.report:
        print(report)

    summary = severity_summary(vulns)
    print(f"\nSummary: C={summary['Critical']} H={summary['High']} M={summary['Medium']} L={summary['Low']}")

    if args.gate:
        passed = gate_check(vulns, args.max_critical, args.max_high)
        sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
