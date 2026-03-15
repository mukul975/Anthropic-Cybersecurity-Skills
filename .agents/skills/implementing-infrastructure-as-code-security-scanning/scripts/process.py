#!/usr/bin/env python3
"""
IaC Security Scanning Pipeline Script

Runs Checkov and/or tfsec against IaC directories, aggregates findings,
evaluates quality gates, and generates reports.

Usage:
    python process.py --iac-dir ./terraform --framework terraform
    python process.py --iac-dir ./k8s --framework kubernetes --output report.json
"""

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


SEVERITY_MAP = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class IaCFinding:
    check_id: str
    check_name: str
    severity: str
    resource: str
    file_path: str
    guideline: str
    framework: str
    tool: str
    file_line_range: list = field(default_factory=list)


def run_checkov(iac_dir: str, framework: str = "terraform",
                skip_checks: Optional[list] = None,
                custom_checks_dir: Optional[str] = None,
                baseline: Optional[str] = None) -> dict:
    """Run Checkov scan and return JSON results."""
    cmd = [
        "checkov", "-d", iac_dir,
        "--framework", framework,
        "--output", "json",
        "--compact",
        "--quiet"
    ]

    if skip_checks:
        cmd.extend(["--skip-check", ",".join(skip_checks)])
    if custom_checks_dir:
        cmd.extend(["--external-checks-dir", custom_checks_dir])
    if baseline:
        cmd.extend(["--baseline", baseline])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if proc.stdout:
            try:
                return json.loads(proc.stdout)
            except json.JSONDecodeError:
                return {"error": "Failed to parse Checkov JSON output"}
        return {"error": proc.stderr[:500] if proc.stderr else "No output from Checkov"}
    except subprocess.TimeoutExpired:
        return {"error": "Checkov scan timed out"}
    except FileNotFoundError:
        return {"error": "checkov not found. Install with: pip install checkov"}


def run_tfsec(iac_dir: str) -> dict:
    """Run tfsec scan and return JSON results."""
    cmd = ["tfsec", iac_dir, "--format", "json", "--no-color"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if proc.stdout:
            try:
                return json.loads(proc.stdout)
            except json.JSONDecodeError:
                return {"error": "Failed to parse tfsec JSON output"}
        return {"error": proc.stderr[:500] if proc.stderr else "No output from tfsec"}
    except FileNotFoundError:
        return {"error": "tfsec not found. Install from https://aquasecurity.github.io/tfsec/"}


def parse_checkov_results(checkov_json: dict) -> tuple:
    """Parse Checkov JSON output into findings."""
    findings = []
    passed_count = 0
    skipped_count = 0

    results_list = checkov_json if isinstance(checkov_json, list) else [checkov_json]

    for result_block in results_list:
        for check_type in result_block.get("results", {}):
            if check_type == "passed_checks":
                passed_count += len(result_block["results"].get("passed_checks", []))
            elif check_type == "skipped_checks":
                skipped_count += len(result_block["results"].get("skipped_checks", []))
            elif check_type == "failed_checks":
                for check in result_block["results"].get("failed_checks", []):
                    severity = check.get("severity", "MEDIUM")
                    if not severity or severity == "UNKNOWN":
                        severity = "MEDIUM"

                    findings.append(IaCFinding(
                        check_id=check.get("check_id", ""),
                        check_name=check.get("check_result", {}).get("name", check.get("name", "")),
                        severity=severity.upper(),
                        resource=check.get("resource", ""),
                        file_path=check.get("file_path", ""),
                        guideline=check.get("guideline", ""),
                        framework=check.get("check_type", "terraform"),
                        tool="checkov",
                        file_line_range=check.get("file_line_range", [])
                    ))

    return findings, passed_count, skipped_count


def parse_tfsec_results(tfsec_json: dict) -> list:
    """Parse tfsec JSON output into findings."""
    findings = []
    for result in tfsec_json.get("results", []):
        findings.append(IaCFinding(
            check_id=result.get("rule_id", result.get("long_id", "")),
            check_name=result.get("rule_description", ""),
            severity=result.get("severity", "MEDIUM").upper(),
            resource=result.get("resource", ""),
            file_path=result.get("location", {}).get("filename", ""),
            guideline=result.get("resolution", ""),
            framework="terraform",
            tool="tfsec",
            file_line_range=[
                result.get("location", {}).get("start_line", 0),
                result.get("location", {}).get("end_line", 0)
            ]
        ))
    return findings


def evaluate_quality_gate(findings: list, threshold: str) -> dict:
    """Evaluate quality gate based on finding severities."""
    threshold_level = SEVERITY_MAP.get(threshold.upper(), 1)
    blocking = [f for f in findings if SEVERITY_MAP.get(f.severity, 3) <= threshold_level]

    severity_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    return {
        "passed": len(blocking) == 0,
        "threshold": threshold.upper(),
        "total_findings": len(findings),
        "blocking_count": len(blocking),
        "severity_counts": severity_counts,
        "blocking_details": [
            {
                "check_id": f.check_id,
                "name": f.check_name,
                "severity": f.severity,
                "resource": f.resource,
                "file": f.file_path,
                "lines": f.file_line_range
            }
            for f in blocking[:25]
        ]
    }


def main():
    parser = argparse.ArgumentParser(description="IaC Security Scanning Pipeline")
    parser.add_argument("--iac-dir", required=True, help="Directory containing IaC files")
    parser.add_argument("--framework", default="terraform",
                        choices=["terraform", "cloudformation", "kubernetes", "helm", "all"])
    parser.add_argument("--output", default="iac-security-report.json")
    parser.add_argument("--severity-threshold", default="high",
                        choices=["critical", "high", "medium", "low"])
    parser.add_argument("--fail-on-findings", action="store_true")
    parser.add_argument("--skip-checks", nargs="*", help="Check IDs to skip")
    parser.add_argument("--custom-checks-dir", default=None)
    parser.add_argument("--run-tfsec", action="store_true", help="Also run tfsec")
    args = parser.parse_args()

    iac_dir = os.path.abspath(args.iac_dir)
    all_findings = []

    print(f"[*] Scanning IaC: {iac_dir} (framework: {args.framework})")

    checkov_json = run_checkov(iac_dir, args.framework, args.skip_checks, args.custom_checks_dir)
    if "error" in checkov_json:
        print(f"[WARN] Checkov: {checkov_json['error']}")
    else:
        findings, passed, skipped = parse_checkov_results(checkov_json)
        all_findings.extend(findings)
        print(f"    Checkov: {len(findings)} failed, {passed} passed, {skipped} skipped")

    if args.run_tfsec and args.framework in ("terraform", "all"):
        tfsec_json = run_tfsec(iac_dir)
        if "error" not in tfsec_json:
            tfsec_findings = parse_tfsec_results(tfsec_json)
            all_findings.extend(tfsec_findings)
            print(f"    tfsec: {len(tfsec_findings)} findings")

    quality_gate = evaluate_quality_gate(all_findings, args.severity_threshold)

    report = {
        "metadata": {
            "directory": iac_dir,
            "framework": args.framework,
            "scan_date": datetime.now(timezone.utc).isoformat()
        },
        "quality_gate": quality_gate,
        "findings": [
            {
                "check_id": f.check_id, "name": f.check_name,
                "severity": f.severity, "resource": f.resource,
                "file": f.file_path, "lines": f.file_line_range,
                "guideline": f.guideline, "tool": f.tool
            }
            for f in sorted(all_findings, key=lambda x: SEVERITY_MAP.get(x.severity, 3))
        ]
    }

    output_path = os.path.abspath(args.output)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Report: {output_path}")

    if quality_gate["passed"]:
        print(f"\n[PASS] Quality gate passed. {quality_gate['total_findings']} findings, none blocking.")
    else:
        print(f"\n[FAIL] {quality_gate['blocking_count']} blocking findings:")
        for d in quality_gate["blocking_details"][:10]:
            print(f"  [{d['severity']}] {d['check_id']}: {d['resource']} ({d['file']})")

    if args.fail_on_findings and not quality_gate["passed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
