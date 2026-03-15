#!/usr/bin/env python3
"""
Snyk SCA Dependency Scanning Pipeline Script

Orchestrates Snyk dependency scans, evaluates quality gates,
and generates consolidated vulnerability reports.

Usage:
    python process.py --project-path /path/to/project --severity-threshold high
    python process.py --project-path . --manifest package.json --output report.json
"""

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class VulnFinding:
    snyk_id: str
    title: str
    severity: str
    cvss_score: float
    package_name: str
    installed_version: str
    fixed_version: str
    exploit_maturity: str
    is_upgradable: bool
    is_patchable: bool
    dependency_path: list = field(default_factory=list)
    cwe: list = field(default_factory=list)


@dataclass
class LicenseIssue:
    package_name: str
    version: str
    license_id: str
    severity: str
    dependency_type: str


def run_snyk_test(project_path: str, manifest: Optional[str] = None,
                  severity_threshold: str = "low",
                  all_projects: bool = False) -> dict:
    """Execute Snyk test and return JSON results."""
    cmd = ["snyk", "test", "--json"]

    if manifest:
        cmd.extend(["--file", manifest])
    if all_projects:
        cmd.append("--all-projects")
    cmd.extend(["--severity-threshold", severity_threshold])

    try:
        proc = subprocess.run(
            cmd,
            cwd=project_path,
            capture_output=True,
            text=True,
            timeout=300
        )

        if proc.stdout:
            try:
                return json.loads(proc.stdout)
            except json.JSONDecodeError:
                return {"error": "Failed to parse Snyk JSON output"}
        return {"error": proc.stderr[:500]}

    except subprocess.TimeoutExpired:
        return {"error": "Snyk test timed out after 300 seconds"}
    except FileNotFoundError:
        return {"error": "snyk CLI not found. Install with: npm install -g snyk"}


def parse_vulnerabilities(snyk_json: dict) -> list:
    """Parse Snyk JSON output into VulnFinding objects."""
    vulns = []
    vuln_list = snyk_json.get("vulnerabilities", [])

    for v in vuln_list:
        vulns.append(VulnFinding(
            snyk_id=v.get("id", ""),
            title=v.get("title", ""),
            severity=v.get("severity", "low"),
            cvss_score=v.get("cvssScore", 0.0),
            package_name=v.get("packageName", ""),
            installed_version=v.get("version", ""),
            fixed_version=v.get("fixedIn", ["none"])[0] if v.get("fixedIn") else "none",
            exploit_maturity=v.get("exploit", "No Known Exploit"),
            is_upgradable=v.get("isUpgradable", False),
            is_patchable=v.get("isPatchable", False),
            dependency_path=v.get("from", []),
            cwe=v.get("identifiers", {}).get("CWE", [])
        ))

    return vulns


def deduplicate_vulns(vulns: list) -> list:
    """Remove duplicate vulnerability entries (same ID + package)."""
    seen = set()
    unique = []
    for v in vulns:
        key = f"{v.snyk_id}:{v.package_name}:{v.installed_version}"
        if key not in seen:
            seen.add(key)
            unique.append(v)
    return unique


def evaluate_quality_gate(vulns: list, threshold: str,
                          fail_on: str = "all") -> dict:
    """Evaluate quality gate based on vulnerability severity."""
    threshold_level = SEVERITY_ORDER.get(threshold.lower(), 1)

    blocking = []
    for v in vulns:
        if SEVERITY_ORDER.get(v.severity.lower(), 3) <= threshold_level:
            if fail_on == "upgradable" and not v.is_upgradable:
                continue
            blocking.append(v)

    severity_counts = {}
    for v in vulns:
        sev = v.severity.lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    fixable_count = sum(1 for v in vulns if v.is_upgradable or v.is_patchable)

    return {
        "passed": len(blocking) == 0,
        "threshold": threshold,
        "fail_on": fail_on,
        "total_vulnerabilities": len(vulns),
        "blocking_count": len(blocking),
        "fixable_count": fixable_count,
        "severity_counts": severity_counts,
        "blocking_details": [
            {
                "id": v.snyk_id,
                "title": v.title,
                "severity": v.severity,
                "package": f"{v.package_name}@{v.installed_version}",
                "fix": v.fixed_version,
                "upgradable": v.is_upgradable,
                "exploit": v.exploit_maturity
            }
            for v in blocking[:20]
        ]
    }


def generate_report(vulns: list, quality_gate: dict, snyk_json: dict,
                    project_path: str) -> dict:
    """Generate consolidated SCA report."""
    dep_count = snyk_json.get("dependencyCount", 0)

    exploit_summary = {}
    for v in vulns:
        exploit_summary[v.exploit_maturity] = exploit_summary.get(v.exploit_maturity, 0) + 1

    return {
        "report_metadata": {
            "project": project_path,
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "total_dependencies": dep_count
        },
        "quality_gate": quality_gate,
        "exploit_maturity_breakdown": exploit_summary,
        "vulnerabilities": [
            {
                "id": v.snyk_id,
                "title": v.title,
                "severity": v.severity,
                "cvss": v.cvss_score,
                "package": v.package_name,
                "version": v.installed_version,
                "fixed_in": v.fixed_version,
                "exploit": v.exploit_maturity,
                "upgradable": v.is_upgradable,
                "path": " > ".join(v.dependency_path[:4]),
                "cwe": v.cwe
            }
            for v in sorted(vulns, key=lambda x: SEVERITY_ORDER.get(x.severity.lower(), 3))
        ]
    }


def main():
    parser = argparse.ArgumentParser(description="Snyk SCA Dependency Scanning Pipeline")
    parser.add_argument("--project-path", required=True, help="Path to project")
    parser.add_argument("--manifest", default=None, help="Manifest file (e.g., package.json)")
    parser.add_argument("--output", default="snyk-report.json", help="Output report path")
    parser.add_argument("--severity-threshold", default="high",
                        choices=["critical", "high", "medium", "low"])
    parser.add_argument("--fail-on", default="all", choices=["all", "upgradable"],
                        help="Fail on all vulns or only upgradable ones")
    parser.add_argument("--fail-on-findings", action="store_true")
    parser.add_argument("--all-projects", action="store_true",
                        help="Scan all projects in monorepo")
    parser.add_argument("--monitor", action="store_true",
                        help="Also run snyk monitor for continuous tracking")
    args = parser.parse_args()

    project_path = os.path.abspath(args.project_path)
    print(f"[*] Scanning dependencies in {project_path}")

    snyk_json = run_snyk_test(
        project_path,
        manifest=args.manifest,
        severity_threshold="low",
        all_projects=args.all_projects
    )

    if "error" in snyk_json:
        print(f"[ERROR] {snyk_json['error']}")
        sys.exit(2)

    vulns = parse_vulnerabilities(snyk_json)
    vulns = deduplicate_vulns(vulns)

    quality_gate = evaluate_quality_gate(vulns, args.severity_threshold, args.fail_on)
    report = generate_report(vulns, quality_gate, snyk_json, project_path)

    output_path = os.path.abspath(args.output)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Report: {output_path}")

    print(f"\n[*] Dependencies: {snyk_json.get('dependencyCount', 'N/A')}")
    print(f"[*] Vulnerabilities: {len(vulns)} (fixable: {quality_gate['fixable_count']})")
    for sev, count in sorted(quality_gate["severity_counts"].items(),
                             key=lambda x: SEVERITY_ORDER.get(x[0], 3)):
        print(f"    {sev.upper()}: {count}")

    if quality_gate["passed"]:
        print(f"\n[PASS] Quality gate passed.")
    else:
        print(f"\n[FAIL] {quality_gate['blocking_count']} blocking vulnerabilities.")
        for d in quality_gate["blocking_details"][:10]:
            fix_info = f"fix: {d['fix']}" if d['upgradable'] else "no fix available"
            print(f"  [{d['severity'].upper()}] {d['id']}: {d['package']} ({fix_info})")

    if args.monitor:
        print("\n[*] Running Snyk monitor for continuous tracking...")
        subprocess.run(
            ["snyk", "monitor", "--project-name", os.path.basename(project_path)],
            cwd=project_path
        )

    if args.fail_on_findings and not quality_gate["passed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
