#!/usr/bin/env python3
"""SCA Dependency Scanning with Snyk agent — runs Snyk CLI to test
project dependencies for known vulnerabilities, generates SARIF output,
and enforces quality gates."""

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def run_snyk_test(project_path: str, severity_threshold: str = "low",
                  extra_args: list = None) -> dict:
    """Run snyk test and return parsed JSON results."""
    cmd = ["snyk", "test", "--json", f"--severity-threshold={severity_threshold}"]
    if extra_args:
        cmd.extend(extra_args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                cwd=project_path, timeout=300)
        if result.stdout:
            return json.loads(result.stdout)
        return {"error": result.stderr, "exit_code": result.returncode}
    except subprocess.TimeoutExpired:
        return {"error": "Snyk test timed out after 300s"}
    except FileNotFoundError:
        return {"error": "snyk CLI not found. Install: npm install -g snyk"}
    except json.JSONDecodeError:
        return {"error": "Failed to parse Snyk output", "raw": result.stdout[:2000]}


def run_snyk_monitor(project_path: str) -> dict:
    """Run snyk monitor to create a snapshot for continuous monitoring."""
    cmd = ["snyk", "monitor", "--json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                cwd=project_path, timeout=300)
        if result.stdout:
            return json.loads(result.stdout)
        return {"error": result.stderr}
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
        return {"error": str(e)}


def parse_vulnerabilities(snyk_result: dict) -> list[dict]:
    """Extract and normalize vulnerability findings."""
    vulns = snyk_result.get("vulnerabilities", [])
    findings = []
    for v in vulns:
        findings.append({
            "id": v.get("id", ""),
            "title": v.get("title", ""),
            "severity": v.get("severity", "unknown"),
            "cvss_score": v.get("cvssScore", 0),
            "package": v.get("packageName", ""),
            "version": v.get("version", ""),
            "fixed_in": v.get("fixedIn", []),
            "exploit_maturity": v.get("exploit", "Not Defined"),
            "is_upgradable": v.get("isUpgradable", False),
            "is_patchable": v.get("isPatchable", False),
            "from_path": v.get("from", []),
        })
    return findings


def apply_quality_gate(findings: list[dict], max_critical: int = 0,
                       max_high: int = 5) -> dict:
    """Apply quality gate based on severity counts."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low").lower()
        counts[sev] = counts.get(sev, 0) + 1

    passed = counts["critical"] <= max_critical and counts["high"] <= max_high
    return {
        "passed": passed,
        "severity_counts": counts,
        "gate_criteria": {"max_critical": max_critical, "max_high": max_high},
        "reason": "PASS" if passed else f"FAIL: {counts['critical']} critical (max {max_critical}), {counts['high']} high (max {max_high})",
    }


def generate_sarif(findings: list[dict], project_path: str) -> dict:
    """Convert findings to SARIF 2.1.0 format for GitHub integration."""
    rules = []
    results = []
    seen_ids = set()
    for f in findings:
        rule_id = f["id"]
        if rule_id not in seen_ids:
            rules.append({
                "id": rule_id,
                "shortDescription": {"text": f["title"]},
                "defaultConfiguration": {
                    "level": "error" if f["severity"] in ("critical", "high") else "warning"
                },
            })
            seen_ids.add(rule_id)
        results.append({
            "ruleId": rule_id,
            "message": {"text": f"{f['title']} in {f['package']}@{f['version']}"},
            "level": "error" if f["severity"] in ("critical", "high") else "warning",
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Snyk", "rules": rules}},
            "results": results,
        }],
    }


def generate_report(project_path: str, severity_threshold: str,
                    max_critical: int, max_high: int) -> dict:
    """Run full scan and build consolidated report."""
    snyk_result = run_snyk_test(project_path, severity_threshold)
    if "error" in snyk_result and "vulnerabilities" not in snyk_result:
        return {"report": "sca_dependency_scan", "error": snyk_result["error"]}

    findings = parse_vulnerabilities(snyk_result)
    gate = apply_quality_gate(findings, max_critical, max_high)
    sarif = generate_sarif(findings, project_path)

    return {
        "report": "sca_dependency_scan",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "project_path": project_path,
        "total_vulnerabilities": len(findings),
        "quality_gate": gate,
        "unique_packages_affected": len(set(f["package"] for f in findings)),
        "upgradable_count": sum(1 for f in findings if f["is_upgradable"]),
        "patchable_count": sum(1 for f in findings if f["is_patchable"]),
        "findings": findings,
        "sarif": sarif,
    }


def main():
    parser = argparse.ArgumentParser(description="SCA Dependency Scanning with Snyk Agent")
    parser.add_argument("--project", required=True, help="Project directory to scan")
    parser.add_argument("--severity", default="low", choices=["low", "medium", "high", "critical"])
    parser.add_argument("--max-critical", type=int, default=0, help="Max critical vulns for quality gate")
    parser.add_argument("--max-high", type=int, default=5, help="Max high vulns for quality gate")
    parser.add_argument("--output", help="Output JSON file path")
    args = parser.parse_args()

    report = generate_report(args.project, args.severity, args.max_critical, args.max_high)
    output = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
