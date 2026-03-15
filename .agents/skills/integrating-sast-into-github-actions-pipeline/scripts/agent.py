#!/usr/bin/env python3
"""Agent for running Semgrep SAST scans and generating SARIF for GitHub Advanced Security."""

import subprocess
import json
import argparse
import sys
import os
from datetime import datetime


def run_semgrep_scan(target_dir, config="auto", output_format="json"):
    """Run Semgrep SAST scan on a code directory."""
    print(f"[*] Running Semgrep scan on {target_dir} (config={config})...")
    cmd = ["semgrep", "scan", "--config", config, "--json", "--no-git", target_dir]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode not in (0, 1):
        print(f"  [-] Semgrep error: {result.stderr[:300]}")
        return {}
    data = json.loads(result.stdout) if result.stdout else {}
    results = data.get("results", [])
    errors = data.get("errors", [])
    print(f"  Findings: {len(results)}, Errors: {len(errors)}")
    return data


def parse_semgrep_results(scan_data):
    """Parse Semgrep findings into structured format."""
    results = scan_data.get("results", [])
    findings = []
    severity_counts = {}
    for r in results:
        severity = r.get("extra", {}).get("severity", "WARNING")
        finding = {
            "rule_id": r.get("check_id", "unknown"),
            "message": r.get("extra", {}).get("message", ""),
            "severity": severity,
            "file": r.get("path", ""),
            "line": r.get("start", {}).get("line", 0),
            "cwe": r.get("extra", {}).get("metadata", {}).get("cwe", []),
            "owasp": r.get("extra", {}).get("metadata", {}).get("owasp", []),
        }
        findings.append(finding)
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    print(f"\n[*] Severity breakdown:")
    for sev, count in sorted(severity_counts.items()):
        print(f"  {sev}: {count}")
    return findings


def generate_sarif(findings, output_path):
    """Convert Semgrep findings to SARIF 2.1.0 format."""
    rules, results = [], []
    seen_rules = set()
    for f in findings:
        rid = f["rule_id"]
        if rid not in seen_rules:
            rules.append({"id": rid, "shortDescription": {"text": f["message"][:200]},
                           "defaultConfiguration": {"level": "warning"}})
            seen_rules.add(rid)
        results.append({
            "ruleId": rid, "message": {"text": f["message"][:500]},
            "level": "error" if f["severity"] == "ERROR" else "warning",
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f["file"]},
                "region": {"startLine": f["line"]}}}],
        })
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "Semgrep", "rules": rules}},
                        "results": results}]}
    with open(output_path, "w") as f:
        json.dump(sarif, f, indent=2)
    print(f"[*] SARIF report: {output_path}")


def apply_quality_gate(findings, fail_on="ERROR"):
    """Apply quality gate based on severity threshold."""
    severity_order = {"INFO": 0, "WARNING": 1, "ERROR": 2}
    threshold = severity_order.get(fail_on, 2)
    blocking = [f for f in findings if severity_order.get(f["severity"], 0) >= threshold]
    if blocking:
        print(f"\n[!] QUALITY GATE FAILED: {len(blocking)} findings at {fail_on}+")
        for b in blocking[:5]:
            print(f"  {b['file']}:{b['line']} - {b['rule_id']}")
        return False
    print(f"\n[+] Quality gate passed (threshold: {fail_on})")
    return True


def generate_github_actions_workflow(config="auto"):
    """Generate a GitHub Actions SAST workflow YAML."""
    workflow = f"""name: SAST Scan
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: returntocorp/semgrep-action@v1
        with:
          config: {config}
          generateSarif: "1"
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif
        if: always()
"""
    print("[*] Generated GitHub Actions workflow:")
    print(workflow)
    return workflow


def main():
    parser = argparse.ArgumentParser(description="SAST GitHub Actions Pipeline Agent")
    parser.add_argument("action", choices=["scan", "parse", "sarif", "gate", "gen-workflow"])
    parser.add_argument("--target", default=".", help="Directory to scan")
    parser.add_argument("--config", default="auto", help="Semgrep config (auto, p/ci, p/owasp)")
    parser.add_argument("--report", help="Existing Semgrep JSON report")
    parser.add_argument("--fail-on", default="ERROR", choices=["INFO", "WARNING", "ERROR"])
    parser.add_argument("-o", "--output", default=".")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    if args.action == "scan":
        data = run_semgrep_scan(args.target, args.config)
        findings = parse_semgrep_results(data)
        generate_sarif(findings, os.path.join(args.output, "semgrep.sarif"))
        apply_quality_gate(findings, args.fail_on)
    elif args.action == "parse":
        with open(args.report) as f:
            data = json.load(f)
        parse_semgrep_results(data)
    elif args.action == "sarif":
        with open(args.report) as f:
            data = json.load(f)
        findings = parse_semgrep_results(data)
        generate_sarif(findings, os.path.join(args.output, "semgrep.sarif"))
    elif args.action == "gate":
        with open(args.report) as f:
            data = json.load(f)
        findings = parse_semgrep_results(data)
        passed = apply_quality_gate(findings, args.fail_on)
        sys.exit(0 if passed else 1)
    elif args.action == "gen-workflow":
        generate_github_actions_workflow(args.config)


if __name__ == "__main__":
    main()
