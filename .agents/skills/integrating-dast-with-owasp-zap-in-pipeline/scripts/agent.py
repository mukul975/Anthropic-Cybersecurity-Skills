#!/usr/bin/env python3
"""Agent for running OWASP ZAP DAST scans and parsing results for CI/CD integration."""

import subprocess
import json
import argparse
import sys
import os
from datetime import datetime


def run_baseline_scan(target_url, output_dir):
    """Run ZAP baseline scan (passive only, fast)."""
    print(f"[*] Running ZAP baseline scan on {target_url}...")
    report_path = os.path.join(output_dir, "zap_baseline.json")
    cmd = ["docker", "run", "--rm", "-v", f"{os.path.abspath(output_dir)}:/zap/wrk",
           "zaproxy/zap-stable", "zap-baseline.py", "-t", target_url,
           "-J", "zap_baseline.json", "-I"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    print(f"  Return code: {result.returncode} (0=pass, 1=warn, 2=fail)")
    return report_path, result.returncode


def run_full_scan(target_url, output_dir, mins=5):
    """Run ZAP full scan (active + passive, slower)."""
    print(f"[*] Running ZAP full scan on {target_url} ({mins} min)...")
    report_path = os.path.join(output_dir, "zap_full.json")
    cmd = ["docker", "run", "--rm", "-v", f"{os.path.abspath(output_dir)}:/zap/wrk",
           "zaproxy/zap-stable", "zap-full-scan.py", "-t", target_url,
           "-J", "zap_full.json", "-m", str(mins), "-I"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=mins * 120)
    print(f"  Return code: {result.returncode}")
    return report_path, result.returncode


def run_api_scan(target_spec, output_dir, spec_format="openapi"):
    """Run ZAP API scan against an OpenAPI/Swagger spec."""
    print(f"[*] Running ZAP API scan with {spec_format} spec...")
    report_path = os.path.join(output_dir, "zap_api.json")
    cmd = ["docker", "run", "--rm", "-v", f"{os.path.abspath(output_dir)}:/zap/wrk",
           "zaproxy/zap-stable", "zap-api-scan.py", "-t", target_spec,
           "-f", spec_format, "-J", "zap_api.json", "-I"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    print(f"  Return code: {result.returncode}")
    return report_path, result.returncode


def parse_zap_report(report_path):
    """Parse ZAP JSON report and extract findings by risk level."""
    if not os.path.exists(report_path):
        print(f"  [-] Report not found: {report_path}")
        return []
    with open(report_path) as f:
        data = json.load(f)
    alerts = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            alerts.append({
                "name": alert.get("name"), "risk": alert.get("riskdesc", "").split()[0],
                "confidence": alert.get("confidence"), "count": alert.get("count", 0),
                "cweid": alert.get("cweid"), "wascid": alert.get("wascid"),
                "solution": alert.get("solution", "")[:200],
            })
    risk_counts = {}
    for a in alerts:
        risk_counts[a["risk"]] = risk_counts.get(a["risk"], 0) + 1
    print(f"\n[*] Findings: {len(alerts)} unique alerts")
    for risk, count in sorted(risk_counts.items()):
        print(f"  {risk}: {count}")
    return alerts


def apply_quality_gate(alerts, fail_on="High"):
    """Apply quality gate: fail if findings at or above threshold."""
    severity_order = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}
    threshold = severity_order.get(fail_on, 3)
    blocking = [a for a in alerts if severity_order.get(a.get("risk", ""), 0) >= threshold]
    if blocking:
        print(f"\n[!] QUALITY GATE FAILED: {len(blocking)} findings at {fail_on}+ severity")
        for b in blocking[:5]:
            print(f"  - {b['risk']}: {b['name']}")
        return False
    print(f"\n[+] Quality gate passed (threshold: {fail_on})")
    return True


def generate_sarif(alerts, output_path):
    """Convert ZAP findings to SARIF format for GitHub Advanced Security."""
    rules, results = [], []
    for i, a in enumerate(alerts):
        rule_id = f"ZAP-{a.get('cweid', i)}"
        rules.append({"id": rule_id, "shortDescription": {"text": a["name"]},
                       "defaultConfiguration": {"level": "warning"}})
        results.append({"ruleId": rule_id, "message": {"text": a["name"]},
                         "level": "warning" if a["risk"] != "High" else "error"})
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "OWASP ZAP", "rules": rules}},
                        "results": results}]}
    with open(output_path, "w") as f:
        json.dump(sarif, f, indent=2)
    print(f"[*] SARIF report: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="OWASP ZAP DAST Pipeline Agent")
    parser.add_argument("action", choices=["baseline", "full", "api", "parse", "gate"])
    parser.add_argument("--target", help="Target URL or API spec URL")
    parser.add_argument("--report", help="Path to existing ZAP JSON report")
    parser.add_argument("--fail-on", default="High", choices=["Low", "Medium", "High"])
    parser.add_argument("--scan-mins", type=int, default=5)
    parser.add_argument("-o", "--output", default=".")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    if args.action == "baseline":
        rpt, _ = run_baseline_scan(args.target, args.output)
        alerts = parse_zap_report(rpt)
        apply_quality_gate(alerts, args.fail_on)
    elif args.action == "full":
        rpt, _ = run_full_scan(args.target, args.output, args.scan_mins)
        alerts = parse_zap_report(rpt)
        apply_quality_gate(alerts, args.fail_on)
    elif args.action == "api":
        rpt, _ = run_api_scan(args.target, args.output)
        alerts = parse_zap_report(rpt)
        apply_quality_gate(alerts, args.fail_on)
    elif args.action == "parse":
        alerts = parse_zap_report(args.report)
        generate_sarif(alerts, os.path.join(args.output, "zap.sarif"))
    elif args.action == "gate":
        alerts = parse_zap_report(args.report)
        passed = apply_quality_gate(alerts, args.fail_on)
        sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
