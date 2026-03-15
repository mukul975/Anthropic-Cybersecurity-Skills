#!/usr/bin/env python3
"""
OWASP ZAP DAST Pipeline Script

Orchestrates ZAP scans, parses results, evaluates quality gates,
and generates consolidated DAST reports.

Usage:
    python process.py --target http://localhost:8080 --scan-type baseline
    python process.py --target http://staging.example.com --scan-type api --openapi-url /openapi.json
"""

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


RISK_LEVELS = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}


@dataclass
class ZapAlert:
    alert_id: int
    name: str
    risk: str
    confidence: str
    description: str
    url: str
    method: str
    evidence: str
    solution: str
    cwe_id: int = 0
    wasc_id: int = 0
    instances_count: int = 1


def run_zap_scan(target: str, scan_type: str = "baseline",
                 rules_file: Optional[str] = None,
                 openapi_url: Optional[str] = None,
                 report_dir: str = "/tmp/zap") -> dict:
    """Run ZAP scan via Docker and return results."""
    os.makedirs(report_dir, exist_ok=True)

    scan_scripts = {
        "baseline": "zap-baseline.py",
        "full": "zap-full-scan.py",
        "api": "zap-api-scan.py"
    }

    script = scan_scripts.get(scan_type, "zap-baseline.py")

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{report_dir}:/zap/wrk",
        "--network", "host",
        "zaproxy/zap-stable",
        script,
        "-t", target,
        "-J", "report.json",
        "-r", "report.html",
        "-w", "report.md"
    ]

    if rules_file and os.path.exists(rules_file):
        cmd.extend(["-c", f"/zap/wrk/{os.path.basename(rules_file)}"])

    if scan_type == "api" and openapi_url:
        cmd.extend(["-f", "openapi"])

    cmd.extend(["-I"])  # Don't return error on warnings

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

        json_report = os.path.join(report_dir, "report.json")
        if os.path.exists(json_report):
            with open(json_report, "r") as f:
                return json.load(f)

        return {"error": f"No report generated. stderr: {proc.stderr[:300]}"}

    except subprocess.TimeoutExpired:
        return {"error": "ZAP scan timed out after 3600 seconds"}
    except FileNotFoundError:
        return {"error": "Docker not found. Install Docker to run ZAP scans."}


def parse_zap_results(zap_json: dict) -> list:
    """Parse ZAP JSON report into ZapAlert objects."""
    alerts = []

    for site in zap_json.get("site", []):
        for alert in site.get("alerts", []):
            instances = alert.get("instances", [])
            first_instance = instances[0] if instances else {}

            alerts.append(ZapAlert(
                alert_id=int(alert.get("pluginid", 0)),
                name=alert.get("name", ""),
                risk=alert.get("riskdesc", "").split(" ")[0] if alert.get("riskdesc") else "Informational",
                confidence=alert.get("confidence", ""),
                description=alert.get("desc", "")[:300],
                url=first_instance.get("uri", ""),
                method=first_instance.get("method", ""),
                evidence=first_instance.get("evidence", "")[:200],
                solution=alert.get("solution", "")[:300],
                cwe_id=int(alert.get("cweid", 0)),
                wasc_id=int(alert.get("wascid", 0)),
                instances_count=len(instances)
            ))

    return alerts


def apply_rules(alerts: list, rules_file: Optional[str]) -> list:
    """Apply rules.tsv to override alert actions."""
    if not rules_file or not os.path.exists(rules_file):
        return alerts

    rules = {}
    with open(rules_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                rules[int(parts[0])] = parts[1].upper()

    filtered = []
    for alert in alerts:
        action = rules.get(alert.alert_id, "WARN")
        if action != "IGNORE":
            alert.confidence = action  # Reuse field for action tracking
            filtered.append(alert)

    return filtered


def evaluate_quality_gate(alerts: list, threshold: str,
                          rules_file: Optional[str] = None) -> dict:
    """Evaluate quality gate based on alert risk levels."""
    threshold_level = RISK_LEVELS.get(threshold, 1)

    rules = {}
    if rules_file and os.path.exists(rules_file):
        with open(rules_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 2:
                    rules[int(parts[0])] = parts[1].upper()

    blocking = []
    for a in alerts:
        action = rules.get(a.alert_id, "WARN")
        if action == "FAIL" and RISK_LEVELS.get(a.risk, 3) <= threshold_level:
            blocking.append(a)

    risk_counts = {}
    for a in alerts:
        risk_counts[a.risk] = risk_counts.get(a.risk, 0) + 1

    return {
        "passed": len(blocking) == 0,
        "threshold": threshold,
        "total_alerts": len(alerts),
        "blocking_count": len(blocking),
        "risk_counts": risk_counts,
        "blocking_details": [
            {"id": a.alert_id, "name": a.name, "risk": a.risk,
             "url": a.url, "cwe": a.cwe_id}
            for a in blocking[:15]
        ]
    }


def main():
    parser = argparse.ArgumentParser(description="OWASP ZAP DAST Pipeline")
    parser.add_argument("--target", required=True, help="Target URL to scan")
    parser.add_argument("--scan-type", default="baseline", choices=["baseline", "full", "api"])
    parser.add_argument("--rules-file", default=None, help="Path to rules.tsv")
    parser.add_argument("--openapi-url", default=None, help="OpenAPI spec URL for API scan")
    parser.add_argument("--output", default="dast-report.json")
    parser.add_argument("--report-dir", default="/tmp/zap")
    parser.add_argument("--risk-threshold", default="Medium", choices=["High", "Medium", "Low"])
    parser.add_argument("--fail-on-findings", action="store_true")
    args = parser.parse_args()

    print(f"[*] Running ZAP {args.scan_type} scan against {args.target}")

    zap_json = run_zap_scan(
        args.target, args.scan_type,
        rules_file=args.rules_file,
        openapi_url=args.openapi_url,
        report_dir=args.report_dir
    )

    if "error" in zap_json:
        print(f"[ERROR] {zap_json['error']}")
        sys.exit(2)

    alerts = parse_zap_results(zap_json)
    quality_gate = evaluate_quality_gate(alerts, args.risk_threshold, args.rules_file)

    report = {
        "metadata": {
            "target": args.target,
            "scan_type": args.scan_type,
            "scan_date": datetime.now(timezone.utc).isoformat()
        },
        "quality_gate": quality_gate,
        "alerts": [
            {"id": a.alert_id, "name": a.name, "risk": a.risk,
             "url": a.url, "method": a.method, "cwe": a.cwe_id,
             "solution": a.solution, "instances": a.instances_count}
            for a in sorted(alerts, key=lambda x: RISK_LEVELS.get(x.risk, 3))
        ]
    }

    output_path = os.path.abspath(args.output)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Report: {output_path}")

    if quality_gate["passed"]:
        print(f"\n[PASS] Quality gate passed. {quality_gate['total_alerts']} alerts, none blocking.")
    else:
        print(f"\n[FAIL] {quality_gate['blocking_count']} blocking alerts:")
        for d in quality_gate["blocking_details"]:
            print(f"  [{d['risk']}] {d['id']} - {d['name']} ({d['url'][:80]})")

    if args.fail_on_findings and not quality_gate["passed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
