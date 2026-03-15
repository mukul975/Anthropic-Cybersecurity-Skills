#!/usr/bin/env python3
"""Secrets scanning CI/CD gate using gitleaks and trufflehog."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

GITLEAKS_SEVERITY_MAP = {
    "aws-access-key": "critical",
    "aws-secret-key": "critical",
    "github-pat": "critical",
    "private-key": "critical",
    "generic-api-key": "high",
    "slack-webhook": "high",
    "stripe-api-key": "critical",
    "twilio-api-key": "high",
    "sendgrid-api-key": "high",
    "npm-access-token": "high",
    "pypi-upload-token": "high",
    "gcp-api-key": "critical",
    "heroku-api-key": "high",
    "jwt": "medium",
    "password-in-url": "high",
    "generic-password": "medium",
}


def run_gitleaks(scan_path: str) -> list:
    report_file = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    report_path = report_file.name
    report_file.close()
    cmd = [
        "gitleaks", "dir",
        "--source", scan_path,
        "--report-format", "json",
        "--report-path", report_path,
        "--exit-code", "0",
        "--no-banner",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    findings = []
    if os.path.exists(report_path) and os.path.getsize(report_path) > 0:
        with open(report_path, "r") as f:
            raw = json.load(f)
        for item in raw:
            rule_id = item.get("RuleID", "unknown")
            severity = GITLEAKS_SEVERITY_MAP.get(rule_id, "medium")
            secret_val = item.get("Secret", "")
            redacted = secret_val[:4] + "****" if len(secret_val) > 4 else "****"
            findings.append({
                "tool": "gitleaks",
                "rule_id": rule_id,
                "description": item.get("Description", ""),
                "file": item.get("File", ""),
                "line": item.get("StartLine", 0),
                "severity": severity,
                "redacted_secret": redacted,
                "commit": item.get("Commit", ""),
                "author": item.get("Author", ""),
                "entropy": item.get("Entropy", 0.0),
            })
    os.unlink(report_path)
    return findings


def run_trufflehog(scan_path: str) -> list:
    cmd = [
        "trufflehog", "filesystem", scan_path,
        "--json",
        "--no-verification",
        "--concurrency", "10",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    findings = []
    for line in proc.stdout.strip().split("\n"):
        if not line.strip():
            continue
        item = json.loads(line)
        detector = item.get("DetectorName", item.get("DetectorType", "unknown"))
        source_meta = item.get("SourceMetadata", {})
        fs_data = source_meta.get("Data", {}).get("Filesystem", {})
        raw_secret = item.get("Raw", "")
        redacted = raw_secret[:4] + "****" if len(raw_secret) > 4 else "****"
        severity = "critical" if item.get("Verified", False) else "high"
        findings.append({
            "tool": "trufflehog",
            "rule_id": detector,
            "description": f"Detected {detector} secret",
            "file": fs_data.get("file", ""),
            "line": fs_data.get("line", 0),
            "severity": severity,
            "redacted_secret": redacted,
            "verified": item.get("Verified", False),
            "decoder_name": item.get("DecoderName", ""),
        })
    return findings


def evaluate_gate(findings: list, fail_on_severity: str) -> dict:
    threshold = SEVERITY_ORDER.get(fail_on_severity, 2)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "medium")
        counts[sev] = counts.get(sev, 0) + 1
    gate_failed = False
    fail_reasons = []
    for sev, count in counts.items():
        if count > 0 and SEVERITY_ORDER.get(sev, 0) >= threshold:
            gate_failed = True
            fail_reasons.append(f"Found {count} {sev} severity findings")
    return {
        "ci_gate": "FAIL" if gate_failed else "PASS",
        "fail_reason": "; ".join(fail_reasons) if fail_reasons else None,
        "total_findings": len(findings),
        **counts,
    }


def main():
    parser = argparse.ArgumentParser(description="Secrets scanning CI/CD gate")
    parser.add_argument("--path", required=True, help="Path to scan for secrets")
    parser.add_argument("--tool", choices=["gitleaks", "trufflehog", "both"],
                        default="both", help="Scanner tool to use")
    parser.add_argument("--fail-on-severity", choices=["critical", "high", "medium", "low"],
                        default="high", help="Minimum severity to fail CI gate")
    parser.add_argument("--output", default=None, help="Output JSON file path")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(json.dumps({"error": f"Path does not exist: {args.path}"}))
        sys.exit(1)

    start_time = time.time()
    all_findings = []

    if args.tool in ("gitleaks", "both"):
        all_findings.extend(run_gitleaks(args.path))
    if args.tool in ("trufflehog", "both"):
        all_findings.extend(run_trufflehog(args.path))

    gate_result = evaluate_gate(all_findings, args.fail_on_severity)
    elapsed = round(time.time() - start_time, 2)

    report = {
        "scan_summary": {
            "tool": args.tool,
            "scanned_path": args.path,
            "fail_on_severity": args.fail_on_severity,
            "scan_duration_seconds": elapsed,
            **gate_result,
        },
        "findings": all_findings,
    }

    output_json = json.dumps(report, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output_json)
    print(output_json)

    if gate_result["ci_gate"] == "FAIL":
        sys.exit(1)


if __name__ == "__main__":
    main()
