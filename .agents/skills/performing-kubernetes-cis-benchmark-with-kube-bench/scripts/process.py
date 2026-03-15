#!/usr/bin/env python3
"""
kube-bench CIS Benchmark Reporter - Parse kube-bench JSON output
and generate compliance reports with trend tracking.
"""

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime
from collections import Counter


def parse_kube_bench_json(filepath: str) -> dict:
    """Parse kube-bench JSON output file."""
    path = Path(filepath)
    if not path.exists():
        print(f"File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    return json.loads(path.read_text())


def extract_checks(data: dict) -> list:
    """Extract all individual checks from kube-bench results."""
    checks = []
    for control in data.get("Controls", []):
        section = control.get("id", "")
        section_text = control.get("text", "")
        for group in control.get("tests", []):
            group_id = group.get("section", "")
            for result in group.get("results", []):
                checks.append({
                    "section": section,
                    "section_text": section_text,
                    "group": group_id,
                    "id": result.get("test_number", ""),
                    "description": result.get("test_desc", ""),
                    "status": result.get("status", ""),
                    "scored": result.get("scored", False),
                    "remediation": result.get("remediation", ""),
                    "reason": result.get("reason", ""),
                })
    return checks


def generate_summary(checks: list) -> dict:
    """Generate summary statistics."""
    status_counts = Counter(c["status"] for c in checks)
    section_counts = {}
    for c in checks:
        sec = c["section"]
        if sec not in section_counts:
            section_counts[sec] = {"section_text": c["section_text"], "PASS": 0, "FAIL": 0, "WARN": 0, "INFO": 0}
        status = c["status"]
        if status in section_counts[sec]:
            section_counts[sec][status] += 1

    total = len(checks)
    passed = status_counts.get("PASS", 0)
    score = (passed / total * 100) if total > 0 else 0

    return {
        "total_checks": total,
        "pass": status_counts.get("PASS", 0),
        "fail": status_counts.get("FAIL", 0),
        "warn": status_counts.get("WARN", 0),
        "info": status_counts.get("INFO", 0),
        "score_percent": round(score, 1),
        "by_section": section_counts,
    }


def generate_report(data: dict, output_path: str = None) -> str:
    """Generate markdown CIS benchmark report."""
    checks = extract_checks(data)
    summary = generate_summary(checks)
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    report = f"""# CIS Kubernetes Benchmark Report

**Date:** {timestamp}
**Total Checks:** {summary['total_checks']}
**Score:** {summary['score_percent']}%

## Summary

| Status | Count |
|--------|-------|
| PASS | {summary['pass']} |
| FAIL | {summary['fail']} |
| WARN | {summary['warn']} |
| INFO | {summary['info']} |

## Results by Section

| Section | Description | Pass | Fail | Warn |
|---------|-------------|------|------|------|
"""
    for sec_id, sec in sorted(summary["by_section"].items()):
        report += f"| {sec_id} | {sec['section_text']} | {sec['PASS']} | {sec['FAIL']} | {sec['WARN']} |\n"

    failed = [c for c in checks if c["status"] == "FAIL"]
    if failed:
        report += "\n## Failed Checks (Requires Remediation)\n\n"
        for c in failed:
            report += f"### {c['id']} - {c['description']}\n"
            report += f"- **Status:** FAIL\n"
            report += f"- **Scored:** {c['scored']}\n"
            if c['remediation']:
                report += f"- **Remediation:** {c['remediation']}\n"
            report += "\n"

    if output_path:
        Path(output_path).write_text(report)
        print(f"Report written to {output_path}")

    return report


def compare_scans(current_file: str, previous_file: str):
    """Compare two kube-bench scan results."""
    current = extract_checks(parse_kube_bench_json(current_file))
    previous = extract_checks(parse_kube_bench_json(previous_file))

    curr_summary = generate_summary(current)
    prev_summary = generate_summary(previous)

    print("\n=== CIS Benchmark Comparison ===\n")
    print(f"{'Metric':<20} {'Previous':<12} {'Current':<12} {'Change'}")
    print("-" * 55)

    for metric in ["pass", "fail", "warn"]:
        prev_val = prev_summary[metric]
        curr_val = curr_summary[metric]
        change = curr_val - prev_val
        sign = "+" if change > 0 else ""
        print(f"{metric.upper():<20} {prev_val:<12} {curr_val:<12} {sign}{change}")

    print(f"{'SCORE':<20} {prev_summary['score_percent']}%{'':<7} {curr_summary['score_percent']}%")


def main():
    parser = argparse.ArgumentParser(description="kube-bench CIS Benchmark Reporter")
    subparsers = parser.add_subparsers(dest="command")

    report_cmd = subparsers.add_parser("report", help="Generate report from kube-bench JSON")
    report_cmd.add_argument("input", help="kube-bench JSON output file")
    report_cmd.add_argument("--output", "-o", help="Output markdown report path")

    compare_cmd = subparsers.add_parser("compare", help="Compare two scan results")
    compare_cmd.add_argument("current", help="Current scan JSON")
    compare_cmd.add_argument("previous", help="Previous scan JSON")

    summary_cmd = subparsers.add_parser("summary", help="Print summary from JSON")
    summary_cmd.add_argument("input", help="kube-bench JSON output file")

    args = parser.parse_args()

    if args.command == "report":
        data = parse_kube_bench_json(args.input)
        report = generate_report(data, args.output)
        if not args.output:
            print(report)

    elif args.command == "compare":
        compare_scans(args.current, args.previous)

    elif args.command == "summary":
        data = parse_kube_bench_json(args.input)
        checks = extract_checks(data)
        summary = generate_summary(checks)
        print(json.dumps(summary, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
