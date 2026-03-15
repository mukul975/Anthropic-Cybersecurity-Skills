#!/usr/bin/env python3
"""
CIS Benchmark Compliance Processor

Parses CIS-CAT Pro XML assessment results, calculates compliance scores,
identifies failed controls, and generates remediation reports.
"""

import xml.etree.ElementTree as ET
import json
import csv
import sys
import os
from datetime import datetime
from collections import defaultdict


def parse_ciscat_xccdf_results(xml_path: str) -> dict:
    """Parse CIS-CAT XCCDF results XML into structured findings."""
    tree = ET.parse(xml_path)
    root = tree.getroot()

    ns = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "cpe": "http://cpe.mitre.org/dictionary/2.0",
    }

    results = {
        "benchmark_id": "",
        "benchmark_title": "",
        "profile": "",
        "target": "",
        "scan_date": "",
        "total_rules": 0,
        "passed": 0,
        "failed": 0,
        "not_applicable": 0,
        "error": 0,
        "score": 0.0,
        "findings": [],
    }

    benchmark = root.find(".//xccdf:benchmark", ns)
    if benchmark is not None:
        results["benchmark_id"] = benchmark.get("id", "")

    title = root.find(".//xccdf:title", ns)
    if title is not None:
        results["benchmark_title"] = title.text or ""

    test_result = root.find(".//xccdf:TestResult", ns)
    if test_result is not None:
        results["scan_date"] = test_result.get("end-time", "")
        target = test_result.find("xccdf:target", ns)
        if target is not None:
            results["target"] = target.text or ""

        profile = test_result.find("xccdf:profile", ns)
        if profile is not None:
            results["profile"] = profile.get("idref", "")

        for rule_result in test_result.findall("xccdf:rule-result", ns):
            rule_id = rule_result.get("idref", "")
            result_elem = rule_result.find("xccdf:result", ns)
            result_value = result_elem.text if result_elem is not None else "unknown"

            results["total_rules"] += 1

            if result_value == "pass":
                results["passed"] += 1
            elif result_value == "fail":
                results["failed"] += 1
                results["findings"].append(
                    {
                        "rule_id": rule_id,
                        "result": "FAIL",
                        "severity": rule_result.get("severity", "unknown"),
                    }
                )
            elif result_value == "notapplicable":
                results["not_applicable"] += 1
            else:
                results["error"] += 1

    scored_rules = results["passed"] + results["failed"]
    if scored_rules > 0:
        results["score"] = round((results["passed"] / scored_rules) * 100, 2)

    return results


def generate_remediation_csv(findings: list, output_path: str) -> None:
    """Generate CSV of failed controls for remediation tracking."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "Rule ID",
                "Severity",
                "Result",
                "Remediation Status",
                "Assigned To",
                "Due Date",
                "Notes",
            ]
        )
        for finding in findings:
            writer.writerow(
                [
                    finding["rule_id"],
                    finding["severity"],
                    finding["result"],
                    "Open",
                    "",
                    "",
                    "",
                ]
            )


def compare_scan_results(current: dict, previous: dict) -> dict:
    """Compare two CIS-CAT scan results to detect compliance drift."""
    drift = {
        "current_score": current["score"],
        "previous_score": previous["score"],
        "score_delta": round(current["score"] - previous["score"], 2),
        "new_failures": [],
        "resolved_failures": [],
        "persistent_failures": [],
    }

    current_failed = {f["rule_id"] for f in current["findings"]}
    previous_failed = {f["rule_id"] for f in previous["findings"]}

    drift["new_failures"] = sorted(current_failed - previous_failed)
    drift["resolved_failures"] = sorted(previous_failed - current_failed)
    drift["persistent_failures"] = sorted(current_failed & previous_failed)

    return drift


def generate_compliance_report(results: dict, output_path: str) -> None:
    """Generate a compliance summary report in JSON format."""
    report = {
        "report_generated": datetime.utcnow().isoformat() + "Z",
        "benchmark": results["benchmark_title"],
        "profile": results["profile"],
        "target_host": results["target"],
        "scan_date": results["scan_date"],
        "compliance_score": results["score"],
        "summary": {
            "total_rules_assessed": results["total_rules"],
            "passed": results["passed"],
            "failed": results["failed"],
            "not_applicable": results["not_applicable"],
            "errors": results["error"],
        },
        "failed_controls": results["findings"],
        "compliance_status": "COMPLIANT"
        if results["score"] >= 95.0
        else "NON-COMPLIANT",
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


def categorize_findings_by_section(findings: list) -> dict:
    """Group failed findings by CIS benchmark section for prioritized remediation."""
    sections = defaultdict(list)

    section_map = {
        "1.1": "Password Policy",
        "1.2": "Account Lockout Policy",
        "2.2": "User Rights Assignment",
        "2.3": "Security Options",
        "5": "System Services",
        "9": "Windows Firewall",
        "17": "Advanced Audit Policy",
        "18": "Administrative Templates",
        "19": "Administrative Templates (User)",
    }

    for finding in findings:
        rule_id = finding["rule_id"]
        categorized = False
        for prefix, section_name in section_map.items():
            if f"_section_{prefix}" in rule_id.lower() or f".{prefix}." in rule_id:
                sections[section_name].append(finding)
                categorized = True
                break
        if not categorized:
            sections["Other"].append(finding)

    return dict(sections)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python process.py <ciscat-results.xml> [previous-results.xml]")
        print()
        print("Parses CIS-CAT XCCDF results and generates compliance reports.")
        print()
        print("Arguments:")
        print("  ciscat-results.xml      Current CIS-CAT assessment results")
        print("  previous-results.xml    (Optional) Previous results for drift detection")
        sys.exit(1)

    xml_path = sys.argv[1]
    if not os.path.exists(xml_path):
        print(f"Error: File not found: {xml_path}")
        sys.exit(1)

    results = parse_ciscat_xccdf_results(xml_path)
    base_name = os.path.splitext(os.path.basename(xml_path))[0]
    output_dir = os.path.dirname(xml_path) or "."

    report_path = os.path.join(output_dir, f"{base_name}_compliance_report.json")
    generate_compliance_report(results, report_path)
    print(f"Compliance report: {report_path}")

    if results["findings"]:
        csv_path = os.path.join(output_dir, f"{base_name}_remediation.csv")
        generate_remediation_csv(results["findings"], csv_path)
        print(f"Remediation tracker: {csv_path}")

    print(f"\nCompliance Score: {results['score']}%")
    print(f"Status: {'COMPLIANT' if results['score'] >= 95.0 else 'NON-COMPLIANT'}")
    print(f"Passed: {results['passed']} | Failed: {results['failed']} | N/A: {results['not_applicable']}")

    if len(sys.argv) >= 3:
        prev_path = sys.argv[2]
        if os.path.exists(prev_path):
            prev_results = parse_ciscat_xccdf_results(prev_path)
            drift = compare_scan_results(results, prev_results)
            drift_path = os.path.join(output_dir, f"{base_name}_drift.json")
            with open(drift_path, "w") as f:
                json.dump(drift, f, indent=2)
            print(f"\nDrift report: {drift_path}")
            print(f"Score delta: {drift['score_delta']:+.2f}%")
            print(f"New failures: {len(drift['new_failures'])}")
            print(f"Resolved: {len(drift['resolved_failures'])}")
