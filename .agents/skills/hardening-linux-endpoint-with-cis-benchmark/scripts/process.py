#!/usr/bin/env python3
"""Linux CIS Benchmark Compliance Processor - Parses OpenSCAP XCCDF results."""

import xml.etree.ElementTree as ET
import json
import csv
import sys
import os
from datetime import datetime


def parse_oscap_results(xml_path: str) -> dict:
    """Parse OpenSCAP XCCDF results XML."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}

    results = {"total": 0, "passed": 0, "failed": 0, "notapplicable": 0,
               "findings": [], "score": 0.0}

    for rr in root.iter():
        if rr.tag.endswith("}rule-result"):
            results["total"] += 1
            result_elem = None
            for child in rr:
                if child.tag.endswith("}result"):
                    result_elem = child
            if result_elem is not None:
                val = result_elem.text
                if val == "pass":
                    results["passed"] += 1
                elif val == "fail":
                    results["failed"] += 1
                    results["findings"].append({
                        "rule_id": rr.get("idref", ""),
                        "severity": rr.get("severity", ""),
                        "result": "FAIL",
                    })
                elif val == "notapplicable":
                    results["notapplicable"] += 1

    scored = results["passed"] + results["failed"]
    if scored > 0:
        results["score"] = round((results["passed"] / scored) * 100, 2)
    return results


def generate_report(results: dict, output_path: str) -> None:
    """Generate compliance report."""
    report = {
        "report_generated": datetime.utcnow().isoformat() + "Z",
        "score": results["score"],
        "total": results["total"],
        "passed": results["passed"],
        "failed": results["failed"],
        "not_applicable": results["notapplicable"],
        "status": "COMPLIANT" if results["score"] >= 95 else "NON-COMPLIANT",
        "failed_controls": results["findings"][:100],
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python process.py <oscap_results.xml>")
        sys.exit(1)
    results = parse_oscap_results(sys.argv[1])
    out = os.path.join(os.path.dirname(sys.argv[1]) or ".", "linux_cis_report.json")
    generate_report(results, out)
    print(f"Score: {results['score']}% | Passed: {results['passed']} | Failed: {results['failed']}")
