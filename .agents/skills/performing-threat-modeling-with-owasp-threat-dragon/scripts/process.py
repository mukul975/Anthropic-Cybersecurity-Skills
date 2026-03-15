#!/usr/bin/env python3
"""
OWASP Threat Dragon Model Analyzer

Parses Threat Dragon JSON threat model files and generates
summary statistics, coverage reports, and mitigation gap analysis.
"""

import json
import sys
import os
from collections import defaultdict
from datetime import datetime


def load_threat_model(filepath: str) -> dict:
    with open(filepath) as f:
        return json.load(f)


def extract_threats(model: dict) -> list:
    threats = []
    detail = model.get("detail", {})
    for diagram in detail.get("diagrams", []):
        diagram_title = diagram.get("title", "Untitled")
        for cell in diagram.get("cells", []):
            cell_data = cell.get("data", {})
            cell_threats = cell_data.get("threats", [])
            for threat in cell_threats:
                threats.append({
                    "diagram": diagram_title,
                    "element": cell_data.get("name", cell.get("id", "unknown")),
                    "element_type": cell_data.get("type", "unknown"),
                    "title": threat.get("title", ""),
                    "description": threat.get("description", ""),
                    "severity": threat.get("severity", "Unknown"),
                    "status": threat.get("status", "Open"),
                    "type": threat.get("type", ""),
                    "mitigation": threat.get("mitigation", ""),
                    "model_type": threat.get("modelType", "STRIDE"),
                })
    return threats


def analyze_coverage(threats: list) -> dict:
    coverage = {
        "total_threats": len(threats),
        "by_status": defaultdict(int),
        "by_severity": defaultdict(int),
        "by_type": defaultdict(int),
        "by_element_type": defaultdict(int),
        "mitigated_count": 0,
        "open_count": 0,
        "not_applicable_count": 0,
        "with_mitigation_text": 0,
    }

    for threat in threats:
        status = threat["status"]
        coverage["by_status"][status] += 1
        coverage["by_severity"][threat["severity"]] += 1
        coverage["by_type"][threat["type"]] += 1
        coverage["by_element_type"][threat["element_type"]] += 1

        if status.lower() == "mitigated":
            coverage["mitigated_count"] += 1
        elif status.lower() == "open":
            coverage["open_count"] += 1
        elif status.lower() in ("not applicable", "n/a"):
            coverage["not_applicable_count"] += 1

        if threat["mitigation"].strip():
            coverage["with_mitigation_text"] += 1

    coverage["by_status"] = dict(coverage["by_status"])
    coverage["by_severity"] = dict(coverage["by_severity"])
    coverage["by_type"] = dict(coverage["by_type"])
    coverage["by_element_type"] = dict(coverage["by_element_type"])
    return coverage


def identify_gaps(threats: list) -> list:
    gaps = []
    for threat in threats:
        if threat["status"].lower() == "open" and not threat["mitigation"].strip():
            gaps.append({
                "diagram": threat["diagram"],
                "element": threat["element"],
                "threat_title": threat["title"],
                "severity": threat["severity"],
                "type": threat["type"],
            })
    return sorted(gaps, key=lambda g: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(g["severity"], 4))


def stride_coverage_check(threats: list) -> dict:
    stride_categories = {
        "Spoofing": False,
        "Tampering": False,
        "Repudiation": False,
        "Information disclosure": False,
        "Denial of service": False,
        "Elevation of privilege": False,
    }
    for threat in threats:
        threat_type = threat.get("type", "")
        for category in stride_categories:
            if category.lower() in threat_type.lower():
                stride_categories[category] = True
    return stride_categories


def print_report(model: dict, coverage: dict, gaps: list, stride: dict) -> None:
    summary = model.get("summary", {})
    print(f"\n{'='*60}")
    print(f"Threat Model Analysis Report")
    print(f"{'='*60}")
    print(f"Title: {summary.get('title', 'Unknown')}")
    print(f"Owner: {summary.get('owner', 'Unknown')}")
    print(f"Description: {summary.get('description', '')}")
    print(f"Generated: {datetime.utcnow().isoformat()}Z")

    diagrams = model.get("detail", {}).get("diagrams", [])
    print(f"\nDiagrams: {len(diagrams)}")
    for d in diagrams:
        print(f"  - {d.get('title', 'Untitled')} ({d.get('diagramType', 'Unknown')} type)")

    print(f"\nThreat Summary:")
    print(f"  Total threats: {coverage['total_threats']}")
    print(f"  Mitigated: {coverage['mitigated_count']}")
    print(f"  Open: {coverage['open_count']}")
    print(f"  Not Applicable: {coverage['not_applicable_count']}")
    print(f"  With mitigation documented: {coverage['with_mitigation_text']}")

    if coverage["total_threats"] > 0:
        mitigation_rate = coverage["mitigated_count"] / coverage["total_threats"] * 100
        print(f"  Mitigation rate: {mitigation_rate:.1f}%")

    print(f"\nBy Severity:")
    for sev in ["Critical", "High", "Medium", "Low", "Unknown"]:
        count = coverage["by_severity"].get(sev, 0)
        if count:
            print(f"  {sev:12s}: {count}")

    print(f"\nSTRIDE Coverage:")
    for category, covered in stride.items():
        status = "COVERED" if covered else "MISSING"
        print(f"  {category:25s}: {status}")

    if gaps:
        print(f"\nMitigation Gaps ({len(gaps)} open threats without mitigations):")
        for gap in gaps:
            print(f"  [{gap['severity']}] {gap['threat_title']}")
            print(f"    Element: {gap['element']} | Diagram: {gap['diagram']}")
    else:
        print(f"\nNo mitigation gaps found.")


def main():
    if len(sys.argv) < 2:
        print("Usage: python process.py <threat_model.json>")
        print("  Analyzes an OWASP Threat Dragon JSON threat model file")
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        sys.exit(1)

    model = load_threat_model(filepath)
    threats = extract_threats(model)
    coverage = analyze_coverage(threats)
    gaps = identify_gaps(threats)
    stride = stride_coverage_check(threats)
    print_report(model, coverage, gaps, stride)

    output = filepath.replace(".json", "_analysis.json")
    analysis = {
        "model_title": model.get("summary", {}).get("title"),
        "analysis_date": datetime.utcnow().isoformat() + "Z",
        "coverage": coverage,
        "gaps": gaps,
        "stride_coverage": stride,
    }
    with open(output, "w") as f:
        json.dump(analysis, f, indent=2)
    print(f"\nAnalysis saved to: {output}")


if __name__ == "__main__":
    main()
