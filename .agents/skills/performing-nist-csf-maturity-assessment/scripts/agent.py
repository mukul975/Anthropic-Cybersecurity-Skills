#!/usr/bin/env python3
"""Agent for performing NIST Cybersecurity Framework (CSF) maturity assessment."""

import json
import argparse
import csv
from datetime import datetime
from pathlib import Path


NIST_CSF_FUNCTIONS = {
    "IDENTIFY": {
        "categories": ["ID.AM", "ID.BE", "ID.GV", "ID.RA", "ID.RM", "ID.SC"],
        "descriptions": {
            "ID.AM": "Asset Management",
            "ID.BE": "Business Environment",
            "ID.GV": "Governance",
            "ID.RA": "Risk Assessment",
            "ID.RM": "Risk Management Strategy",
            "ID.SC": "Supply Chain Risk Management",
        },
    },
    "PROTECT": {
        "categories": ["PR.AC", "PR.AT", "PR.DS", "PR.IP", "PR.MA", "PR.PT"],
        "descriptions": {
            "PR.AC": "Identity Management & Access Control",
            "PR.AT": "Awareness and Training",
            "PR.DS": "Data Security",
            "PR.IP": "Information Protection Processes",
            "PR.MA": "Maintenance",
            "PR.PT": "Protective Technology",
        },
    },
    "DETECT": {
        "categories": ["DE.AE", "DE.CM", "DE.DP"],
        "descriptions": {
            "DE.AE": "Anomalies and Events",
            "DE.CM": "Security Continuous Monitoring",
            "DE.DP": "Detection Processes",
        },
    },
    "RESPOND": {
        "categories": ["RS.RP", "RS.CO", "RS.AN", "RS.MI", "RS.IM"],
        "descriptions": {
            "RS.RP": "Response Planning",
            "RS.CO": "Communications",
            "RS.AN": "Analysis",
            "RS.MI": "Mitigation",
            "RS.IM": "Improvements",
        },
    },
    "RECOVER": {
        "categories": ["RC.RP", "RC.IM", "RC.CO"],
        "descriptions": {
            "RC.RP": "Recovery Planning",
            "RC.IM": "Improvements",
            "RC.CO": "Communications",
        },
    },
}

MATURITY_LEVELS = {
    1: "Partial — Risk management practices not formalized",
    2: "Risk Informed — Risk management approved but not org-wide",
    3: "Repeatable — Policies and practices formally approved and expressed as policy",
    4: "Adaptive — Organization adapts based on lessons learned and predictive indicators",
}


def assess_from_csv(assessment_file):
    """Load assessment responses from CSV and calculate maturity scores."""
    with open(assessment_file, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    scores = {}
    for row in rows:
        category = row.get("category", row.get("Category", row.get("subcategory", "")))
        score = int(row.get("score", row.get("maturity_level", row.get("Score", 0))))
        target = int(row.get("target", row.get("Target", 3)))
        function_name = ""
        for fn, data in NIST_CSF_FUNCTIONS.items():
            if any(category.startswith(c) for c in data["categories"]):
                function_name = fn
                break
        scores.setdefault(function_name or "UNKNOWN", []).append({
            "category": category, "score": score, "target": target, "gap": target - score,
        })
    function_scores = {}
    for fn, items in scores.items():
        avg = sum(i["score"] for i in items) / len(items) if items else 0
        avg_target = sum(i["target"] for i in items) / len(items) if items else 0
        function_scores[fn] = {
            "average_maturity": round(avg, 1),
            "target_maturity": round(avg_target, 1),
            "gap": round(avg_target - avg, 1),
            "categories_assessed": len(items),
            "below_target": sum(1 for i in items if i["gap"] > 0),
        }
    overall = sum(fs["average_maturity"] for fs in function_scores.values()) / max(len(function_scores), 1)
    return {
        "assessment_file": assessment_file,
        "overall_maturity": round(overall, 1),
        "overall_level": MATURITY_LEVELS.get(round(overall), "Unknown"),
        "function_scores": function_scores,
        "total_categories": sum(fs["categories_assessed"] for fs in function_scores.values()),
        "categories_below_target": sum(fs["below_target"] for fs in function_scores.values()),
    }


def generate_gap_analysis(assessment_file):
    """Generate detailed gap analysis with prioritized recommendations."""
    assessment = assess_from_csv(assessment_file)
    gaps = []
    for fn, data in assessment["function_scores"].items():
        if data["gap"] > 0:
            gaps.append({
                "function": fn, "current": data["average_maturity"],
                "target": data["target_maturity"], "gap": data["gap"],
                "priority": "HIGH" if data["gap"] >= 2 else "MEDIUM" if data["gap"] >= 1 else "LOW",
            })
    gaps.sort(key=lambda x: x["gap"], reverse=True)
    return {
        "generated": datetime.utcnow().isoformat(),
        "overall_maturity": assessment["overall_maturity"],
        "gaps": gaps,
        "high_priority_gaps": [g for g in gaps if g["priority"] == "HIGH"],
    }


def create_assessment_template(output_file=None):
    """Create a blank NIST CSF assessment CSV template."""
    rows = [["category", "description", "score", "target", "evidence", "notes"]]
    for fn, data in NIST_CSF_FUNCTIONS.items():
        for cat in data["categories"]:
            rows.append([cat, data["descriptions"].get(cat, ""), "", "3", "", ""])
    if output_file:
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(rows)
    return {"template_rows": len(rows) - 1, "functions": list(NIST_CSF_FUNCTIONS.keys()),
            "output": output_file, "categories": [r[0] for r in rows[1:]]}


def generate_executive_summary(assessment_file):
    """Generate executive-level maturity summary."""
    assessment = assess_from_csv(assessment_file)
    gap = generate_gap_analysis(assessment_file)
    return {
        "generated": datetime.utcnow().isoformat(),
        "framework": "NIST CSF 2.0",
        "overall_maturity_score": assessment["overall_maturity"],
        "maturity_level": assessment["overall_level"],
        "total_categories_assessed": assessment["total_categories"],
        "categories_meeting_target": assessment["total_categories"] - assessment["categories_below_target"],
        "categories_below_target": assessment["categories_below_target"],
        "function_summary": {fn: {"score": d["average_maturity"], "target": d["target_maturity"]}
                            for fn, d in assessment["function_scores"].items()},
        "top_gaps": gap["high_priority_gaps"][:5],
    }


def main():
    parser = argparse.ArgumentParser(description="NIST CSF Maturity Assessment Agent")
    sub = parser.add_subparsers(dest="command")
    a = sub.add_parser("assess", help="Run maturity assessment from CSV")
    a.add_argument("--csv", required=True)
    g = sub.add_parser("gaps", help="Generate gap analysis")
    g.add_argument("--csv", required=True)
    t = sub.add_parser("template", help="Create assessment template")
    t.add_argument("--output", help="Output CSV file path")
    e = sub.add_parser("executive", help="Executive summary")
    e.add_argument("--csv", required=True)
    args = parser.parse_args()
    if args.command == "assess":
        result = assess_from_csv(args.csv)
    elif args.command == "gaps":
        result = generate_gap_analysis(args.csv)
    elif args.command == "template":
        result = create_assessment_template(args.output)
    elif args.command == "executive":
        result = generate_executive_summary(args.csv)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
