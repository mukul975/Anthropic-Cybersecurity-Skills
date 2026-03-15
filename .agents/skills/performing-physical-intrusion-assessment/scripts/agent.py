#!/usr/bin/env python3
"""Agent for performing physical intrusion assessment — checklist management and finding documentation."""

import json
import argparse
import csv
from datetime import datetime
from pathlib import Path


ASSESSMENT_CATEGORIES = {
    "perimeter": {
        "name": "Perimeter Security",
        "checks": [
            {"id": "P01", "check": "Perimeter fencing intact and adequate height (>=7ft)", "severity": "HIGH"},
            {"id": "P02", "check": "CCTV cameras covering all entry points", "severity": "HIGH"},
            {"id": "P03", "check": "Adequate exterior lighting at night", "severity": "MEDIUM"},
            {"id": "P04", "check": "Vehicle barriers at building entrances", "severity": "MEDIUM"},
            {"id": "P05", "check": "Signage prohibiting unauthorized access", "severity": "LOW"},
        ],
    },
    "access_control": {
        "name": "Access Control",
        "checks": [
            {"id": "A01", "check": "Badge/card access on all entry doors", "severity": "CRITICAL"},
            {"id": "A02", "check": "Tailgating prevention mechanisms (mantrap, turnstile)", "severity": "HIGH"},
            {"id": "A03", "check": "Visitor sign-in and escort policy enforced", "severity": "HIGH"},
            {"id": "A04", "check": "Badge visible at all times policy", "severity": "MEDIUM"},
            {"id": "A05", "check": "After-hours access controls and logging", "severity": "HIGH"},
            {"id": "A06", "check": "Terminated employee badge deactivation process", "severity": "CRITICAL"},
        ],
    },
    "server_room": {
        "name": "Server Room / Data Center",
        "checks": [
            {"id": "S01", "check": "MFA or biometric access to server room", "severity": "CRITICAL"},
            {"id": "S02", "check": "CCTV monitoring inside server room", "severity": "HIGH"},
            {"id": "S03", "check": "Environmental controls (temp, humidity sensors)", "severity": "MEDIUM"},
            {"id": "S04", "check": "Fire suppression system present", "severity": "HIGH"},
            {"id": "S05", "check": "Access logs reviewed regularly", "severity": "MEDIUM"},
            {"id": "S06", "check": "No unlocked network ports in common areas", "severity": "HIGH"},
        ],
    },
    "social_engineering": {
        "name": "Social Engineering Resistance",
        "checks": [
            {"id": "E01", "check": "Employees challenge unknown visitors", "severity": "HIGH"},
            {"id": "E02", "check": "Clean desk policy enforced", "severity": "MEDIUM"},
            {"id": "E03", "check": "Sensitive documents shredded", "severity": "MEDIUM"},
            {"id": "E04", "check": "USB drives not left unattended", "severity": "HIGH"},
            {"id": "E05", "check": "Dumpster diving countermeasures", "severity": "MEDIUM"},
        ],
    },
}


def generate_checklist(categories=None, output_file=None):
    """Generate physical security assessment checklist."""
    cats = categories or list(ASSESSMENT_CATEGORIES.keys())
    checklist = []
    for cat in cats:
        if cat in ASSESSMENT_CATEGORIES:
            data = ASSESSMENT_CATEGORIES[cat]
            for check in data["checks"]:
                checklist.append({
                    "category": data["name"], "id": check["id"],
                    "check": check["check"], "severity": check["severity"],
                    "status": "NOT_TESTED", "finding": "", "evidence": "",
                })
    if output_file:
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["category", "id", "check", "severity", "status", "finding", "evidence"])
            writer.writeheader()
            writer.writerows(checklist)
    return {"total_checks": len(checklist), "categories": cats, "checklist": checklist, "output": output_file}


def score_assessment(results_csv):
    """Score a completed physical security assessment."""
    with open(results_csv, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        results = list(reader)
    passed = sum(1 for r in results if r.get("status", "").lower() in ("pass", "compliant", "ok"))
    failed = sum(1 for r in results if r.get("status", "").lower() in ("fail", "non-compliant", "nc"))
    total = len(results)
    by_category = {}
    by_severity = {}
    failures = []
    for r in results:
        cat = r.get("category", "unknown")
        sev = r.get("severity", "MEDIUM")
        by_category.setdefault(cat, {"pass": 0, "fail": 0})
        by_severity.setdefault(sev, {"pass": 0, "fail": 0})
        if r.get("status", "").lower() in ("pass", "compliant", "ok"):
            by_category[cat]["pass"] += 1
            by_severity[sev]["pass"] += 1
        elif r.get("status", "").lower() in ("fail", "non-compliant", "nc"):
            by_category[cat]["fail"] += 1
            by_severity[sev]["fail"] += 1
            failures.append({"id": r.get("id"), "check": r.get("check"), "severity": sev,
                             "finding": r.get("finding", "")[:200]})
    return {
        "total_checks": total, "passed": passed, "failed": failed,
        "compliance_pct": round(passed / max(total, 1) * 100, 1),
        "by_category": by_category,
        "by_severity": by_severity,
        "critical_failures": [f for f in failures if f["severity"] == "CRITICAL"],
        "all_failures": failures,
    }


def generate_report(results_csv):
    """Generate executive physical security assessment report."""
    scores = score_assessment(results_csv)
    risk = "CRITICAL" if scores.get("critical_failures") else "HIGH" if scores["failed"] > 5 else "MEDIUM" if scores["failed"] > 0 else "LOW"
    return {
        "generated": datetime.utcnow().isoformat(),
        "overall_risk": risk,
        "compliance_score": scores["compliance_pct"],
        **scores,
        "recommendations": [
            f"CRITICAL: Address {len(scores['critical_failures'])} critical findings immediately"
        ] if scores["critical_failures"] else ["All critical controls passed"],
    }


def main():
    parser = argparse.ArgumentParser(description="Physical Intrusion Assessment Agent")
    sub = parser.add_subparsers(dest="command")
    c = sub.add_parser("checklist", help="Generate assessment checklist")
    c.add_argument("--categories", nargs="*", choices=list(ASSESSMENT_CATEGORIES.keys()))
    c.add_argument("--output", help="Output CSV file")
    s = sub.add_parser("score", help="Score completed assessment")
    s.add_argument("--csv", required=True)
    r = sub.add_parser("report", help="Generate assessment report")
    r.add_argument("--csv", required=True)
    args = parser.parse_args()
    if args.command == "checklist":
        result = generate_checklist(args.categories, args.output)
    elif args.command == "score":
        result = score_assessment(args.csv)
    elif args.command == "report":
        result = generate_report(args.csv)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
