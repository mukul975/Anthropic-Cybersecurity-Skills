#!/usr/bin/env python3
"""
Cyber Threat Intelligence Lifecycle Management Agent
Manages the CTI lifecycle from requirements gathering through dissemination,
tracking PIRs, collection sources, and intelligence product metrics.
"""

import json
import os
import sys
from datetime import datetime, timezone, timedelta


def load_intelligence_requirements(filepath: str) -> list[dict]:
    """Load Priority Intelligence Requirements (PIRs) from config."""
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return json.load(f)

    return [
        {"id": "PIR-001", "requirement": "Which threat actors are actively targeting our industry sector?",
         "stakeholder": "CISO", "priority": "HIGH", "status": "active", "review_date": "2024-06-01"},
        {"id": "PIR-002", "requirement": "What new vulnerabilities affect our technology stack?",
         "stakeholder": "VP Engineering", "priority": "HIGH", "status": "active", "review_date": "2024-06-01"},
        {"id": "PIR-003", "requirement": "Are any of our credentials or data exposed on dark web?",
         "stakeholder": "CISO", "priority": "MEDIUM", "status": "active", "review_date": "2024-06-01"},
    ]


def evaluate_collection_sources(sources_file: str) -> list[dict]:
    """Evaluate intelligence collection source coverage and quality."""
    if os.path.exists(sources_file):
        with open(sources_file, "r") as f:
            return json.load(f)

    return [
        {"name": "MITRE ATT&CK", "type": "open-source", "category": "TTPs",
         "reliability": "A", "update_freq": "quarterly", "pirs_covered": ["PIR-001"]},
        {"name": "NVD/CVE", "type": "open-source", "category": "vulnerabilities",
         "reliability": "A", "update_freq": "daily", "pirs_covered": ["PIR-002"]},
        {"name": "Recorded Future", "type": "commercial", "category": "multi-source",
         "reliability": "B", "update_freq": "real-time", "pirs_covered": ["PIR-001", "PIR-002", "PIR-003"]},
        {"name": "VirusTotal", "type": "commercial", "category": "IOCs",
         "reliability": "B", "update_freq": "real-time", "pirs_covered": ["PIR-001"]},
        {"name": "ISAC Feeds", "type": "sharing-community", "category": "sector-specific",
         "reliability": "B", "update_freq": "weekly", "pirs_covered": ["PIR-001", "PIR-002"]},
    ]


def assess_pir_coverage(pirs: list[dict], sources: list[dict]) -> dict:
    """Assess how well collection sources cover PIRs."""
    coverage = {}
    for pir in pirs:
        pir_id = pir["id"]
        covering_sources = [s["name"] for s in sources if pir_id in s.get("pirs_covered", [])]
        coverage[pir_id] = {
            "requirement": pir["requirement"],
            "priority": pir["priority"],
            "sources_count": len(covering_sources),
            "sources": covering_sources,
            "gap": len(covering_sources) == 0,
        }

    total_pirs = len(pirs)
    covered_pirs = sum(1 for c in coverage.values() if not c["gap"])
    gap_pirs = [pid for pid, c in coverage.items() if c["gap"]]

    return {
        "total_pirs": total_pirs,
        "covered_pirs": covered_pirs,
        "coverage_pct": round(covered_pirs / max(total_pirs, 1) * 100, 1),
        "gaps": gap_pirs,
        "details": coverage,
    }


def track_intelligence_products(products_file: str) -> dict:
    """Track intelligence products and dissemination metrics."""
    if os.path.exists(products_file):
        with open(products_file, "r") as f:
            products = json.load(f)
    else:
        products = [
            {"id": "PROD-001", "type": "Weekly Threat Briefing", "audience": "SOC Team",
             "frequency": "weekly", "last_published": "2024-03-08", "feedback_score": 4.2},
            {"id": "PROD-002", "type": "Threat Actor Profile", "audience": "Executive Leadership",
             "frequency": "monthly", "last_published": "2024-03-01", "feedback_score": 3.8},
            {"id": "PROD-003", "type": "IOC Feed", "audience": "SIEM/EDR",
             "frequency": "daily", "last_published": "2024-03-15", "feedback_score": 4.5},
            {"id": "PROD-004", "type": "Vulnerability Intelligence", "audience": "Engineering",
             "frequency": "weekly", "last_published": "2024-03-10", "feedback_score": 4.0},
        ]

    overdue = []
    for prod in products:
        last = datetime.strptime(prod["last_published"], "%Y-%m-%d")
        freq_days = {"daily": 1, "weekly": 7, "monthly": 30, "quarterly": 90}
        expected_interval = freq_days.get(prod["frequency"], 30)
        days_since = (datetime.now() - last).days
        if days_since > expected_interval * 1.5:
            overdue.append({"product": prod["type"], "days_overdue": days_since - expected_interval})

    avg_feedback = sum(p["feedback_score"] for p in products) / max(len(products), 1)

    return {
        "total_products": len(products),
        "overdue_products": overdue,
        "avg_feedback_score": round(avg_feedback, 2),
        "products": products,
    }


def assess_maturity(pir_coverage: dict, products: dict, sources: list) -> dict:
    """Assess CTI program maturity using simplified FIRST CTI-SIG model."""
    scores = {}

    scores["planning_direction"] = min(5, 1 + (pir_coverage["total_pirs"] // 2))
    scores["collection"] = min(5, 1 + len(sources) // 2)
    scores["processing"] = 3 if products["total_products"] > 2 else 2
    scores["analysis"] = 3 if pir_coverage["coverage_pct"] > 80 else 2
    scores["dissemination"] = min(5, 1 + products["total_products"])
    scores["feedback"] = 4 if products["avg_feedback_score"] > 4.0 else 3

    overall = round(sum(scores.values()) / len(scores), 1)

    return {"dimension_scores": scores, "overall_maturity": overall, "maturity_level": (
        "Initial" if overall < 2 else "Developing" if overall < 3 else
        "Defined" if overall < 4 else "Managed" if overall < 4.5 else "Optimizing"
    )}


def generate_report(pirs: list, coverage: dict, products: dict, maturity: dict) -> str:
    """Generate CTI lifecycle management report."""
    lines = [
        "CYBER THREAT INTELLIGENCE LIFECYCLE REPORT",
        "=" * 50,
        f"Report Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"PIR COVERAGE: {coverage['coverage_pct']}%",
        f"  Total PIRs: {coverage['total_pirs']}",
        f"  Covered: {coverage['covered_pirs']}",
        f"  Gaps: {len(coverage['gaps'])}",
        "",
        f"INTELLIGENCE PRODUCTS:",
        f"  Active Products: {products['total_products']}",
        f"  Overdue: {len(products['overdue_products'])}",
        f"  Avg Feedback Score: {products['avg_feedback_score']}/5.0",
        "",
        f"PROGRAM MATURITY: {maturity['maturity_level']} ({maturity['overall_maturity']}/5.0)",
    ]
    for dim, score in maturity["dimension_scores"].items():
        lines.append(f"  {dim}: {score}/5")

    return "\n".join(lines)


if __name__ == "__main__":
    pir_file = sys.argv[1] if len(sys.argv) > 1 else "pirs.json"
    sources_file = sys.argv[2] if len(sys.argv) > 2 else "sources.json"
    products_file = sys.argv[3] if len(sys.argv) > 3 else "products.json"

    print("[*] CTI Lifecycle Management Assessment")
    pirs = load_intelligence_requirements(pir_file)
    sources = evaluate_collection_sources(sources_file)
    coverage = assess_pir_coverage(pirs, sources)
    products = track_intelligence_products(products_file)
    maturity = assess_maturity(coverage, products, sources)

    report = generate_report(pirs, coverage, products, maturity)
    print(report)

    output = f"cti_lifecycle_{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
    with open(output, "w") as f:
        json.dump({"pirs": pirs, "coverage": coverage, "products": products, "maturity": maturity}, f, indent=2)
    print(f"\n[*] Results saved to {output}")
