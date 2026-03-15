#!/usr/bin/env python3
"""Agent for assessing ISO 27001:2022 ISMS compliance."""

import json
import argparse
from datetime import datetime
from collections import Counter

ANNEX_A_CATEGORIES = {
    "A.5": {"name": "Organizational controls", "count": 37},
    "A.6": {"name": "People controls", "count": 8},
    "A.7": {"name": "Physical controls", "count": 14},
    "A.8": {"name": "Technological controls", "count": 34},
}

REQUIRED_DOCUMENTS = [
    "ISMS Scope (4.3)", "Information Security Policy (5.2)",
    "Risk Assessment Methodology (6.1.2)", "Risk Treatment Plan (6.1.3)",
    "Statement of Applicability (6.1.3d)", "Information Security Objectives (6.2)",
    "Evidence of Competence (7.2)", "Documented Operating Procedures (8.1)",
    "Risk Assessment Results (8.2)", "Risk Treatment Results (8.3)",
    "Monitoring and Measurement Results (9.1)", "Internal Audit Program (9.2)",
    "Management Review Results (9.3)", "Nonconformities and Corrective Actions (10.1)",
]


def assess_soa_completeness(soa_path):
    """Assess Statement of Applicability completeness."""
    with open(soa_path) as f:
        soa = json.load(f)
    controls = soa if isinstance(soa, list) else soa.get("controls", [])
    total = len(controls)
    implemented = sum(1 for c in controls if c.get("status", "").lower() == "implemented")
    partially = sum(1 for c in controls if c.get("status", "").lower() == "partial")
    not_implemented = sum(1 for c in controls if c.get("status", "").lower() == "not_implemented")
    excluded = sum(1 for c in controls if c.get("status", "").lower() == "excluded")

    missing_justification = [c for c in controls
                             if c.get("status", "").lower() == "excluded"
                             and not c.get("justification")]
    findings = []
    if missing_justification:
        findings.append({
            "issue": f"{len(missing_justification)} excluded controls without justification",
            "severity": "HIGH",
            "controls": [c.get("id", "") for c in missing_justification],
        })

    no_evidence = [c for c in controls
                   if c.get("status", "").lower() == "implemented"
                   and not c.get("evidence")]
    if no_evidence:
        findings.append({
            "issue": f"{len(no_evidence)} implemented controls without evidence",
            "severity": "MEDIUM",
        })

    return {
        "total_controls": total,
        "implemented": implemented,
        "partial": partially,
        "not_implemented": not_implemented,
        "excluded": excluded,
        "implementation_rate": round(implemented / total * 100, 1) if total else 0,
        "findings": findings,
    }


def assess_documentation(docs_inventory_path):
    """Check required ISMS documentation against inventory."""
    with open(docs_inventory_path) as f:
        inventory = json.load(f)
    docs = inventory if isinstance(inventory, list) else inventory.get("documents", [])
    doc_names = [d.get("name", d.get("title", "")).lower() for d in docs]

    missing = []
    for req in REQUIRED_DOCUMENTS:
        found = any(req.lower().split("(")[0].strip() in name for name in doc_names)
        if not found:
            missing.append(req)

    outdated = [d for d in docs
                if d.get("last_review") and
                (datetime.utcnow() - datetime.fromisoformat(
                    d["last_review"].replace("Z", ""))).days > 365]

    return {
        "required": len(REQUIRED_DOCUMENTS),
        "present": len(REQUIRED_DOCUMENTS) - len(missing),
        "missing": missing,
        "outdated_documents": len(outdated),
        "compliance_rate": round(
            (len(REQUIRED_DOCUMENTS) - len(missing)) / len(REQUIRED_DOCUMENTS) * 100, 1),
    }


def assess_risk_register(risk_register_path):
    """Assess risk register for completeness and currency."""
    with open(risk_register_path) as f:
        register = json.load(f)
    risks = register if isinstance(register, list) else register.get("risks", [])
    findings = []
    by_level = Counter()

    for risk in risks:
        level = risk.get("risk_level", risk.get("rating", "unknown")).lower()
        by_level[level] += 1
        if not risk.get("treatment", risk.get("mitigation")):
            findings.append({
                "risk": risk.get("id", risk.get("name", "")),
                "issue": "No treatment plan defined",
                "severity": "HIGH",
            })
        if not risk.get("owner"):
            findings.append({
                "risk": risk.get("id", ""),
                "issue": "No risk owner assigned",
                "severity": "MEDIUM",
            })
        if risk.get("treatment", "").lower() == "accept" and not risk.get("acceptance_authority"):
            findings.append({
                "risk": risk.get("id", ""),
                "issue": "Risk accepted without management approval",
                "severity": "HIGH",
            })

    return {
        "total_risks": len(risks),
        "by_level": dict(by_level),
        "findings": findings,
        "untreated": sum(1 for r in risks if not r.get("treatment")),
    }


def generate_gap_analysis(current_state):
    """Generate ISO 27001 gap analysis from current state assessment."""
    clauses = {
        "4_context": ["scope_defined", "interested_parties", "isms_scope_document"],
        "5_leadership": ["security_policy", "roles_responsibilities", "management_commitment"],
        "6_planning": ["risk_methodology", "risk_assessment", "soa", "security_objectives"],
        "7_support": ["resources", "competence", "awareness", "communication", "documented_info"],
        "8_operation": ["operational_planning", "risk_assessment_results", "risk_treatment"],
        "9_evaluation": ["monitoring", "internal_audit", "management_review"],
        "10_improvement": ["nonconformity_handling", "corrective_actions", "continual_improvement"],
    }
    gaps = {}
    for clause, requirements in clauses.items():
        clause_state = current_state.get(clause, {})
        met = sum(1 for r in requirements if clause_state.get(r, False))
        gaps[clause] = {
            "total": len(requirements),
            "met": met,
            "gaps": [r for r in requirements if not clause_state.get(r, False)],
            "compliance": round(met / len(requirements) * 100, 1),
        }
    return gaps


def main():
    parser = argparse.ArgumentParser(description="ISO 27001 ISMS Compliance Agent")
    parser.add_argument("--soa", help="Statement of Applicability JSON")
    parser.add_argument("--docs", help="Documentation inventory JSON")
    parser.add_argument("--risks", help="Risk register JSON")
    parser.add_argument("--state", help="Current state assessment JSON for gap analysis")
    parser.add_argument("--action", choices=["soa", "docs", "risks", "gaps", "full"],
                        default="full")
    parser.add_argument("--output", default="iso27001_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}

    if args.action in ("soa", "full") and args.soa:
        result = assess_soa_completeness(args.soa)
        report["results"]["soa"] = result
        print(f"[+] SoA: {result['implementation_rate']}% implemented")

    if args.action in ("docs", "full") and args.docs:
        result = assess_documentation(args.docs)
        report["results"]["documentation"] = result
        print(f"[+] Documentation: {result['compliance_rate']}%, {len(result['missing'])} missing")

    if args.action in ("risks", "full") and args.risks:
        result = assess_risk_register(args.risks)
        report["results"]["risks"] = result
        print(f"[+] Risk register: {result['total_risks']} risks, {result['untreated']} untreated")

    if args.action in ("gaps", "full") and args.state:
        with open(args.state) as f:
            state = json.load(f)
        gaps = generate_gap_analysis(state)
        report["results"]["gap_analysis"] = gaps
        avg = sum(g["compliance"] for g in gaps.values()) / len(gaps)
        print(f"[+] Gap analysis: {avg:.1f}% average compliance")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
