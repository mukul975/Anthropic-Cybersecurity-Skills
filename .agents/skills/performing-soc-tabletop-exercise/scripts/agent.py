#!/usr/bin/env python3
"""SOC tabletop exercise management agent with scenario generation and scoring."""

import json
import datetime
import random
import hashlib


SCENARIO_TEMPLATES = {
    "ransomware": {
        "title": "Ransomware Attack Scenario",
        "phases": [
            {"time": "T+0", "inject": "Shadow copy deletion detected on file server",
             "questions": ["Initial assessment?", "What data sources to query?"]},
            {"time": "T+10", "inject": "Mass file encryption with .locked extension across 7 hosts",
             "questions": ["Severity assignment?", "Containment actions?", "Notification chain?"]},
            {"time": "T+25", "inject": "Ransom note found, data exfiltration confirmed",
             "questions": ["Containment strategy order?", "Executive notification plan?"]},
            {"time": "T+45", "inject": "CFO demands access for SEC filing, media inquiry received",
             "questions": ["Business vs security balance?", "Ransom payment recommendation?"]},
            {"time": "T+70", "inject": "Forensics reveal 5-day dwell time, 15GB exfiltrated PII",
             "questions": ["Regulatory notifications?", "Law enforcement engagement?"]},
            {"time": "T+90", "inject": "Recovery decision point, CEO briefing in 30 minutes",
             "questions": ["Executive briefing content?", "Recovery timeline?"]},
        ],
    },
    "data_breach": {
        "title": "Data Breach / Insider Threat Scenario",
        "phases": [
            {"time": "T+0", "inject": "DLP alert: large data transfer to personal cloud storage",
             "questions": ["Initial triage steps?", "Who to involve?"]},
            {"time": "T+15", "inject": "Employee identified is in notice period, accessing HR data",
             "questions": ["Containment approach?", "Legal considerations?"]},
            {"time": "T+30", "inject": "Evidence of systematic data collection over 2 weeks",
             "questions": ["Forensic preservation?", "HR and Legal coordination?"]},
            {"time": "T+50", "inject": "Customer PII confirmed in exfiltrated data",
             "questions": ["Breach notification timeline?", "Regulatory requirements?"]},
        ],
    },
    "supply_chain": {
        "title": "Supply Chain Compromise Scenario",
        "phases": [
            {"time": "T+0", "inject": "Vendor software update contains backdoor, CISA advisory published",
             "questions": ["Impact assessment scope?", "Vendor communication?"]},
            {"time": "T+15", "inject": "Affected software deployed on 40% of endpoints",
             "questions": ["Isolation strategy?", "Business continuity?"]},
            {"time": "T+35", "inject": "C2 beaconing detected from 12 hosts",
             "questions": ["Containment priority order?", "Evidence preservation?"]},
            {"time": "T+55", "inject": "Attacker accessed domain controller via compromised agent",
             "questions": ["Credential reset plan?", "Recovery sequence?"]},
        ],
    },
}

EVALUATION_CRITERIA = {
    "detection_and_triage": {"weight": 25, "max_score": 100},
    "containment_decision": {"weight": 25, "max_score": 100},
    "communication": {"weight": 25, "max_score": 100},
    "business_continuity": {"weight": 25, "max_score": 100},
}


def generate_exercise_id():
    now = datetime.datetime.now()
    quarter = (now.month - 1) // 3 + 1
    return f"TTX-{now.year}-Q{quarter}"


def create_exercise(scenario_type, participants, duration_hours=3):
    if scenario_type not in SCENARIO_TEMPLATES:
        raise ValueError(f"Unknown scenario: {scenario_type}. Choose from: {list(SCENARIO_TEMPLATES)}")
    template = SCENARIO_TEMPLATES[scenario_type]
    exercise = {
        "exercise_id": generate_exercise_id(),
        "title": template["title"],
        "date": datetime.datetime.now().isoformat(),
        "duration_hours": duration_hours,
        "classification": "TLP:AMBER",
        "participants": participants,
        "phases": template["phases"],
        "objectives": [
            "Test detection and triage capabilities",
            "Validate escalation procedures",
            "Assess cross-functional communication",
            "Evaluate containment decision-making",
            "Test recovery procedures",
        ],
    }
    return exercise


def score_response(category, score):
    if category not in EVALUATION_CRITERIA:
        raise ValueError(f"Unknown category: {category}")
    criteria = EVALUATION_CRITERIA[category]
    clamped = max(0, min(score, criteria["max_score"]))
    if clamped >= 85:
        rating = "Excellent"
    elif clamped >= 70:
        rating = "Good"
    elif clamped >= 55:
        rating = "Adequate"
    else:
        rating = "Needs Improvement"
    return {"category": category, "score": clamped, "rating": rating, "weight": criteria["weight"]}


def calculate_overall_score(scores):
    total_weighted = sum(s["score"] * s["weight"] for s in scores)
    total_weight = sum(s["weight"] for s in scores)
    return round(total_weighted / total_weight, 1) if total_weight > 0 else 0


def generate_after_action_report(exercise, scores, gaps, strengths):
    overall = calculate_overall_score(scores)
    if overall >= 85:
        overall_rating = "Excellent"
    elif overall >= 70:
        overall_rating = "Good"
    elif overall >= 55:
        overall_rating = "Adequate"
    else:
        overall_rating = "Needs Improvement"
    report = {
        "exercise_id": exercise["exercise_id"],
        "title": exercise["title"],
        "date": exercise["date"],
        "participants": len(exercise["participants"]),
        "duration_hours": exercise["duration_hours"],
        "scores": {s["category"]: f"{s['score']}/100 ({s['rating']})" for s in scores},
        "overall_score": f"{overall}/100 ({overall_rating})",
        "strengths": strengths,
        "gaps": gaps,
        "next_exercise": f"TTX-{datetime.datetime.now().year}-Q{((datetime.datetime.now().month - 1) // 3 + 2) % 4 + 1}",
    }
    return report


def print_exercise_summary(exercise):
    print(f"TABLETOP EXERCISE: {exercise['title']}")
    print("=" * 50)
    print(f"ID:            {exercise['exercise_id']}")
    print(f"Date:          {exercise['date']}")
    print(f"Duration:      {exercise['duration_hours']} hours")
    print(f"Participants:  {len(exercise['participants'])}")
    print(f"Classification:{exercise['classification']}")
    print(f"\nPHASES ({len(exercise['phases'])} injects):")
    for i, phase in enumerate(exercise["phases"], 1):
        print(f"  Inject {i} [{phase['time']}]: {phase['inject']}")
        for q in phase["questions"]:
            print(f"    - {q}")


def print_report(report):
    print(f"\nAFTER-ACTION REPORT - {report['exercise_id']}")
    print("=" * 50)
    print(f"Overall Score: {report['overall_score']}")
    for cat, score in report["scores"].items():
        print(f"  {cat}: {score}")
    print(f"\nStrengths: {len(report['strengths'])}")
    for s in report["strengths"]:
        print(f"  [+] {s}")
    print(f"\nGaps: {len(report['gaps'])}")
    for g in report["gaps"]:
        print(f"  [-] {g['finding']} (Risk: {g['risk']}, Owner: {g['owner']})")


if __name__ == "__main__":
    participants = [
        {"role": "SOC Tier 1 Analyst", "count": 2},
        {"role": "SOC Tier 2 Analyst", "count": 2},
        {"role": "SOC Manager", "count": 1},
        {"role": "IT Operations Lead", "count": 1},
        {"role": "CISO", "count": 1},
        {"role": "Legal Counsel", "count": 1},
        {"role": "Communications Lead", "count": 1},
    ]
    exercise = create_exercise("ransomware", participants)
    print_exercise_summary(exercise)
    scores = [
        score_response("detection_and_triage", 85),
        score_response("containment_decision", 80),
        score_response("communication", 60),
        score_response("business_continuity", 65),
    ]
    gaps = [
        {"finding": "No after-hours CISO notification procedure", "risk": "High", "owner": "SOC Manager"},
        {"finding": "Backup recovery untested for 6 months", "risk": "Critical", "owner": "IT Ops Lead"},
    ]
    strengths = [
        "Ransomware indicators correctly identified immediately",
        "EDR isolation procedure well understood",
    ]
    report = generate_after_action_report(exercise, scores, gaps, strengths)
    print_report(report)
