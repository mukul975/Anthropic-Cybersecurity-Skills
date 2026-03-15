#!/usr/bin/env python3
"""Social engineering pretext call planning and tracking agent."""

import json
import sys
import argparse
from datetime import datetime


def generate_pretext_templates():
    """Generate pretext call templates for authorized engagements."""
    return [
        {
            "name": "IT Help Desk Password Reset",
            "target_role": "General employee",
            "objective": "Obtain credentials or MFA bypass",
            "opening": "Hi, this is [Name] from the IT help desk. We noticed unusual activity on your account.",
            "key_questions": [
                "Can you verify your employee ID?",
                "What is your current password so we can compare against the compromised list?",
                "Can you read me the code from your authenticator app?",
            ],
            "success_criteria": "Target provides password, MFA token, or confirms identity details",
            "difficulty": "easy",
        },
        {
            "name": "Executive Assistant Urgency",
            "target_role": "Executive assistant / Finance",
            "objective": "Initiate wire transfer or reveal financial info",
            "opening": "Hi, this is [Name] calling on behalf of [CEO]. They need an urgent wire processed.",
            "key_questions": [
                "Can you process this payment today?",
                "What account do we usually wire from?",
                "The CEO said to skip the usual approval — can you make an exception?",
            ],
            "success_criteria": "Target initiates process or reveals account details",
            "difficulty": "hard",
        },
        {
            "name": "Vendor Support Callback",
            "target_role": "IT administrator",
            "objective": "Gain remote access or credential disclosure",
            "opening": "This is [Name] from [Vendor] support returning your call about the ticket.",
            "key_questions": [
                "Can you give me remote access to troubleshoot?",
                "What is the admin password for the [system]?",
                "Can you add our support account to the admin group temporarily?",
            ],
            "success_criteria": "Target provides remote access or admin credentials",
            "difficulty": "medium",
        },
    ]


def create_call_tracking_sheet(targets):
    """Create tracking sheet for pretext calls."""
    tracking = []
    for target in targets:
        tracking.append({
            "name": target.get("name", ""),
            "phone": target.get("phone", ""),
            "department": target.get("department", ""),
            "pretext": target.get("pretext", "IT Help Desk"),
            "status": "pending",
            "result": None,
            "info_obtained": [],
            "call_duration": None,
            "notes": "",
        })
    return tracking


def analyze_results(call_results):
    """Analyze pretext call results for reporting."""
    total = len(call_results)
    success = sum(1 for c in call_results if c.get("result") == "success")
    partial = sum(1 for c in call_results if c.get("result") == "partial")
    failed = sum(1 for c in call_results if c.get("result") == "failed")
    reported = sum(1 for c in call_results if c.get("result") == "reported")
    return {
        "total_calls": total,
        "successful": success,
        "partial_success": partial,
        "failed": failed,
        "reported_to_security": reported,
        "success_rate": round(success / max(total, 1) * 100, 1),
        "report_rate": round(reported / max(total, 1) * 100, 1),
    }


def run_planning(targets_file=None, results_file=None):
    """Execute pretext call planning and analysis."""
    print(f"\n{'='*60}")
    print(f"  SOCIAL ENGINEERING PRETEXT CALL PLANNER")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    templates = generate_pretext_templates()
    print(f"--- PRETEXT TEMPLATES ({len(templates)}) ---")
    for t in templates:
        print(f"  [{t['difficulty'].upper()}] {t['name']}")
        print(f"    Target: {t['target_role']}")
        print(f"    Objective: {t['objective']}")

    if targets_file:
        with open(targets_file, "r") as f:
            targets = json.load(f)
        sheet = create_call_tracking_sheet(targets)
        print(f"\n--- TRACKING SHEET ({len(sheet)} targets) ---")
        for s in sheet[:10]:
            print(f"  {s['name']} ({s['department']}): {s['pretext']}")

    if results_file:
        with open(results_file, "r") as f:
            results = json.load(f)
        metrics = analyze_results(results)
        print(f"\n--- CAMPAIGN METRICS ---")
        for k, v in metrics.items():
            print(f"  {k}: {v}")

    return {"templates": templates}


def main():
    parser = argparse.ArgumentParser(description="Pretext Call Planning Agent")
    parser.add_argument("--targets", help="Target list JSON file")
    parser.add_argument("--results", help="Call results JSON file for analysis")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_planning(args.targets, args.results)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
