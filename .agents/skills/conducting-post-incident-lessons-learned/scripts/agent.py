#!/usr/bin/env python3
"""Post-incident lessons learned analysis agent."""

import json
import sys
import argparse
from datetime import datetime


def analyze_incident_timeline(incident_data):
    """Analyze incident timeline for response gaps."""
    gaps = []
    if not incident_data:
        return gaps
    events = incident_data.get("timeline", [])
    for i in range(1, len(events)):
        prev_time = datetime.fromisoformat(events[i-1]["timestamp"])
        curr_time = datetime.fromisoformat(events[i]["timestamp"])
        delta_minutes = (curr_time - prev_time).total_seconds() / 60
        if delta_minutes > 30:
            gaps.append({
                "between": f"{events[i-1]['action']} -> {events[i]['action']}",
                "gap_minutes": round(delta_minutes),
                "severity": "HIGH" if delta_minutes > 120 else "MEDIUM",
                "recommendation": "Reduce response time with automated playbooks",
            })
    return gaps


def calculate_metrics(incident_data):
    """Calculate key incident response metrics."""
    timeline = incident_data.get("timeline", [])
    if len(timeline) < 2:
        return {}
    detect_time = None
    contain_time = None
    resolve_time = None
    for event in timeline:
        action = event.get("action", "").lower()
        ts = datetime.fromisoformat(event["timestamp"])
        if "detect" in action and not detect_time:
            detect_time = ts
        if "contain" in action and not contain_time:
            contain_time = ts
        if "resolve" in action or "close" in action:
            resolve_time = ts
    start = datetime.fromisoformat(timeline[0]["timestamp"])
    metrics = {}
    if detect_time:
        metrics["mttd_minutes"] = round((detect_time - start).total_seconds() / 60)
    if contain_time and detect_time:
        metrics["mttc_minutes"] = round((contain_time - detect_time).total_seconds() / 60)
    if resolve_time and detect_time:
        metrics["mttr_minutes"] = round((resolve_time - detect_time).total_seconds() / 60)
    return metrics


def generate_action_items(gaps, metrics):
    """Generate prioritized action items from analysis."""
    items = []
    if metrics.get("mttd_minutes", 0) > 60:
        items.append({
            "priority": "P1",
            "area": "Detection",
            "action": "Deploy automated detection rules to reduce MTTD below 30 minutes",
            "owner": "SOC Engineering",
        })
    if metrics.get("mttc_minutes", 0) > 120:
        items.append({
            "priority": "P1",
            "area": "Containment",
            "action": "Implement automated containment playbook in SOAR platform",
            "owner": "IR Team",
        })
    for gap in gaps:
        if gap["severity"] == "HIGH":
            items.append({
                "priority": "P2",
                "area": "Process",
                "action": f"Address {gap['gap_minutes']}min gap in {gap['between']}",
                "owner": "IR Manager",
            })
    items.append({
        "priority": "P3",
        "area": "Training",
        "action": "Schedule tabletop exercise within 30 days based on incident scenario",
        "owner": "Security Training",
    })
    return items


def generate_report_template():
    """Generate lessons learned report template."""
    return {
        "sections": [
            {"title": "Executive Summary", "content": "Brief overview of incident and impact"},
            {"title": "Incident Timeline", "content": "Chronological sequence of events"},
            {"title": "Root Cause Analysis", "content": "Underlying cause identification"},
            {"title": "What Went Well", "content": "Effective response actions"},
            {"title": "What Needs Improvement", "content": "Gaps and failures identified"},
            {"title": "Action Items", "content": "Prioritized remediation tasks with owners and deadlines"},
            {"title": "Metrics", "content": "MTTD, MTTC, MTTR measurements"},
            {"title": "Appendix", "content": "Supporting evidence, IOCs, detection rules"},
        ],
    }


def run_analysis(incident_file):
    """Execute post-incident lessons learned analysis."""
    print(f"\n{'='*60}")
    print(f"  POST-INCIDENT LESSONS LEARNED")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    incident_data = {}
    if incident_file:
        with open(incident_file, "r") as f:
            incident_data = json.load(f)

    metrics = calculate_metrics(incident_data)
    print(f"--- RESPONSE METRICS ---")
    for k, v in metrics.items():
        print(f"  {k}: {v} minutes")

    gaps = analyze_incident_timeline(incident_data)
    print(f"\n--- TIMELINE GAPS ({len(gaps)}) ---")
    for g in gaps:
        print(f"  [{g['severity']}] {g['between']}: {g['gap_minutes']} min gap")

    items = generate_action_items(gaps, metrics)
    print(f"\n--- ACTION ITEMS ({len(items)}) ---")
    for item in items:
        print(f"  [{item['priority']}] {item['area']}: {item['action']}")

    template = generate_report_template()
    print(f"\n--- REPORT SECTIONS ---")
    for s in template["sections"]:
        print(f"  - {s['title']}")

    return {"metrics": metrics, "gaps": gaps, "action_items": items, "template": template}


def main():
    parser = argparse.ArgumentParser(description="Post-Incident Lessons Learned Agent")
    parser.add_argument("--incident-file", help="Incident data JSON file")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_analysis(args.incident_file)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
