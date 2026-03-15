#!/usr/bin/env python3
"""Full-scope red team engagement management agent."""

import json
import sys
import argparse
from datetime import datetime

try:
    from attackcti import attack_client
except ImportError:
    print("Install: pip install attackcti")
    sys.exit(1)


def get_attack_techniques(tactics=None):
    """Retrieve MITRE ATT&CK techniques for engagement planning."""
    client = attack_client()
    techniques = client.get_enterprise_techniques()
    if tactics:
        tactic_set = set(t.lower() for t in tactics)
        filtered = []
        for tech in techniques:
            kill_chain = tech.get("kill_chain_phases", [])
            for phase in kill_chain:
                if phase.get("phase_name", "").lower() in tactic_set:
                    filtered.append({
                        "id": tech.get("external_references", [{}])[0].get("external_id", ""),
                        "name": tech.get("name", ""),
                        "tactic": phase.get("phase_name", ""),
                        "platforms": tech.get("x_mitre_platforms", []),
                    })
                    break
        return filtered
    return [{"id": t.get("external_references", [{}])[0].get("external_id", ""),
             "name": t.get("name", "")} for t in techniques[:50]]


def generate_engagement_plan(scope, objectives):
    """Generate red team engagement plan with phases."""
    phases = [
        {
            "phase": "Reconnaissance",
            "tactic": "reconnaissance",
            "duration_days": 3,
            "activities": [
                "OSINT collection on target organization",
                "DNS enumeration and subdomain discovery",
                "Employee profiling via LinkedIn and social media",
                "Technology stack fingerprinting",
            ],
        },
        {
            "phase": "Initial Access",
            "tactic": "initial-access",
            "duration_days": 5,
            "activities": [
                "Spearphishing campaign with custom payloads",
                "Watering hole attack on frequented sites",
                "Credential spraying against external portals",
                "Physical access testing (if in scope)",
            ],
        },
        {
            "phase": "Execution & Persistence",
            "tactic": "execution",
            "duration_days": 5,
            "activities": [
                "C2 infrastructure deployment",
                "Lateral movement via Pass-the-Hash/Ticket",
                "Persistence mechanism installation",
                "Privilege escalation to domain admin",
            ],
        },
        {
            "phase": "Objective Completion",
            "tactic": "exfiltration",
            "duration_days": 3,
            "activities": [
                "Crown jewel access demonstration",
                "Data exfiltration simulation",
                "Business impact scenario documentation",
                "Evidence collection and cleanup",
            ],
        },
    ]
    return {
        "scope": scope,
        "objectives": objectives,
        "total_duration_days": sum(p["duration_days"] for p in phases),
        "phases": phases,
        "rules_of_engagement": [
            "No denial-of-service attacks",
            "No destruction of data",
            "Emergency contact procedure established",
            "Daily status updates to trusted agent",
        ],
    }


def generate_c2_checklist():
    """Generate C2 infrastructure preparation checklist."""
    return {
        "infrastructure": [
            {"item": "Domain registration (categorized, aged)", "status": "pending"},
            {"item": "SSL certificates via Let's Encrypt", "status": "pending"},
            {"item": "Redirector servers (Apache mod_rewrite)", "status": "pending"},
            {"item": "C2 server (Cobalt Strike / Sliver / Mythic)", "status": "pending"},
            {"item": "Phishing server (GoPhish)", "status": "pending"},
            {"item": "Payload hosting (S3 / Azure Blob)", "status": "pending"},
        ],
        "opsec": [
            {"item": "VPN for all operator traffic", "status": "pending"},
            {"item": "Domain fronting or CDN configuration", "status": "pending"},
            {"item": "Logging and evidence collection setup", "status": "pending"},
            {"item": "Deconfliction process with blue team POC", "status": "pending"},
        ],
    }


def run_planning(scope, objectives):
    """Execute red team engagement planning."""
    print(f"\n{'='*60}")
    print(f"  RED TEAM ENGAGEMENT PLANNER")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    plan = generate_engagement_plan(scope, objectives)
    print(f"--- ENGAGEMENT PLAN ---")
    print(f"  Scope: {plan['scope']}")
    print(f"  Duration: {plan['total_duration_days']} days")
    for phase in plan["phases"]:
        print(f"\n  Phase: {phase['phase']} ({phase['duration_days']} days)")
        for act in phase["activities"]:
            print(f"    - {act}")

    checklist = generate_c2_checklist()
    print(f"\n--- C2 INFRASTRUCTURE CHECKLIST ---")
    for item in checklist["infrastructure"]:
        print(f"  [ ] {item['item']}")

    techniques = get_attack_techniques(["initial-access", "lateral-movement"])
    print(f"\n--- RELEVANT ATT&CK TECHNIQUES ({len(techniques)}) ---")
    for t in techniques[:10]:
        print(f"  {t['id']}: {t['name']}")

    return {"plan": plan, "checklist": checklist, "techniques": techniques}


def main():
    parser = argparse.ArgumentParser(description="Red Team Engagement Agent")
    parser.add_argument("--scope", required=True, help="Engagement scope description")
    parser.add_argument("--objectives", nargs="+", required=True, help="Engagement objectives")
    parser.add_argument("--output", help="Save plan to JSON file")
    args = parser.parse_args()

    report = run_planning(args.scope, args.objectives)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Plan saved to {args.output}")


if __name__ == "__main__":
    main()
