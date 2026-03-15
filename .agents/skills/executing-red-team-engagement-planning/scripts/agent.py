#!/usr/bin/env python3
"""Agent for planning and documenting red team engagements with scope, rules, and attack paths."""

import argparse
import json
import os
from datetime import datetime, timezone


MITRE_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access",
    "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

ATTACK_SCENARIOS = {
    "phishing": {
        "name": "Spearphishing Campaign",
        "tactics": ["Initial Access", "Execution"],
        "techniques": ["T1566.001", "T1204.002"],
        "tools": ["GoPhish", "Evilginx2", "custom payloads"],
    },
    "external_recon": {
        "name": "External Reconnaissance & Exploitation",
        "tactics": ["Reconnaissance", "Initial Access"],
        "techniques": ["T1595", "T1190", "T1133"],
        "tools": ["Nmap", "Nuclei", "Subfinder", "Burp Suite"],
    },
    "assumed_breach": {
        "name": "Assumed Breach — Internal",
        "tactics": ["Discovery", "Lateral Movement", "Privilege Escalation"],
        "techniques": ["T1087", "T1021", "T1068"],
        "tools": ["BloodHound", "Rubeus", "Impacket", "CrackMapExec"],
    },
    "physical": {
        "name": "Physical Access & Social Engineering",
        "tactics": ["Initial Access", "Collection"],
        "techniques": ["T1200", "T1091"],
        "tools": ["Rubber Ducky", "LAN Turtle", "badge cloning"],
    },
}


def generate_engagement_plan(client_name, scenarios, duration_weeks, team_size):
    """Generate a structured red team engagement plan."""
    plan = {
        "engagement": {
            "client": client_name,
            "type": "Red Team Assessment",
            "created": datetime.now(timezone.utc).isoformat(),
            "duration_weeks": duration_weeks,
            "team_size": team_size,
        },
        "scope": {
            "in_scope": [],
            "out_of_scope": [
                "Denial of Service attacks",
                "Physical destruction of equipment",
                "Social engineering of non-consenting third parties",
                "Data exfiltration of real PII/PHI",
            ],
        },
        "rules_of_engagement": {
            "authorization": f"Written authorization required from {client_name} CISO",
            "communication": "Daily check-ins with client POC via encrypted channel",
            "deconfliction": "24/7 hotline for incident deconfliction",
            "data_handling": "All collected data encrypted at rest and in transit",
            "emergency_stop": "Immediate halt on client request via deconfliction hotline",
            "hours_of_operation": "Business hours unless otherwise agreed",
        },
        "scenarios": [],
        "phases": [
            {"phase": 1, "name": "Planning & Reconnaissance", "weeks": 1},
            {"phase": 2, "name": "Initial Access", "weeks": max(1, duration_weeks // 4)},
            {"phase": 3, "name": "Post-Exploitation", "weeks": max(1, duration_weeks // 3)},
            {"phase": 4, "name": "Objective Achievement", "weeks": max(1, duration_weeks // 4)},
            {"phase": 5, "name": "Reporting & Debrief", "weeks": 1},
        ],
        "objectives": [
            "Gain initial foothold in corporate network",
            "Escalate to Domain Admin privileges",
            "Access simulated crown jewels (flag files)",
            "Test detection and response capabilities",
            "Evaluate security awareness of personnel",
        ],
    }

    for scenario_key in scenarios:
        if scenario_key in ATTACK_SCENARIOS:
            plan["scenarios"].append(ATTACK_SCENARIOS[scenario_key])

    return plan


def generate_attack_tree(scenario):
    """Generate an attack tree for a given scenario."""
    tree = {
        "scenario": scenario["name"],
        "goal": f"Achieve objectives via {scenario['name']}",
        "attack_paths": [],
    }
    for i, technique in enumerate(scenario["techniques"]):
        tree["attack_paths"].append({
            "step": i + 1,
            "technique": technique,
            "tactic": scenario["tactics"][min(i, len(scenario["tactics"]) - 1)],
            "tools": scenario["tools"],
            "success_criteria": f"Successfully execute {technique}",
        })
    return tree


def main():
    parser = argparse.ArgumentParser(
        description="Generate red team engagement plans"
    )
    parser.add_argument("--client", required=True, help="Client organization name")
    parser.add_argument("--scenarios", nargs="+",
                        choices=list(ATTACK_SCENARIOS.keys()),
                        default=["phishing", "assumed_breach"],
                        help="Attack scenarios to include")
    parser.add_argument("--duration", type=int, default=4, help="Duration in weeks")
    parser.add_argument("--team-size", type=int, default=4, help="Red team size")
    parser.add_argument("--output", "-o", help="Output JSON plan path")
    args = parser.parse_args()

    print("[*] Red Team Engagement Planning Agent")
    plan = generate_engagement_plan(args.client, args.scenarios, args.duration, args.team_size)

    attack_trees = []
    for scenario in plan["scenarios"]:
        tree = generate_attack_tree(scenario)
        attack_trees.append(tree)
    plan["attack_trees"] = attack_trees

    print(f"[*] Plan generated for {args.client}")
    print(f"[*] Scenarios: {len(plan['scenarios'])}")
    print(f"[*] Duration: {args.duration} weeks, Team: {args.team_size}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(plan, f, indent=2)
        print(f"[*] Plan saved to {args.output}")
    else:
        print(json.dumps(plan, indent=2))


if __name__ == "__main__":
    main()
