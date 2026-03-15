#!/usr/bin/env python3
"""Ransomware Tabletop Exercise agent — generates scenario injects, tracks
participant decisions, scores response effectiveness, and produces an
after-action report."""

import argparse
import json
import random
import sys
from datetime import datetime
from pathlib import Path


SCENARIO_PHASES = [
    {
        "phase": "detection",
        "inject": "SOC analyst observes unusual SMB traffic and multiple failed login attempts from a single workstation. AV alerts show Cobalt Strike beacon signatures.",
        "expected_actions": ["isolate_host", "preserve_evidence", "notify_ir_lead"],
        "time_pressure_minutes": 15,
    },
    {
        "phase": "containment",
        "inject": "Ransomware has spread to 3 file servers. Active encryption observed on \\fs01\shared. Lateral movement detected via PsExec.",
        "expected_actions": ["network_segmentation", "disable_compromised_accounts", "block_c2_domains", "preserve_shadow_copies"],
        "time_pressure_minutes": 30,
    },
    {
        "phase": "escalation",
        "inject": "Threat actor sends ransom demand via email: 50 BTC within 48 hours. They claim to have exfiltrated 200GB of customer PII data.",
        "expected_actions": ["notify_executive_team", "engage_legal_counsel", "contact_law_enforcement", "activate_crisis_comms"],
        "time_pressure_minutes": 60,
    },
    {
        "phase": "eradication",
        "inject": "IR team identifies initial access via phishing email with macro-enabled document. Persistence mechanisms found in scheduled tasks and registry run keys.",
        "expected_actions": ["remove_persistence", "reset_all_credentials", "rebuild_compromised_hosts", "reset_krbtgt_twice"],
        "time_pressure_minutes": 120,
    },
    {
        "phase": "recovery",
        "inject": "Backups verified clean. Recovery point is 6 hours old. Business requests fastest path to resume operations.",
        "expected_actions": ["restore_from_backup", "validate_restored_systems", "monitor_for_reinfection", "staged_network_reconnection"],
        "time_pressure_minutes": 240,
    },
]


def generate_scenario(variant: str = "standard") -> list[dict]:
    """Return the scenario phases, optionally shuffled for advanced exercises."""
    phases = [dict(p) for p in SCENARIO_PHASES]
    if variant == "accelerated":
        for p in phases:
            p["time_pressure_minutes"] = max(5, p["time_pressure_minutes"] // 2)
    return phases


def score_response(phase: dict, participant_actions: list[str]) -> dict:
    """Score participant actions against expected actions for a phase."""
    expected = set(phase["expected_actions"])
    taken = set(participant_actions)
    correct = expected & taken
    missed = expected - taken
    extra = taken - expected
    score = len(correct) / len(expected) * 100 if expected else 0
    return {
        "phase": phase["phase"],
        "score_pct": round(score, 1),
        "correct_actions": sorted(correct),
        "missed_actions": sorted(missed),
        "additional_actions": sorted(extra),
    }


def evaluate_exercise(scenario: list[dict], all_responses: list[list[str]]) -> dict:
    """Score all phases and compute overall effectiveness."""
    phase_scores = []
    for phase, actions in zip(scenario, all_responses):
        phase_scores.append(score_response(phase, actions))
    overall = sum(s["score_pct"] for s in phase_scores) / len(phase_scores) if phase_scores else 0
    return {
        "phase_scores": phase_scores,
        "overall_score_pct": round(overall, 1),
        "rating": "excellent" if overall >= 90 else "good" if overall >= 70 else "needs_improvement" if overall >= 50 else "critical_gaps",
    }


def generate_aar(scenario: list[dict], evaluation: dict) -> dict:
    """Generate After-Action Report."""
    recommendations = []
    for ps in evaluation["phase_scores"]:
        if ps["missed_actions"]:
            recommendations.append({
                "phase": ps["phase"],
                "gap": f"Missed actions: {', '.join(ps['missed_actions'])}",
                "recommendation": f"Add {ps['phase']} procedures to IR playbook and train responders",
            })
    return {
        "report": "ransomware_tabletop_aar",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "scenario_phases": len(scenario),
        "evaluation": evaluation,
        "recommendations": recommendations,
        "next_exercise_date": "Schedule within 90 days to validate improvements",
    }


def run_demo() -> dict:
    """Run a demonstration exercise with simulated participant responses."""
    scenario = generate_scenario("standard")
    simulated_responses = [
        ["isolate_host", "notify_ir_lead"],
        ["network_segmentation", "disable_compromised_accounts", "block_c2_domains"],
        ["notify_executive_team", "engage_legal_counsel", "contact_law_enforcement", "activate_crisis_comms"],
        ["remove_persistence", "reset_all_credentials", "rebuild_compromised_hosts"],
        ["restore_from_backup", "validate_restored_systems", "monitor_for_reinfection", "staged_network_reconnection"],
    ]
    evaluation = evaluate_exercise(scenario, simulated_responses)
    return generate_aar(scenario, evaluation)


def main():
    parser = argparse.ArgumentParser(description="Ransomware Tabletop Exercise Agent")
    parser.add_argument("--mode", choices=["generate", "score", "demo"], default="demo",
                        help="Mode: generate scenario, score responses, or run demo")
    parser.add_argument("--variant", choices=["standard", "accelerated"], default="standard")
    parser.add_argument("--responses-file", help="JSON file with participant responses for scoring")
    parser.add_argument("--output", help="Output JSON file path")
    args = parser.parse_args()

    if args.mode == "generate":
        result = {"scenario": generate_scenario(args.variant)}
    elif args.mode == "score":
        if not args.responses_file:
            print("Error: --responses-file required for score mode", file=sys.stderr)
            sys.exit(1)
        responses = json.loads(Path(args.responses_file).read_text())
        scenario = generate_scenario(args.variant)
        evaluation = evaluate_exercise(scenario, responses)
        result = generate_aar(scenario, evaluation)
    else:
        result = run_demo()

    output = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
