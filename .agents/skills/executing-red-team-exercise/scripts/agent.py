#!/usr/bin/env python3
# For authorized testing in lab/CTF environments only
"""Red team exercise planning and ATT&CK technique tracking agent."""

import argparse
import json
import logging
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Optional

try:
    import requests
except ImportError:
    import sys; sys.exit("requests is required: pip install requests")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


@dataclass
class TechniqueExecution:
    technique_id: str
    technique_name: str
    tactic: str
    timestamp: str = ""
    status: str = "planned"
    detected: bool = False
    detection_time: str = ""
    notes: str = ""


@dataclass
class RedTeamOperation:
    operation_name: str
    target_org: str
    emulated_actor: str
    start_date: str
    objectives: List[str] = field(default_factory=list)
    techniques: List[TechniqueExecution] = field(default_factory=list)


def load_attack_techniques(cache_file: str = "attack_enterprise.json") -> dict:
    """Load MITRE ATT&CK Enterprise techniques from local cache or upstream."""
    import os
    if os.path.exists(cache_file):
        with open(cache_file) as f:
            return json.load(f)
    logger.info("Downloading ATT&CK Enterprise data...")
    resp = requests.get(MITRE_ATTACK_URL, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    with open(cache_file, "w") as f:
        json.dump(data, f)
    return data


def get_actor_techniques(attack_data: dict, actor_name: str) -> List[dict]:
    """Extract techniques used by a specific threat actor from ATT&CK data."""
    actor_id = None
    for obj in attack_data.get("objects", []):
        if obj.get("type") == "intrusion-set" and actor_name.lower() in obj.get("name", "").lower():
            actor_id = obj["id"]
            break

    if not actor_id:
        logger.warning("Actor '%s' not found in ATT&CK data", actor_name)
        return []

    technique_refs = set()
    for obj in attack_data.get("objects", []):
        if obj.get("type") == "relationship" and obj.get("source_ref") == actor_id:
            if obj.get("relationship_type") == "uses":
                technique_refs.add(obj["target_ref"])

    techniques = []
    for obj in attack_data.get("objects", []):
        if obj.get("id") in technique_refs and obj.get("type") == "attack-pattern":
            ext_refs = obj.get("external_references", [])
            tech_id = next((r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"), "")
            kill_chain = obj.get("kill_chain_phases", [{}])
            tactic = kill_chain[0].get("phase_name", "") if kill_chain else ""
            techniques.append({"id": tech_id, "name": obj["name"], "tactic": tactic})

    logger.info("Found %d techniques for actor '%s'", len(techniques), actor_name)
    return techniques


def build_operation_plan(actor_name: str, target: str, objectives: List[str],
                         attack_data: dict) -> RedTeamOperation:
    """Create a red team operation plan based on emulated threat actor TTPs."""
    techniques = get_actor_techniques(attack_data, actor_name)
    executions = [
        TechniqueExecution(
            technique_id=t["id"], technique_name=t["name"],
            tactic=t["tactic"], status="planned",
        )
        for t in techniques
    ]
    return RedTeamOperation(
        operation_name=f"{actor_name} Emulation - {target}",
        target_org=target, emulated_actor=actor_name,
        start_date=datetime.utcnow().isoformat(),
        objectives=objectives, techniques=executions,
    )


def log_technique_execution(op: RedTeamOperation, technique_id: str,
                             detected: bool = False, notes: str = "") -> None:
    """Mark a technique as executed and record detection status."""
    for tech in op.techniques:
        if tech.technique_id == technique_id:
            tech.status = "executed"
            tech.timestamp = datetime.utcnow().isoformat()
            tech.detected = detected
            if detected:
                tech.detection_time = datetime.utcnow().isoformat()
            tech.notes = notes
            logger.info("Technique %s executed (detected=%s)", technique_id, detected)
            return
    logger.warning("Technique %s not found in operation plan", technique_id)


def generate_detection_gap_report(op: RedTeamOperation) -> dict:
    """Produce a detection gap analysis comparing executed vs detected techniques."""
    executed = [t for t in op.techniques if t.status == "executed"]
    detected = [t for t in executed if t.detected]
    missed = [t for t in executed if not t.detected]

    return {
        "operation": op.operation_name,
        "emulated_actor": op.emulated_actor,
        "total_techniques_planned": len(op.techniques),
        "techniques_executed": len(executed),
        "techniques_detected": len(detected),
        "techniques_missed": len(missed),
        "detection_rate": f"{len(detected)/len(executed)*100:.1f}%" if executed else "N/A",
        "detected_list": [asdict(t) for t in detected],
        "missed_list": [asdict(t) for t in missed],
        "recommendations": [
            f"Improve detection for {t.technique_id} ({t.technique_name})"
            for t in missed
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="Red Team Exercise Agent")
    parser.add_argument("--actor", required=True, help="Threat actor to emulate (e.g., APT29)")
    parser.add_argument("--target", required=True, help="Target organization name")
    parser.add_argument("--objectives", nargs="+", default=["Demonstrate domain compromise"])
    parser.add_argument("--output", default="redteam_plan.json")
    args = parser.parse_args()

    attack_data = load_attack_techniques()
    op = build_operation_plan(args.actor, args.target, args.objectives, attack_data)
    report = {
        "operation": asdict(op),
        "technique_count": len(op.techniques),
        "tactics_covered": list(set(t.tactic for t in op.techniques if t.tactic)),
    }
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Operation plan saved to %s", args.output)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
