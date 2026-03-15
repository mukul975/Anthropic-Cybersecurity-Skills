#!/usr/bin/env python3
"""Threat hunt hypothesis framework builder.

Generates structured threat hunting hypotheses from MITRE ATT&CK techniques,
maps data sources, defines detection logic, and tracks hunt outcomes.
"""

import sys
import json
import datetime
import hashlib

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


HUNT_MATURITY_LEVELS = {
    0: "Initial - ad hoc, no documentation",
    1: "Minimal - basic procedures, limited data",
    2: "Procedural - documented hypotheses, repeatable",
    3: "Innovative - custom analytics, threat intel driven",
    4: "Leading - automated, ML-assisted, continuous",
}

DATA_SOURCE_MAP = {
    "T1059.001": {"name": "PowerShell", "sources": ["Script Block Logging (4104)", "Module Logging (4103)",
                   "Process Creation (4688/Sysmon 1)"], "log_channel": "Microsoft-Windows-PowerShell/Operational"},
    "T1053.005": {"name": "Scheduled Task", "sources": ["Task Scheduler (4698/4702)", "Sysmon Event 1"],
                   "log_channel": "Microsoft-Windows-TaskScheduler/Operational"},
    "T1078": {"name": "Valid Accounts", "sources": ["Logon Events (4624/4625)", "Kerberos (4768/4769)"],
               "log_channel": "Security"},
    "T1003.001": {"name": "LSASS Memory", "sources": ["Sysmon Event 10 (ProcessAccess)", "Windows Defender alerts"],
                   "log_channel": "Microsoft-Windows-Sysmon/Operational"},
    "T1071.001": {"name": "Web Protocols C2", "sources": ["Proxy logs", "DNS query logs", "Zeek http.log"],
                   "log_channel": "Proxy/DNS"},
    "T1486": {"name": "Data Encrypted for Impact", "sources": ["File creation burst (Sysmon 11)",
               "Canary file triggers", "VSS deletion (Sysmon 1)"], "log_channel": "Sysmon"},
    "T1021.001": {"name": "Remote Desktop Protocol", "sources": ["Logon Type 10 (4624)",
                   "RDP connection (1149)"], "log_channel": "Security / TerminalServices-RemoteConnectionManager"},
}


def generate_hypothesis(technique_id, threat_actor=None, environment=None):
    """Generate a structured threat hunting hypothesis."""
    ds = DATA_SOURCE_MAP.get(technique_id, {})
    technique_name = ds.get("name", technique_id)
    hyp_id = "HYP-" + hashlib.md5(
        (technique_id + str(datetime.datetime.utcnow())).encode()
    ).hexdigest()[:8].upper()

    hypothesis = {
        "hypothesis_id": hyp_id,
        "created": datetime.datetime.utcnow().isoformat() + "Z",
        "technique_id": technique_id,
        "technique_name": technique_name,
        "hypothesis_statement": (
            "An adversary{} may be using {} ({}) within our environment{}. "
            "Evidence of this activity can be found in {}.".format(
                " (" + threat_actor + ")" if threat_actor else "",
                technique_name,
                technique_id,
                " targeting " + environment if environment else "",
                ", ".join(ds.get("sources", ["endpoint telemetry"])),
            )
        ),
        "data_sources": ds.get("sources", []),
        "log_channel": ds.get("log_channel", "Unknown"),
        "priority": "high" if technique_id in ["T1003.001", "T1486", "T1059.001"] else "medium",
        "status": "planned",
    }
    return hypothesis


def build_hunt_plan(hypotheses, analyst="SOC Analyst"):
    """Build a hunt plan from a list of hypotheses."""
    plan = {
        "plan_id": "PLAN-" + datetime.datetime.utcnow().strftime("%Y%m%d"),
        "created": datetime.datetime.utcnow().isoformat() + "Z",
        "analyst": analyst,
        "maturity_level": 2,
        "maturity_description": HUNT_MATURITY_LEVELS[2],
        "hypothesis_count": len(hypotheses),
        "hypotheses": hypotheses,
        "data_coverage": list(set(
            src for h in hypotheses for src in h.get("data_sources", [])
        )),
        "estimated_hours": len(hypotheses) * 4,
    }
    return plan


def evaluate_hunt_results(hypothesis, findings_count, true_positives, false_positives):
    """Evaluate hunt execution results and update hypothesis."""
    hypothesis["status"] = "completed"
    hypothesis["results"] = {
        "total_findings": findings_count,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "precision": round(true_positives / max(findings_count, 1), 3),
        "outcome": "confirmed" if true_positives > 0 else "not_confirmed",
        "recommendation": (
            "Create detection rule" if true_positives > 0
            else "Refine hypothesis and re-hunt with broader data"
        ),
    }
    return hypothesis


def fetch_attack_techniques():
    """Fetch MITRE ATT&CK technique list."""
    if not HAS_REQUESTS:
        return list(DATA_SOURCE_MAP.keys())
    try:
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        resp = requests.get(url, timeout=30)
        bundle = resp.json()
        techniques = [
            obj["external_references"][0]["external_id"]
            for obj in bundle.get("objects", [])
            if obj.get("type") == "attack-pattern"
            and obj.get("external_references")
            and not obj.get("x_mitre_deprecated", False)
        ]
        return techniques[:50]
    except Exception:
        return list(DATA_SOURCE_MAP.keys())


if __name__ == "__main__":
    print("=" * 60)
    print("Threat Hunt Hypothesis Framework")
    print("Hypothesis generation, hunt planning, result tracking")
    print("=" * 60)

    techniques = sys.argv[1:] if len(sys.argv) > 1 else ["T1059.001", "T1078", "T1003.001", "T1486"]
    actor = "APT29"

    hypotheses = []
    for t in techniques:
        h = generate_hypothesis(t, threat_actor=actor)
        hypotheses.append(h)

    plan = build_hunt_plan(hypotheses)
    print("\nHunt Plan: {} ({} hypotheses, ~{} hours)".format(
        plan["plan_id"], plan["hypothesis_count"], plan["estimated_hours"]))
    print("Maturity: {}".format(plan["maturity_description"]))

    print("\n--- Hypotheses ---")
    for h in hypotheses:
        print("  [{}] {} - {}".format(h["priority"].upper(), h["technique_id"], h["technique_name"]))
        print("    {}".format(h["hypothesis_statement"][:120] + "..."))
        print("    Sources: {}".format(", ".join(h["data_sources"][:3])))

    evaluated = evaluate_hunt_results(hypotheses[0], findings_count=12, true_positives=3, false_positives=9)
    print("\n--- Sample Result ---")
    print("  {} precision: {} -> {}".format(
        evaluated["technique_id"],
        evaluated["results"]["precision"],
        evaluated["results"]["recommendation"]))

    print("\n" + json.dumps({"hypotheses_generated": len(hypotheses)}, indent=2))
