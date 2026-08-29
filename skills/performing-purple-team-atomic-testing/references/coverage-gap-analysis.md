# ATT&CK Coverage Gap Analysis Script

Full Python script for Step 5 of the workflow. Parses the atomics library, execution logs, and SIEM detection exports to produce a coverage gap report and an ATT&CK Navigator layer JSON for heatmap visualization.

```python
#!/usr/bin/env python3
"""ATT&CK coverage gap analysis - compares atomic test results against SIEM detections."""

import json
import os
import yaml
from pathlib import Path
from datetime import datetime


def load_atomics_inventory(atomics_path):
    """Parse all atomic test YAML files to build technique inventory."""
    inventory = {}
    atomics_dir = Path(atomics_path)

    for yaml_file in atomics_dir.glob("T*/T*.yaml"):
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            tech_id = data.get("attack_technique", "")
            if not tech_id:
                continue

            tests = data.get("atomic_tests", [])
            inventory[tech_id] = {
                "name": data.get("display_name", "Unknown"),
                "test_count": len(tests),
                "platforms": list(set(
                    p for t in tests
                    for p in t.get("supported_platforms", [])
                )),
                "tests": [
                    {
                        "name": t.get("name", "Unnamed"),
                        "description": t.get("description", ""),
                        "platforms": t.get("supported_platforms", []),
                        "executor": t.get("executor", {}).get("name", "unknown"),
                    }
                    for t in tests
                ],
            }
        except Exception as e:
            print(f"[WARN] Failed to parse {yaml_file}: {e}")

    return inventory


def load_execution_logs(log_dir):
    """Load atomic test execution logs."""
    executed = {}
    log_path = Path(log_dir)

    if not log_path.exists():
        return executed

    for log_file in log_path.glob("T*_*.json"):
        try:
            with open(log_file, "r") as f:
                data = json.load(f)
            tech_id = data.get("technique_id", "")
            if tech_id:
                if tech_id not in executed:
                    executed[tech_id] = {
                        "executions": [],
                        "last_executed": data.get("end_time", ""),
                    }
                executed[tech_id]["executions"].append({
                    "timestamp": data.get("start_time", ""),
                    "results": data.get("results", []),
                })
        except Exception as e:
            print(f"[WARN] Failed to parse {log_file}: {e}")

    return executed


def load_detection_results(detection_file):
    """Load SIEM detection validation results (JSON export from SIEM queries)."""
    if not os.path.exists(detection_file):
        return {}

    with open(detection_file, "r") as f:
        data = json.load(f)

    detections = {}
    for entry in data:
        tech_id = entry.get("technique_id", "")
        if tech_id:
            detections[tech_id] = {
                "detected": entry.get("detected", False),
                "alert_count": entry.get("alert_count", 0),
                "rule_name": entry.get("rule_name", ""),
                "confidence": entry.get("confidence", "unknown"),
                "data_sources": entry.get("data_sources", []),
            }

    return detections


# MITRE ATT&CK tactic ordering for structured output
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

# Tactic-to-technique mapping for common techniques (subset for illustration)
TACTIC_TECHNIQUE_MAP = {
    "execution": [
        "T1059", "T1059.001", "T1059.003", "T1059.004", "T1059.005",
        "T1059.006", "T1059.007", "T1047", "T1053", "T1053.005",
        "T1129", "T1203", "T1569", "T1569.002",
    ],
    "persistence": [
        "T1547", "T1547.001", "T1547.004", "T1547.009",
        "T1053.005", "T1136", "T1136.001", "T1543", "T1543.003",
        "T1546", "T1546.001", "T1546.003", "T1574", "T1574.001",
        "T1197", "T1505", "T1505.003",
    ],
    "credential-access": [
        "T1003", "T1003.001", "T1003.002", "T1003.003",
        "T1003.004", "T1003.005", "T1003.006",
        "T1110", "T1110.001", "T1110.003",
        "T1555", "T1555.003", "T1552", "T1552.001",
        "T1558", "T1558.003",
    ],
    "defense-evasion": [
        "T1070", "T1070.001", "T1070.004",
        "T1218", "T1218.001", "T1218.003", "T1218.005",
        "T1218.010", "T1218.011",
        "T1027", "T1140", "T1562", "T1562.001",
        "T1036", "T1036.005",
    ],
    "discovery": [
        "T1082", "T1083", "T1087", "T1087.001", "T1087.002",
        "T1016", "T1049", "T1057", "T1069", "T1069.001",
        "T1069.002", "T1518", "T1518.001",
    ],
    "lateral-movement": [
        "T1021", "T1021.001", "T1021.002", "T1021.003",
        "T1021.004", "T1021.006", "T1570",
    ],
    "command-and-control": [
        "T1071", "T1071.001", "T1071.004",
        "T1105", "T1132", "T1573", "T1573.001",
        "T1219", "T1090",
    ],
    "exfiltration": [
        "T1041", "T1048", "T1048.003", "T1567",
    ],
    "impact": [
        "T1485", "T1486", "T1489", "T1490", "T1491",
    ],
}


def generate_coverage_report(atomics_inventory, execution_logs, detection_results):
    """Generate comprehensive coverage gap analysis."""
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {},
        "tactics": {},
        "gaps": [],
        "recommendations": [],
    }

    total_available = len(atomics_inventory)
    total_executed = len(execution_logs)
    total_detected = sum(1 for d in detection_results.values() if d.get("detected"))

    report["summary"] = {
        "total_techniques_with_atomics": total_available,
        "total_techniques_executed": total_executed,
        "total_techniques_detected": total_detected,
        "execution_coverage_pct": round(
            (total_executed / total_available * 100) if total_available else 0, 1
        ),
        "detection_coverage_pct": round(
            (total_detected / total_executed * 100) if total_executed else 0, 1
        ),
    }

    # Per-tactic analysis
    for tactic, technique_ids in TACTIC_TECHNIQUE_MAP.items():
        tactic_data = {
            "techniques_available": 0,
            "techniques_executed": 0,
            "techniques_detected": 0,
            "gaps": [],
        }

        for tech_id in technique_ids:
            if tech_id in atomics_inventory:
                tactic_data["techniques_available"] += 1

                executed = tech_id in execution_logs
                detected = detection_results.get(tech_id, {}).get("detected", False)

                if executed:
                    tactic_data["techniques_executed"] += 1
                if detected:
                    tactic_data["techniques_detected"] += 1

                if executed and not detected:
                    gap = {
                        "technique_id": tech_id,
                        "technique_name": atomics_inventory[tech_id]["name"],
                        "tactic": tactic,
                        "status": "BLIND_SPOT",
                        "detail": "Test executed but no detection triggered",
                    }
                    tactic_data["gaps"].append(gap)
                    report["gaps"].append(gap)
                elif not executed and tech_id in atomics_inventory:
                    gap = {
                        "technique_id": tech_id,
                        "technique_name": atomics_inventory[tech_id]["name"],
                        "tactic": tactic,
                        "status": "NOT_TESTED",
                        "detail": "Atomic test available but not yet executed",
                    }
                    tactic_data["gaps"].append(gap)

        avail = tactic_data["techniques_available"]
        tactic_data["coverage_pct"] = round(
            (tactic_data["techniques_detected"] / avail * 100) if avail else 0, 1
        )
        report["tactics"][tactic] = tactic_data

    # Generate prioritized recommendations
    blind_spots = [g for g in report["gaps"] if g["status"] == "BLIND_SPOT"]
    if blind_spots:
        report["recommendations"].append({
            "priority": "CRITICAL",
            "action": f"Write detection rules for {len(blind_spots)} blind spot techniques",
            "techniques": [g["technique_id"] for g in blind_spots],
        })

    low_coverage_tactics = [
        t for t, d in report["tactics"].items() if d["coverage_pct"] < 30
    ]
    if low_coverage_tactics:
        report["recommendations"].append({
            "priority": "HIGH",
            "action": f"Expand testing in low-coverage tactics: {', '.join(low_coverage_tactics)}",
            "detail": "These tactics have less than 30% detection coverage",
        })

    return report


def generate_navigator_layer(atomics_inventory, execution_logs, detection_results,
                             layer_name="Purple Team Coverage"):
    """Generate ATT&CK Navigator layer JSON for heatmap visualization."""
    layer = {
        "name": layer_name,
        "versions": {
            "attack": "15",
            "navigator": "5.1",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": f"Purple team atomic testing coverage - Generated {datetime.utcnow().isoformat()}Z",
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
        },
        "hideDisabled": False,
        "techniques": [],
        "gradient": {
            "colors": ["#ff6666", "#ffeb3b", "#66bb6a"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "No Coverage (Blind Spot)", "color": "#ff6666"},
            {"label": "Logged Only (Partial)", "color": "#ffeb3b"},
            {"label": "Alert/Detection Active", "color": "#66bb6a"},
            {"label": "Not Tested", "color": "#d3d3d3"},
        ],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }

    for tech_id, tech_data in atomics_inventory.items():
        executed = tech_id in execution_logs
        detection = detection_results.get(tech_id, {})
        detected = detection.get("detected", False)
        confidence = detection.get("confidence", "none")

        if detected and confidence in ("high", "medium"):
            score = 100
            color = "#66bb6a"  # Green - high confidence detection
            comment = f"DETECTED - {detection.get('rule_name', 'Alert active')}"
        elif detected:
            score = 50
            color = "#ffeb3b"  # Yellow - logged/partial
            comment = "PARTIAL - Detection exists but low confidence"
        elif executed:
            score = 0
            color = "#ff6666"  # Red - blind spot
            comment = "BLIND SPOT - Test executed, no detection"
        else:
            score = 0
            color = "#d3d3d3"  # Gray - not tested
            comment = f"NOT TESTED - {tech_data['test_count']} atomic tests available"

        technique_entry = {
            "techniqueID": tech_id,
            "tactic": "",
            "color": color,
            "comment": comment,
            "score": score,
            "enabled": True,
            "metadata": [
                {"name": "tests_available", "value": str(tech_data["test_count"])},
                {"name": "executed", "value": str(executed)},
                {"name": "detected", "value": str(detected)},
            ],
            "links": [],
            "showSubtechniques": False,
        }
        layer["techniques"].append(technique_entry)

    return layer


def print_coverage_report(report):
    """Print formatted coverage report to console."""
    print("=" * 72)
    print("PURPLE TEAM ATOMIC TESTING - COVERAGE GAP ANALYSIS")
    print("=" * 72)
    print(f"Generated: {report['generated_at']}")
    print()

    s = report["summary"]
    print("EXECUTIVE SUMMARY")
    print("-" * 40)
    print(f"  Techniques with atomics:  {s['total_techniques_with_atomics']}")
    print(f"  Techniques executed:      {s['total_techniques_executed']}")
    print(f"  Techniques detected:      {s['total_techniques_detected']}")
    print(f"  Execution coverage:       {s['execution_coverage_pct']}%")
    print(f"  Detection coverage:       {s['detection_coverage_pct']}%")
    print()

    print("PER-TACTIC COVERAGE")
    print("-" * 72)
    print(f"{'Tactic':<25} {'Available':>9} {'Executed':>9} {'Detected':>9} {'Coverage':>9}")
    print("-" * 72)
    for tactic in TACTIC_ORDER:
        if tactic in report["tactics"]:
            t = report["tactics"][tactic]
            bar = "#" * int(t["coverage_pct"] / 5) + "." * (20 - int(t["coverage_pct"] / 5))
            print(
                f"  {tactic:<23} {t['techniques_available']:>9} "
                f"{t['techniques_executed']:>9} {t['techniques_detected']:>9} "
                f"{t['coverage_pct']:>8.1f}%"
            )
    print()

    blind_spots = [g for g in report["gaps"] if g["status"] == "BLIND_SPOT"]
    if blind_spots:
        print("CRITICAL BLIND SPOTS (executed but not detected)")
        print("-" * 72)
        for gap in blind_spots:
            print(f"  [!] {gap['technique_id']} - {gap['technique_name']}")
            print(f"      Tactic: {gap['tactic']}")
        print()

    if report["recommendations"]:
        print("RECOMMENDATIONS")
        print("-" * 72)
        for rec in report["recommendations"]:
            print(f"  [{rec['priority']}] {rec['action']}")
            if "techniques" in rec:
                print(f"         Techniques: {', '.join(rec['techniques'][:10])}")
            if "detail" in rec:
                print(f"         {rec['detail']}")
        print()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ATT&CK coverage gap analysis for purple team testing")
    parser.add_argument("--atomics-path", default=r"C:\AtomicRedTeam\atomics",
                        help="Path to Atomic Red Team atomics directory")
    parser.add_argument("--log-dir", default=r"C:\AtomicRedTeam\logs",
                        help="Path to atomic test execution logs")
    parser.add_argument("--detections-file", default="detection_results.json",
                        help="Path to SIEM detection validation export (JSON)")
    parser.add_argument("--output-layer", default="navigator_layer.json",
                        help="Output path for ATT&CK Navigator layer JSON")
    parser.add_argument("--output-report", default="coverage_report.json",
                        help="Output path for coverage report JSON")
    args = parser.parse_args()

    print("[*] Loading atomics inventory...")
    inventory = load_atomics_inventory(args.atomics_path)
    print(f"    Found {len(inventory)} techniques with atomic tests")

    print("[*] Loading execution logs...")
    exec_logs = load_execution_logs(args.log_dir)
    print(f"    Found logs for {len(exec_logs)} techniques")

    print("[*] Loading detection results...")
    det_results = load_detection_results(args.detections_file)
    print(f"    Found detection data for {len(det_results)} techniques")

    print("[*] Generating coverage report...")
    report = generate_coverage_report(inventory, exec_logs, det_results)
    print_coverage_report(report)

    # Save report JSON
    with open(args.output_report, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Report saved to {args.output_report}")

    # Generate and save Navigator layer
    print("[*] Generating ATT&CK Navigator layer...")
    layer = generate_navigator_layer(inventory, exec_logs, det_results)
    with open(args.output_layer, "w") as f:
        json.dump(layer, f, indent=2)
    print(f"[+] Navigator layer saved to {args.output_layer}")
    print(f"    Import at: https://mitre-attack.github.io/attack-navigator/")
```

