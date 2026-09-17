#!/usr/bin/env python3
"""
Purple Team Atomic Testing Agent

Parses Atomic Red Team YAML definitions, correlates execution logs with detection
results, generates MITRE ATT&CK Navigator layers, and produces coverage gap reports.

Usage:
    python agent.py --atomics-path /path/to/atomics --log-dir /path/to/logs
    python agent.py --atomics-path /path/to/atomics --detections detection_results.json
    python agent.py --mode navigator --output-layer coverage.json
    python agent.py --mode report --output-report coverage_report.json

Requirements:
    pip install pyyaml
"""

import argparse
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ---------------------------------------------------------------------------
# MITRE ATT&CK Tactic Metadata
# ---------------------------------------------------------------------------

TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

TACTIC_ID_MAP = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}

# Top ATT&CK techniques by prevalence mapped to their primary tactic
TOP_TECHNIQUES_BY_TACTIC = {
    "execution": [
        "T1059.001", "T1059.003", "T1059.004", "T1059.005",
        "T1059.006", "T1059.007", "T1047", "T1053.005",
        "T1129", "T1203", "T1569.002",
    ],
    "persistence": [
        "T1547.001", "T1547.004", "T1547.009", "T1053.005",
        "T1136.001", "T1543.003", "T1546.001", "T1546.003",
        "T1574.001", "T1574.002", "T1197", "T1505.003",
    ],
    "privilege-escalation": [
        "T1548.002", "T1134.001", "T1068", "T1055.001",
        "T1055.003", "T1055.012",
    ],
    "defense-evasion": [
        "T1070.001", "T1070.004", "T1218.001", "T1218.003",
        "T1218.005", "T1218.010", "T1218.011", "T1027",
        "T1140", "T1562.001", "T1036.005", "T1112",
    ],
    "credential-access": [
        "T1003.001", "T1003.002", "T1003.003", "T1003.004",
        "T1003.005", "T1003.006", "T1110.001", "T1110.003",
        "T1555.003", "T1552.001", "T1558.003",
    ],
    "discovery": [
        "T1082", "T1083", "T1087.001", "T1087.002",
        "T1016", "T1049", "T1057", "T1069.001",
        "T1069.002", "T1518.001", "T1033",
    ],
    "lateral-movement": [
        "T1021.001", "T1021.002", "T1021.003",
        "T1021.004", "T1021.006", "T1570",
    ],
    "collection": [
        "T1005", "T1039", "T1074.001", "T1113",
        "T1115", "T1560.001",
    ],
    "command-and-control": [
        "T1071.001", "T1071.004", "T1105", "T1132.001",
        "T1573.001", "T1219", "T1090.001",
    ],
    "exfiltration": [
        "T1041", "T1048.003", "T1567.002",
    ],
    "impact": [
        "T1485", "T1486", "T1489", "T1490", "T1491.002",
    ],
}


# ---------------------------------------------------------------------------
# Atomics Parsing
# ---------------------------------------------------------------------------

def load_atomics_inventory(atomics_path):
    """Parse all Atomic Red Team YAML files into a technique inventory."""
    if not HAS_YAML:
        print("[ERROR] pyyaml required: pip install pyyaml")
        return {}

    inventory = {}
    atomics_dir = Path(atomics_path)

    if not atomics_dir.exists():
        print(f"[ERROR] Atomics path does not exist: {atomics_path}")
        return {}

    yaml_files = list(atomics_dir.glob("T*/T*.yaml"))
    if not yaml_files:
        print(f"[WARN] No YAML files found in {atomics_path}")
        return {}

    for yaml_file in sorted(yaml_files):
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            tech_id = data.get("attack_technique", "")
            if not tech_id:
                continue

            tests = data.get("atomic_tests", [])
            all_platforms = set()
            all_executors = set()
            parsed_tests = []

            for t in tests:
                platforms = t.get("supported_platforms", [])
                executor = t.get("executor", {})
                executor_name = executor.get("name", "unknown")
                all_platforms.update(platforms)
                all_executors.add(executor_name)

                parsed_tests.append({
                    "name": t.get("name", "Unnamed"),
                    "description": t.get("description", ""),
                    "platforms": platforms,
                    "executor": executor_name,
                    "elevation_required": t.get("executor", {}).get(
                        "elevation_required", False
                    ),
                    "has_cleanup": "cleanup_command" in executor,
                })

            inventory[tech_id] = {
                "name": data.get("display_name", tech_id),
                "test_count": len(tests),
                "platforms": sorted(all_platforms),
                "executors": sorted(all_executors),
                "tests": parsed_tests,
                "yaml_path": str(yaml_file),
            }

        except Exception as e:
            print(f"[WARN] Failed to parse {yaml_file.name}: {e}")

    return inventory


def load_execution_logs(log_dir):
    """Load atomic test execution logs from JSON files."""
    executed = {}
    log_path = Path(log_dir)

    if not log_path.exists():
        return executed

    for log_file in sorted(log_path.glob("T*_*.json")):
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            tech_id = data.get("technique_id", "")
            if not tech_id:
                continue

            if tech_id not in executed:
                executed[tech_id] = {
                    "executions": [],
                    "last_executed": "",
                    "total_runs": 0,
                    "success_count": 0,
                    "failure_count": 0,
                }

            results = data.get("results", [])
            successes = sum(1 for r in results if r.get("status") == "executed")
            failures = sum(1 for r in results if r.get("status") == "failed")

            executed[tech_id]["executions"].append({
                "timestamp": data.get("start_time", ""),
                "hostname": data.get("hostname", "unknown"),
                "username": data.get("username", "unknown"),
                "test_count": len(results),
                "successes": successes,
                "failures": failures,
            })
            executed[tech_id]["total_runs"] += len(results)
            executed[tech_id]["success_count"] += successes
            executed[tech_id]["failure_count"] += failures

            end_time = data.get("end_time", "")
            if end_time > executed[tech_id]["last_executed"]:
                executed[tech_id]["last_executed"] = end_time

        except Exception as e:
            print(f"[WARN] Failed to parse log {log_file.name}: {e}")

    return executed


def load_detection_results(detection_file):
    """Load SIEM detection validation results."""
    if not detection_file or not os.path.exists(detection_file):
        return {}

    try:
        with open(detection_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[WARN] Failed to load detections file: {e}")
        return {}

    detections = {}
    entries = data if isinstance(data, list) else data.get("results", [])

    for entry in entries:
        tech_id = entry.get("technique_id", "")
        if not tech_id:
            continue

        detections[tech_id] = {
            "detected": entry.get("detected", False),
            "alert_count": entry.get("alert_count", 0),
            "rule_name": entry.get("rule_name", ""),
            "confidence": entry.get("confidence", "unknown"),
            "data_sources": entry.get("data_sources", []),
            "siem_query": entry.get("siem_query", ""),
            "false_positive_rate": entry.get("false_positive_rate", None),
        }

    return detections


# ---------------------------------------------------------------------------
# Coverage Analysis
# ---------------------------------------------------------------------------

def compute_coverage_report(inventory, execution_logs, detection_results):
    """Generate a comprehensive coverage gap analysis report."""
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {},
        "tactics": {},
        "gaps": {
            "blind_spots": [],       # Executed but not detected
            "not_tested": [],        # Available but not executed
            "low_confidence": [],    # Detected but low confidence
        },
        "recommendations": [],
    }

    total_available = len(inventory)
    total_executed = len(execution_logs)
    total_detected = sum(
        1 for d in detection_results.values() if d.get("detected")
    )
    high_confidence = sum(
        1 for d in detection_results.values()
        if d.get("detected") and d.get("confidence") in ("high", "medium")
    )

    report["summary"] = {
        "total_techniques_with_atomics": total_available,
        "total_techniques_executed": total_executed,
        "total_techniques_with_detection": total_detected,
        "high_confidence_detections": high_confidence,
        "execution_coverage_pct": round(
            (total_executed / total_available * 100) if total_available else 0, 1
        ),
        "detection_coverage_pct": round(
            (total_detected / total_executed * 100) if total_executed else 0, 1
        ),
        "high_confidence_pct": round(
            (high_confidence / total_executed * 100) if total_executed else 0, 1
        ),
    }

    # Per-tactic breakdown
    for tactic in TACTIC_ORDER:
        technique_ids = TOP_TECHNIQUES_BY_TACTIC.get(tactic, [])
        tactic_data = {
            "tactic_id": TACTIC_ID_MAP.get(tactic, ""),
            "techniques_in_scope": len(technique_ids),
            "techniques_with_atomics": 0,
            "techniques_executed": 0,
            "techniques_detected": 0,
            "blind_spots": [],
            "not_tested": [],
        }

        for tech_id in technique_ids:
            has_atomic = tech_id in inventory
            was_executed = tech_id in execution_logs
            detection = detection_results.get(tech_id, {})
            was_detected = detection.get("detected", False)
            confidence = detection.get("confidence", "none")

            if has_atomic:
                tactic_data["techniques_with_atomics"] += 1
            if was_executed:
                tactic_data["techniques_executed"] += 1
            if was_detected:
                tactic_data["techniques_detected"] += 1

            tech_name = inventory.get(tech_id, {}).get("name", tech_id)

            # Classify gaps
            if was_executed and not was_detected:
                gap = {
                    "technique_id": tech_id,
                    "technique_name": tech_name,
                    "tactic": tactic,
                    "status": "BLIND_SPOT",
                }
                tactic_data["blind_spots"].append(tech_id)
                report["gaps"]["blind_spots"].append(gap)

            elif was_detected and confidence == "low":
                gap = {
                    "technique_id": tech_id,
                    "technique_name": tech_name,
                    "tactic": tactic,
                    "status": "LOW_CONFIDENCE",
                    "rule_name": detection.get("rule_name", ""),
                }
                report["gaps"]["low_confidence"].append(gap)

            elif has_atomic and not was_executed:
                gap = {
                    "technique_id": tech_id,
                    "technique_name": tech_name,
                    "tactic": tactic,
                    "status": "NOT_TESTED",
                    "tests_available": inventory[tech_id]["test_count"],
                }
                tactic_data["not_tested"].append(tech_id)
                report["gaps"]["not_tested"].append(gap)

        executed = tactic_data["techniques_executed"]
        detected = tactic_data["techniques_detected"]
        tactic_data["detection_coverage_pct"] = round(
            (detected / executed * 100) if executed else 0, 1
        )
        report["tactics"][tactic] = tactic_data

    # Recommendations
    blind_count = len(report["gaps"]["blind_spots"])
    if blind_count > 0:
        report["recommendations"].append({
            "priority": "CRITICAL",
            "action": f"Create detection rules for {blind_count} blind spot techniques",
            "techniques": [g["technique_id"] for g in report["gaps"]["blind_spots"]],
            "detail": "These techniques were executed but no SIEM/EDR alert was generated",
        })

    low_tactics = [
        t for t, d in report["tactics"].items()
        if d["detection_coverage_pct"] < 30 and d["techniques_executed"] > 0
    ]
    if low_tactics:
        report["recommendations"].append({
            "priority": "HIGH",
            "action": f"Improve detection coverage in: {', '.join(low_tactics)}",
            "detail": "These tactics have less than 30% detection rate among tested techniques",
        })

    untested_count = len(report["gaps"]["not_tested"])
    if untested_count > 10:
        report["recommendations"].append({
            "priority": "MEDIUM",
            "action": f"Expand test execution to {untested_count} untested techniques",
            "detail": "Atomic tests exist but have not been executed yet",
        })

    lc_count = len(report["gaps"]["low_confidence"])
    if lc_count > 0:
        report["recommendations"].append({
            "priority": "MEDIUM",
            "action": f"Tune {lc_count} low-confidence detection rules to reduce false positives",
            "techniques": [g["technique_id"] for g in report["gaps"]["low_confidence"]],
        })

    return report


# ---------------------------------------------------------------------------
# ATT&CK Navigator Layer Generation
# ---------------------------------------------------------------------------

def generate_navigator_layer(inventory, execution_logs, detection_results,
                             layer_name="Purple Team Coverage"):
    """Produce an ATT&CK Navigator v4.5 layer JSON."""
    layer = {
        "name": layer_name,
        "versions": {
            "attack": "15",
            "navigator": "5.1",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            f"Purple team atomic testing coverage layer. "
            f"Generated {datetime.utcnow().isoformat()}Z"
        ),
        "filters": {
            "platforms": ["Windows", "Linux", "macOS"],
        },
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
            {"label": "Blind Spot (tested, no detection)", "color": "#ff6666"},
            {"label": "Partial / Low Confidence", "color": "#ffeb3b"},
            {"label": "Detected (high confidence)", "color": "#66bb6a"},
            {"label": "Not Tested", "color": "#d3d3d3"},
        ],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }

    for tech_id, tech_data in sorted(inventory.items()):
        was_executed = tech_id in execution_logs
        detection = detection_results.get(tech_id, {})
        was_detected = detection.get("detected", False)
        confidence = detection.get("confidence", "none")

        if was_detected and confidence in ("high", "medium"):
            score = 100
            color = "#66bb6a"
            comment = f"DETECTED [{confidence}] - {detection.get('rule_name', 'alert active')}"
        elif was_detected:
            score = 50
            color = "#ffeb3b"
            comment = f"PARTIAL [{confidence}] - detection exists, needs tuning"
        elif was_executed:
            score = 0
            color = "#ff6666"
            comment = "BLIND SPOT - test executed, no detection"
        else:
            score = 0
            color = "#d3d3d3"
            comment = f"NOT TESTED - {tech_data['test_count']} atomic tests available"

        entry = {
            "techniqueID": tech_id,
            "tactic": "",
            "color": color,
            "comment": comment,
            "score": score,
            "enabled": True,
            "metadata": [
                {"name": "tests_available", "value": str(tech_data["test_count"])},
                {"name": "platforms", "value": ", ".join(tech_data["platforms"])},
                {"name": "executed", "value": str(was_executed)},
                {"name": "detected", "value": str(was_detected)},
            ],
            "links": [],
            "showSubtechniques": False,
        }

        if was_executed:
            log = execution_logs[tech_id]
            entry["metadata"].append({
                "name": "last_executed",
                "value": log.get("last_executed", "unknown"),
            })
            entry["metadata"].append({
                "name": "total_runs",
                "value": str(log.get("total_runs", 0)),
            })

        layer["techniques"].append(entry)

    return layer


# ---------------------------------------------------------------------------
# Sigma Rule Suggestion
# ---------------------------------------------------------------------------

SIGMA_TEMPLATES = {
    "T1059.001": {
        "title": "Suspicious PowerShell Script Block Execution",
        "logsource": {"product": "windows", "service": "powershell"},
        "detection_field": "ScriptBlockText",
        "event_id": 4104,
    },
    "T1003.001": {
        "title": "LSASS Memory Access for Credential Dumping",
        "logsource": {"product": "windows", "service": "sysmon"},
        "detection_field": "TargetImage",
        "event_id": 10,
        "target_pattern": "*lsass.exe",
    },
    "T1547.001": {
        "title": "Registry Run Key Persistence",
        "logsource": {"product": "windows", "service": "sysmon"},
        "detection_field": "TargetObject",
        "event_id": 13,
        "target_pattern": "*\\CurrentVersion\\Run*",
    },
    "T1053.005": {
        "title": "Scheduled Task Created via Command Line",
        "logsource": {"product": "windows", "service": "security"},
        "detection_field": "TaskName",
        "event_id": 4698,
    },
    "T1070.004": {
        "title": "Indicator Removal - File Deletion",
        "logsource": {"product": "windows", "service": "sysmon"},
        "detection_field": "TargetFilename",
        "event_id": 23,
    },
    "T1218.011": {
        "title": "Suspicious Rundll32 Execution",
        "logsource": {"product": "windows", "service": "sysmon"},
        "detection_field": "Image",
        "event_id": 1,
        "target_pattern": "*rundll32.exe",
    },
    "T1105": {
        "title": "Ingress Tool Transfer via Common Utilities",
        "logsource": {"product": "windows", "service": "sysmon"},
        "detection_field": "CommandLine",
        "event_id": 1,
        "target_pattern": "*certutil*|*bitsadmin*|*curl*|*wget*",
    },
}


def suggest_sigma_rules(blind_spots):
    """Suggest Sigma rule stubs for blind spot techniques."""
    suggestions = []
    for gap in blind_spots:
        tech_id = gap["technique_id"]
        template = SIGMA_TEMPLATES.get(tech_id)

        if template:
            sigma_stub = {
                "title": template["title"],
                "id": hashlib.md5(tech_id.encode()).hexdigest(),
                "status": "experimental",
                "description": (
                    f"Detects {gap['technique_name']} ({tech_id}) - "
                    f"generated from purple team blind spot analysis"
                ),
                "references": [
                    f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                ],
                "author": "Purple Team Automation",
                "date": datetime.utcnow().strftime("%Y/%m/%d"),
                "tags": [
                    f"attack.{gap.get('tactic', 'unknown')}",
                    f"attack.{tech_id.lower()}",
                ],
                "logsource": template["logsource"],
                "detection": {
                    "selection": {
                        "EventID": template["event_id"],
                    },
                    "condition": "selection",
                },
                "level": "medium",
                "falsepositives": ["Legitimate administrative activity"],
            }

            if "target_pattern" in template:
                sigma_stub["detection"]["selection"][template["detection_field"]] = (
                    template["target_pattern"]
                )

            suggestions.append({
                "technique_id": tech_id,
                "technique_name": gap["technique_name"],
                "sigma_rule": sigma_stub,
            })
        else:
            suggestions.append({
                "technique_id": tech_id,
                "technique_name": gap["technique_name"],
                "sigma_rule": None,
                "note": (
                    f"No template available for {tech_id}. "
                    f"Manual rule creation required. "
                    f"Reference: https://attack.mitre.org/techniques/"
                    f"{tech_id.replace('.', '/')}/"
                ),
            })

    return suggestions


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_coverage_report(report):
    """Print formatted coverage report to stdout."""
    print("=" * 76)
    print("  PURPLE TEAM ATOMIC TESTING - COVERAGE GAP ANALYSIS")
    print("=" * 76)
    print(f"  Generated: {report['generated_at']}")
    print()

    s = report["summary"]
    print("  EXECUTIVE SUMMARY")
    print("  " + "-" * 50)
    print(f"    Techniques with atomics:     {s['total_techniques_with_atomics']}")
    print(f"    Techniques executed:         {s['total_techniques_executed']}")
    print(f"    Techniques with detection:   {s['total_techniques_with_detection']}")
    print(f"    High-confidence detections:  {s['high_confidence_detections']}")
    print(f"    Execution coverage:          {s['execution_coverage_pct']}%")
    print(f"    Detection coverage:          {s['detection_coverage_pct']}%")
    print(f"    High-confidence rate:        {s['high_confidence_pct']}%")
    print()

    print("  PER-TACTIC DETECTION COVERAGE")
    print("  " + "-" * 72)
    header = f"  {'Tactic':<24} {'Scope':>6} {'Avail':>6} {'Exec':>6} {'Det':>6} {'Cov%':>7}"
    print(header)
    print("  " + "-" * 72)

    for tactic in TACTIC_ORDER:
        if tactic not in report["tactics"]:
            continue
        t = report["tactics"][tactic]
        if t["techniques_in_scope"] == 0:
            continue
        cov = t["detection_coverage_pct"]
        indicator = "!!!" if cov < 30 and t["techniques_executed"] > 0 else ""
        print(
            f"  {tactic:<24} {t['techniques_in_scope']:>6} "
            f"{t['techniques_with_atomics']:>6} "
            f"{t['techniques_executed']:>6} "
            f"{t['techniques_detected']:>6} "
            f"{cov:>6.1f}% {indicator}"
        )
    print()

    blind_spots = report["gaps"]["blind_spots"]
    if blind_spots:
        print(f"  CRITICAL BLIND SPOTS ({len(blind_spots)} techniques)")
        print("  " + "-" * 72)
        for gap in blind_spots:
            print(f"    [!] {gap['technique_id']:<14} {gap['technique_name']}")
            print(f"        Tactic: {gap['tactic']}")
        print()

    lc = report["gaps"]["low_confidence"]
    if lc:
        print(f"  LOW-CONFIDENCE DETECTIONS ({len(lc)} techniques)")
        print("  " + "-" * 72)
        for gap in lc:
            rule = gap.get("rule_name", "unnamed rule")
            print(f"    [~] {gap['technique_id']:<14} {gap['technique_name']}")
            print(f"        Rule: {rule} -- needs tuning")
        print()

    if report["recommendations"]:
        print("  RECOMMENDATIONS")
        print("  " + "-" * 72)
        for rec in report["recommendations"]:
            print(f"    [{rec['priority']}] {rec['action']}")
            if "techniques" in rec:
                techs = rec["techniques"][:8]
                suffix = f" (+{len(rec['techniques']) - 8} more)" if len(rec["techniques"]) > 8 else ""
                print(f"           Techniques: {', '.join(techs)}{suffix}")
            if "detail" in rec:
                print(f"           {rec['detail']}")
        print()


def generate_powershell_test_script(blind_spots, output_path):
    """Generate a PowerShell script to re-test blind spot techniques."""
    lines = [
        "# Auto-generated Purple Team Retest Script",
        f"# Generated: {datetime.utcnow().isoformat()}Z",
        f"# Blind spots to retest: {len(blind_spots)}",
        "#",
        "# DISCLAIMER: Only execute on systems you own or have authorization to test.",
        "# These tests execute real attack techniques. Run cleanup after each test.",
        "",
        "Import-Module invoke-atomicredteam",
        "",
        "$Results = @()",
        "",
    ]

    for gap in blind_spots:
        tech_id = gap["technique_id"]
        tech_name = gap["technique_name"]
        lines.extend([
            f'# --- {tech_id}: {tech_name} ---',
            f'Write-Host "[*] Testing {tech_id} - {tech_name}" -ForegroundColor Cyan',
            'try {',
            f'    Invoke-AtomicTest {tech_id} -TestNumbers 1 -CheckPrereqs',
            f'    Invoke-AtomicTest {tech_id} -TestNumbers 1 -GetPrereqs',
            f'    Invoke-AtomicTest {tech_id} -TestNumbers 1 -Confirm:$false',
            f'    $Results += [PSCustomObject]@{{ TechniqueId="{tech_id}"; Status="EXECUTED" }}',
            '    Write-Host "    [+] Success" -ForegroundColor Green',
            '} catch {',
            f'    $Results += [PSCustomObject]@{{ TechniqueId="{tech_id}"; Status="FAILED"; Error=$_.Exception.Message }}',
            '    Write-Host "    [-] Failed: $($_.Exception.Message)" -ForegroundColor Red',
            '}',
            'Start-Sleep -Seconds 30  # Allow SIEM ingestion',
            '',
        ])

    lines.extend([
        "# Cleanup all tests",
        'Write-Host "`n[*] Running cleanup..." -ForegroundColor Yellow',
    ])
    for gap in blind_spots:
        tech_id = gap["technique_id"]
        lines.append(
            f'try {{ Invoke-AtomicTest {tech_id} -TestNumbers 1 -Cleanup 2>&1 | Out-Null }} '
            f'catch {{ Write-Host "    Cleanup failed for {tech_id}" -ForegroundColor DarkYellow }}'
        )

    lines.extend([
        "",
        "# Summary",
        '$Results | Format-Table -AutoSize',
        '$Results | Export-Csv "retest_results_$(Get-Date -Format yyyyMMdd_HHmmss).csv" -NoTypeInformation',
    ])

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return output_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Purple Team Atomic Testing - Coverage Gap Analysis Agent"
    )
    parser.add_argument(
        "--atomics-path",
        default=os.path.join("C:\\", "AtomicRedTeam", "atomics"),
        help="Path to Atomic Red Team atomics directory",
    )
    parser.add_argument(
        "--log-dir",
        default=os.path.join("C:\\", "AtomicRedTeam", "logs"),
        help="Path to atomic test execution logs",
    )
    parser.add_argument(
        "--detections",
        default=None,
        help="Path to SIEM detection validation results JSON",
    )
    parser.add_argument(
        "--mode",
        choices=["report", "navigator", "sigma", "retest", "all"],
        default="all",
        help="Output mode: report, navigator layer, sigma suggestions, retest script, or all",
    )
    parser.add_argument("--output-layer", default="navigator_layer.json",
                        help="Output path for ATT&CK Navigator layer")
    parser.add_argument("--output-report", default="coverage_report.json",
                        help="Output path for coverage report JSON")
    parser.add_argument("--output-sigma", default="sigma_suggestions.json",
                        help="Output path for Sigma rule suggestions")
    parser.add_argument("--output-retest", default="retest_blind_spots.ps1",
                        help="Output path for PowerShell retest script")
    parser.add_argument("--layer-name", default="Purple Team Coverage",
                        help="Name for the ATT&CK Navigator layer")

    args = parser.parse_args()

    print("[*] Purple Team Atomic Testing Agent")
    print(f"    Mode: {args.mode}")
    print()

    # Load data
    print("[*] Loading atomics inventory...")
    inventory = load_atomics_inventory(args.atomics_path)
    print(f"    Loaded {len(inventory)} techniques with atomic tests")

    print("[*] Loading execution logs...")
    exec_logs = load_execution_logs(args.log_dir)
    print(f"    Loaded logs for {len(exec_logs)} techniques")

    print("[*] Loading detection results...")
    det_results = load_detection_results(args.detections)
    print(f"    Loaded detection data for {len(det_results)} techniques")
    print()

    # Generate coverage report
    report = compute_coverage_report(inventory, exec_logs, det_results)

    if args.mode in ("report", "all"):
        print_coverage_report(report)
        with open(args.output_report, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Coverage report saved: {args.output_report}")

    if args.mode in ("navigator", "all"):
        layer = generate_navigator_layer(
            inventory, exec_logs, det_results, args.layer_name
        )
        with open(args.output_layer, "w", encoding="utf-8") as f:
            json.dump(layer, f, indent=2)
        print(f"[+] Navigator layer saved: {args.output_layer}")
        print("    Import at: https://mitre-attack.github.io/attack-navigator/")

    if args.mode in ("sigma", "all"):
        blind_spots = report["gaps"]["blind_spots"]
        if blind_spots:
            suggestions = suggest_sigma_rules(blind_spots)
            with open(args.output_sigma, "w", encoding="utf-8") as f:
                json.dump(suggestions, f, indent=2)
            print(f"[+] Sigma suggestions saved: {args.output_sigma}")
            print(f"    {len([s for s in suggestions if s['sigma_rule']])} rules generated, "
                  f"{len([s for s in suggestions if not s['sigma_rule']])} need manual creation")
        else:
            print("[*] No blind spots found -- no Sigma suggestions needed")

    if args.mode in ("retest", "all"):
        blind_spots = report["gaps"]["blind_spots"]
        if blind_spots:
            ps_path = generate_powershell_test_script(blind_spots, args.output_retest)
            print(f"[+] Retest script saved: {ps_path}")
            print(f"    {len(blind_spots)} techniques queued for retesting")
        else:
            print("[*] No blind spots found -- no retest script needed")

    print()
    print("[*] Done.")


if __name__ == "__main__":
    main()
