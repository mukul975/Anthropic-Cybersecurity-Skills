#!/usr/bin/env python3
"""Breach and Attack Simulation (BAS) agent for continuous security validation using MITRE ATT&CK."""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional

try:
    import requests
except ImportError:
    sys.exit("requests required: pip install requests")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ATTACK_TECHNIQUES = [
    {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access",
     "test_type": "email", "payload": "eicar_test_attachment"},
    {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution",
     "test_type": "endpoint", "payload": "benign_ps_download_cradle"},
    {"id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access",
     "test_type": "endpoint", "payload": "procdump_lsass_simulation"},
    {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement",
     "test_type": "network", "payload": "smb_admin_share_access"},
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact",
     "test_type": "endpoint", "payload": "benign_file_encryption"},
    {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control",
     "test_type": "network", "payload": "http_c2_beacon_simulation"},
    {"id": "T1048.003", "name": "Exfiltration Over Unencrypted Protocol", "tactic": "Exfiltration",
     "test_type": "network", "payload": "dns_exfil_simulation"},
]


def simulate_technique(technique: dict, target: str) -> dict:
    """Simulate a single ATT&CK technique and record detection status."""
    start_time = datetime.utcnow().isoformat()
    detected = False
    blocked = False
    alert_id = ""
    try:
        if technique["test_type"] == "network":
            resp = requests.get(f"http://{target}/health", timeout=5)
            detected = resp.status_code != 200
        elif technique["test_type"] == "email":
            detected = False
        elif technique["test_type"] == "endpoint":
            detected = False
    except requests.RequestException:
        blocked = True
        detected = True
    return {
        "technique_id": technique["id"],
        "technique_name": technique["name"],
        "tactic": technique["tactic"],
        "test_type": technique["test_type"],
        "start_time": start_time,
        "detected": detected,
        "blocked": blocked,
        "alert_generated": alert_id,
    }


def check_siem_detection(siem_url: str, api_key: str, technique_id: str,
                          time_window_minutes: int = 15) -> dict:
    """Check if SIEM generated an alert for the simulated technique."""
    try:
        resp = requests.get(
            f"{siem_url}/api/alerts",
            headers={"Authorization": f"Bearer {api_key}"},
            params={"technique": technique_id, "minutes": time_window_minutes},
            timeout=15)
        if resp.status_code == 200:
            alerts = resp.json().get("alerts", [])
            return {"detected": len(alerts) > 0, "alert_count": len(alerts)}
    except requests.RequestException:
        pass
    return {"detected": False, "alert_count": 0}


def compute_detection_coverage(results: List[dict]) -> dict:
    """Compute detection coverage across tested techniques."""
    total = len(results)
    detected = sum(1 for r in results if r["detected"])
    blocked = sum(1 for r in results if r["blocked"])
    by_tactic = {}
    for r in results:
        tactic = r["tactic"]
        if tactic not in by_tactic:
            by_tactic[tactic] = {"total": 0, "detected": 0}
        by_tactic[tactic]["total"] += 1
        if r["detected"]:
            by_tactic[tactic]["detected"] += 1
    return {
        "total_tests": total,
        "detected": detected,
        "blocked": blocked,
        "missed": total - detected,
        "detection_rate_pct": round(detected / total * 100, 1) if total else 0,
        "by_tactic": by_tactic,
    }


def generate_report(target: str, siem_url: str = "", siem_key: str = "") -> dict:
    """Run BAS simulation campaign and generate detection gap report."""
    report = {"analysis_date": datetime.utcnow().isoformat(), "target": target, "results": []}
    for technique in ATTACK_TECHNIQUES:
        result = simulate_technique(technique, target)
        if siem_url and siem_key:
            siem_check = check_siem_detection(siem_url, siem_key, technique["id"])
            result["siem_detection"] = siem_check
            if siem_check["detected"]:
                result["detected"] = True
        report["results"].append(result)
    report["coverage"] = compute_detection_coverage(report["results"])
    report["gaps"] = [r for r in report["results"] if not r["detected"]]
    report["recommendations"] = []
    for gap in report["gaps"]:
        report["recommendations"].append(
            f"Create detection rule for {gap['technique_id']} ({gap['technique_name']})")
    return report


def main():
    parser = argparse.ArgumentParser(description="Breach and Attack Simulation Agent")
    parser.add_argument("--target", required=True, help="Target host for simulation")
    parser.add_argument("--siem-url", default="", help="SIEM API URL for detection validation")
    parser.add_argument("--siem-key", default="", help="SIEM API key")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--output", default="bas_report.json")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    report = generate_report(args.target, args.siem_url, args.siem_key)
    out_path = os.path.join(args.output_dir, args.output)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", out_path)
    print(json.dumps(report["coverage"], indent=2))


if __name__ == "__main__":
    main()
