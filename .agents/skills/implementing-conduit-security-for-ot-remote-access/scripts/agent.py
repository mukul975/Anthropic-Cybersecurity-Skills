#!/usr/bin/env python3
"""OT remote access conduit security assessment agent for ICS/SCADA environments."""

import argparse
import json
import logging
import os
import socket
import sys
from datetime import datetime
from typing import Dict, List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

OT_PORTS = {
    502: "Modbus TCP",
    102: "S7comm (Siemens)",
    44818: "EtherNet/IP",
    20000: "DNP3",
    4840: "OPC UA",
    2222: "EtherNet/IP (implicit)",
    47808: "BACnet",
    1911: "Niagara Fox",
    9600: "OMRON FINS",
}

CONDUIT_CHECKS = [
    {"id": "C-01", "control": "Jump server required for OT access",
     "category": "Access Control", "iec_ref": "IEC 62443-3-3 SR 5.1"},
    {"id": "C-02", "control": "MFA enforced on conduit entry point",
     "category": "Authentication", "iec_ref": "IEC 62443-3-3 SR 1.1"},
    {"id": "C-03", "control": "Session recording enabled",
     "category": "Monitoring", "iec_ref": "IEC 62443-3-3 SR 6.1"},
    {"id": "C-04", "control": "Time-limited access windows",
     "category": "Access Control", "iec_ref": "IEC 62443-3-3 SR 2.1"},
    {"id": "C-05", "control": "Network segmentation between IT and OT",
     "category": "Network", "iec_ref": "IEC 62443-3-3 SR 5.1"},
    {"id": "C-06", "control": "Protocol-aware firewall at conduit boundary",
     "category": "Network", "iec_ref": "IEC 62443-3-3 SR 5.2"},
    {"id": "C-07", "control": "Encrypted tunnel for remote access",
     "category": "Encryption", "iec_ref": "IEC 62443-3-3 SR 4.1"},
    {"id": "C-08", "control": "Vendor access through separate conduit",
     "category": "Access Control", "iec_ref": "IEC 62443-3-3 SR 1.13"},
]


def scan_ot_ports(target: str, timeout: int = 3) -> List[dict]:
    """Scan for exposed OT protocol ports on a target."""
    results = []
    for port, protocol in OT_PORTS.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                results.append({"port": port, "protocol": protocol, "status": "open"})
            s.close()
        except (socket.timeout, OSError):
            continue
    return results


def assess_conduit_controls(responses: Dict[str, bool]) -> List[dict]:
    """Assess conduit security controls against IEC 62443 requirements."""
    results = []
    for check in CONDUIT_CHECKS:
        implemented = responses.get(check["id"], False)
        results.append({
            **check,
            "implemented": implemented,
            "severity": "CRITICAL" if not implemented and check["category"] in ("Access Control", "Network") else "HIGH" if not implemented else "OK",
        })
    return results


def compute_conduit_risk_score(control_results: List[dict], open_ports: List[dict]) -> dict:
    """Compute conduit risk score based on controls and exposed ports."""
    max_score = len(CONDUIT_CHECKS) * 10
    score = sum(10 for c in control_results if c["implemented"])
    port_penalty = len(open_ports) * 5
    final_score = max(0, score - port_penalty)
    pct = (final_score / max_score * 100) if max_score else 0
    if pct >= 80:
        risk = "LOW"
    elif pct >= 50:
        risk = "MEDIUM"
    else:
        risk = "HIGH"
    return {"score": final_score, "max_score": max_score,
            "percentage": round(pct, 1), "risk_level": risk,
            "exposed_ot_ports": len(open_ports)}


def generate_report(targets: List[str], responses: Dict[str, bool]) -> dict:
    """Generate OT conduit security assessment report."""
    report = {"analysis_date": datetime.utcnow().isoformat(), "targets": []}
    control_results = assess_conduit_controls(responses)
    for target in targets:
        open_ports = scan_ot_ports(target)
        risk = compute_conduit_risk_score(control_results, open_ports)
        report["targets"].append({
            "host": target, "open_ot_ports": open_ports, "risk": risk,
        })
    report["conduit_controls"] = control_results
    report["summary"] = {
        "controls_implemented": sum(1 for c in control_results if c["implemented"]),
        "controls_total": len(control_results),
        "targets_scanned": len(targets),
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="OT Conduit Security Assessment Agent")
    parser.add_argument("--targets", nargs="+", default=[], help="OT gateway hosts to scan")
    parser.add_argument("--controls-data", default="", help="JSON file with control responses")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--output", default="conduit_report.json")
    args = parser.parse_args()

    responses = {}
    if args.controls_data and os.path.isfile(args.controls_data):
        with open(args.controls_data) as f:
            responses = json.load(f)

    os.makedirs(args.output_dir, exist_ok=True)
    report = generate_report(args.targets, responses)
    out_path = os.path.join(args.output_dir, args.output)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", out_path)
    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
