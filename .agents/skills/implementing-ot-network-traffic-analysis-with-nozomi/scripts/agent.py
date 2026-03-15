#!/usr/bin/env python3
"""Nozomi Networks OT Traffic Analysis Agent - monitors ICS protocols and detects anomalies."""

import json
import argparse
import logging
import subprocess
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def nozomi_api(base_url, token, endpoint):
    cmd = ["curl", "-s", "-k", "-H", f"Authorization: Bearer {token}", f"{base_url}/api/v1{endpoint}"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout else {}


def get_alerts(base_url, token):
    return nozomi_api(base_url, token, "/alerts?limit=500")


def get_assets(base_url, token):
    return nozomi_api(base_url, token, "/assets?limit=500")


def get_sessions(base_url, token):
    return nozomi_api(base_url, token, "/sessions?limit=500")


def analyze_ot_protocols(sessions):
    protocol_counts = defaultdict(int)
    ot_protocols = {"modbus", "s7comm", "dnp3", "opcua", "ethernet/ip", "bacnet", "profinet"}
    ot_sessions = []
    for session in sessions:
        proto = session.get("protocol", "").lower()
        protocol_counts[proto] += 1
        if proto in ot_protocols:
            ot_sessions.append({"source": session.get("source_ip", ""), "destination": session.get("destination_ip", ""),
                              "protocol": proto, "bytes": session.get("bytes_total", 0)})
    return {"protocol_distribution": dict(protocol_counts), "ot_sessions": len(ot_sessions), "total_sessions": len(sessions)}


def detect_anomalies(alerts):
    anomaly_types = defaultdict(list)
    for alert in alerts:
        anomaly_types[alert.get("type_id", "unknown")].append({
            "description": alert.get("description", ""), "risk": alert.get("risk", ""),
            "source": alert.get("source_ip", ""), "timestamp": alert.get("created_at", ""),
        })
    return {cat: {"count": len(items), "samples": items[:3]} for cat, items in anomaly_types.items()}


def audit_asset_inventory(assets):
    by_type = defaultdict(int)
    by_vendor = defaultdict(int)
    for asset in assets:
        by_type[asset.get("type", "unknown")] += 1
        by_vendor[asset.get("vendor", "unknown")] += 1
    return {"total_assets": len(assets), "by_type": dict(by_type),
            "by_vendor": dict(sorted(by_vendor.items(), key=lambda x: x[1], reverse=True)[:10])}


def generate_report(alerts, sessions, assets, base_url):
    return {
        "timestamp": datetime.utcnow().isoformat(), "nozomi_url": base_url,
        "alert_summary": {"total": len(alerts), "critical": sum(1 for a in alerts if a.get("risk") == "critical")},
        "protocol_analysis": analyze_ot_protocols(sessions),
        "anomalies": detect_anomalies(alerts),
        "asset_inventory": audit_asset_inventory(assets),
    }


def main():
    parser = argparse.ArgumentParser(description="Nozomi Networks OT Traffic Analysis Agent")
    parser.add_argument("--nozomi-url", required=True, help="Nozomi Guardian URL")
    parser.add_argument("--token", required=True, help="API bearer token")
    parser.add_argument("--output", default="nozomi_ot_report.json")
    args = parser.parse_args()
    alerts = get_alerts(args.nozomi_url, args.token)
    sessions = get_sessions(args.nozomi_url, args.token)
    assets = get_assets(args.nozomi_url, args.token)
    report = generate_report(alerts, sessions, assets, args.nozomi_url)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Nozomi: %d alerts, %d sessions, %d assets", len(alerts), len(sessions), len(assets))
    print(json.dumps(report, indent=2, default=str))

if __name__ == "__main__":
    main()
