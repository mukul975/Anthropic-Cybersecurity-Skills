#!/usr/bin/env python3
"""Agent for implementing Dragos Platform OT network monitoring."""

import json
import argparse
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


def query_dragos_api(base_url, api_key, endpoint):
    """Query the Dragos Platform API."""
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    resp = requests.get(f"{base_url}/api/v1/{endpoint}", headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def get_asset_inventory(base_url, api_key):
    """Retrieve OT asset inventory from Dragos."""
    data = query_dragos_api(base_url, api_key, "assets")
    assets = data.get("data", data.get("assets", []))
    summary = {"total": len(assets), "by_type": {}, "by_zone": {}}
    for asset in assets:
        atype = asset.get("type", asset.get("asset_type", "unknown"))
        zone = asset.get("zone", asset.get("network_zone", "unknown"))
        summary["by_type"][atype] = summary["by_type"].get(atype, 0) + 1
        summary["by_zone"][zone] = summary["by_zone"].get(zone, 0) + 1
    return {"summary": summary, "assets": assets[:100]}


def get_threat_detections(base_url, api_key):
    """Retrieve threat detections from Dragos."""
    data = query_dragos_api(base_url, api_key, "detections")
    detections = data.get("data", data.get("detections", []))
    by_severity = {}
    for det in detections:
        sev = det.get("severity", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
    return {"total": len(detections), "by_severity": by_severity, "detections": detections[:50]}


def get_vulnerabilities(base_url, api_key):
    """Retrieve OT vulnerabilities from Dragos."""
    data = query_dragos_api(base_url, api_key, "vulnerabilities")
    vulns = data.get("data", data.get("vulnerabilities", []))
    critical = [v for v in vulns if v.get("severity", "").lower() == "critical"]
    return {"total": len(vulns), "critical_count": len(critical), "critical": critical[:20]}


def analyze_ot_protocols(log_path):
    """Analyze OT protocol traffic from exported logs."""
    protocol_counts = {}
    anomalies = []
    with open(log_path) as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            proto = entry.get("protocol", entry.get("service", ""))
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
            if entry.get("anomaly") or entry.get("alert"):
                anomalies.append({
                    "timestamp": entry.get("timestamp", ""),
                    "protocol": proto,
                    "src": entry.get("src_ip", ""),
                    "dst": entry.get("dst_ip", ""),
                    "description": entry.get("description", entry.get("alert", "")),
                })
    return {"protocols": protocol_counts, "anomalies": anomalies[:100]}


def generate_monitoring_config():
    """Generate OT monitoring configuration template."""
    return {
        "monitored_protocols": [
            {"name": "Modbus/TCP", "port": 502, "monitoring": "deep_packet_inspection"},
            {"name": "EtherNet/IP", "port": 44818, "monitoring": "deep_packet_inspection"},
            {"name": "DNP3", "port": 20000, "monitoring": "deep_packet_inspection"},
            {"name": "OPC UA", "port": 4840, "monitoring": "deep_packet_inspection"},
            {"name": "IEC 61850 MMS", "port": 102, "monitoring": "protocol_aware"},
            {"name": "S7comm", "port": 102, "monitoring": "deep_packet_inspection"},
            {"name": "BACnet", "port": 47808, "monitoring": "protocol_aware"},
        ],
        "alert_thresholds": {
            "new_asset_detection": True,
            "protocol_anomaly": True,
            "unauthorized_protocol": True,
            "firmware_change_detection": True,
            "plc_program_change": True,
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Dragos Platform OT Monitoring Agent")
    parser.add_argument("--url", help="Dragos Platform base URL")
    parser.add_argument("--api-key", help="Dragos API key")
    parser.add_argument("--log", help="OT protocol log (JSON lines)")
    parser.add_argument("--output", default="dragos_monitoring_report.json")
    parser.add_argument("--action", choices=["assets", "threats", "vulns", "protocols",
                                              "config", "full"], default="full")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.url and args.api_key:
        if args.action in ("assets", "full"):
            r = get_asset_inventory(args.url, args.api_key)
            report["findings"]["assets"] = r
            print(f"[+] Assets: {r['summary']['total']}")
        if args.action in ("threats", "full"):
            r = get_threat_detections(args.url, args.api_key)
            report["findings"]["detections"] = r
            print(f"[+] Detections: {r['total']}")
        if args.action in ("vulns", "full"):
            r = get_vulnerabilities(args.url, args.api_key)
            report["findings"]["vulnerabilities"] = r
            print(f"[+] Vulnerabilities: {r['total']} ({r['critical_count']} critical)")

    if args.action in ("protocols", "full") and args.log:
        r = analyze_ot_protocols(args.log)
        report["findings"]["protocol_analysis"] = r
        print(f"[+] Protocol anomalies: {len(r['anomalies'])}")

    if args.action in ("config", "full"):
        config = generate_monitoring_config()
        report["findings"]["monitoring_config"] = config
        print("[+] Monitoring config generated")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
