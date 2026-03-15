#!/usr/bin/env python3
"""Lateral movement detection agent using Zeek logs and Windows event analysis."""

import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

try:
    import Evtx.Evtx as evtx
    HAS_EVTX = True
except ImportError:
    HAS_EVTX = False


LATERAL_MOVEMENT_EVENT_IDS = {
    "4624": "Successful Logon",
    "4625": "Failed Logon",
    "4648": "Logon with Explicit Credentials",
    "4672": "Special Privileges Assigned",
    "7045": "New Service Installed",
}

SUSPICIOUS_LOGON_TYPES = {"3": "Network", "10": "RemoteInteractive (RDP)"}


def parse_zeek_conn_log(log_path):
    """Parse Zeek conn.log for internal lateral movement patterns."""
    if not os.path.exists(log_path):
        return {"error": f"Zeek conn.log not found: {log_path}"}

    connections = defaultdict(lambda: {"count": 0, "ports": Counter(), "bytes": 0})
    with open(log_path, "r") as f:
        for line in f:
            if line.startswith("#"):
                continue
            fields = line.strip().split("\t")
            if len(fields) < 10:
                continue
            src_ip = fields[2] if len(fields) > 2 else ""
            dst_ip = fields[4] if len(fields) > 4 else ""
            dst_port = fields[5] if len(fields) > 5 else ""
            resp_bytes = int(fields[9]) if len(fields) > 9 and fields[9] != "-" else 0

            if src_ip.startswith(("10.", "172.16.", "192.168.")) and dst_ip.startswith(("10.", "172.16.", "192.168.")):
                key = f"{src_ip}->{dst_ip}"
                connections[key]["count"] += 1
                connections[key]["ports"][dst_port] += 1
                connections[key]["bytes"] += resp_bytes

    lateral_indicators = []
    for pair, info in connections.items():
        smb_count = info["ports"].get("445", 0) + info["ports"].get("139", 0)
        rdp_count = info["ports"].get("3389", 0)
        winrm_count = info["ports"].get("5985", 0) + info["ports"].get("5986", 0)
        psexec_count = info["ports"].get("445", 0)

        if smb_count > 0 or rdp_count > 0 or winrm_count > 0:
            src, dst = pair.split("->")
            lateral_indicators.append({
                "source": src, "destination": dst,
                "total_connections": info["count"],
                "smb_connections": smb_count,
                "rdp_connections": rdp_count,
                "winrm_connections": winrm_count,
                "total_bytes": info["bytes"],
                "risk": "HIGH" if smb_count > 10 or rdp_count > 5 else "MEDIUM",
            })

    lateral_indicators.sort(key=lambda x: x["total_connections"], reverse=True)
    return {"total_internal_pairs": len(connections), "lateral_indicators": lateral_indicators[:30]}


def parse_zeek_smb_log(log_path):
    """Parse Zeek smb_mapping.log for file share access patterns."""
    if not os.path.exists(log_path):
        return {"error": f"SMB log not found: {log_path}"}

    mappings = []
    with open(log_path, "r") as f:
        for line in f:
            if line.startswith("#"):
                continue
            fields = line.strip().split("\t")
            if len(fields) >= 6:
                mappings.append({
                    "timestamp": fields[0],
                    "source": fields[2] if len(fields) > 2 else "",
                    "destination": fields[4] if len(fields) > 4 else "",
                    "share": fields[5] if len(fields) > 5 else "",
                })

    share_counts = Counter(m.get("share", "") for m in mappings)
    src_counts = Counter(m.get("source", "") for m in mappings)

    return {
        "total_mappings": len(mappings),
        "top_shares": share_counts.most_common(10),
        "top_sources": src_counts.most_common(10),
        "recent": mappings[-20:],
    }


def analyze_windows_auth_logs(evtx_path):
    """Analyze Windows Security EVTX for lateral movement indicators."""
    if not HAS_EVTX:
        return {"error": "python-evtx not installed (pip install python-evtx)"}
    if not os.path.exists(evtx_path):
        return {"error": f"EVTX file not found: {evtx_path}"}

    network_logons = []
    failed_logons = []
    explicit_creds = []
    new_services = []

    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            try:
                xml = record.xml()
                for eid, desc in LATERAL_MOVEMENT_EVENT_IDS.items():
                    if f"<EventID>{eid}</EventID>" in xml:
                        entry = {
                            "event_id": eid,
                            "description": desc,
                            "timestamp": record.timestamp().isoformat(),
                        }
                        if eid == "4624":
                            logon_type_match = re.search(r"<Data Name='LogonType'>(\d+)</Data>", xml)
                            if logon_type_match and logon_type_match.group(1) in SUSPICIOUS_LOGON_TYPES:
                                entry["logon_type"] = logon_type_match.group(1)
                                network_logons.append(entry)
                        elif eid == "4625":
                            failed_logons.append(entry)
                        elif eid == "4648":
                            explicit_creds.append(entry)
                        elif eid == "7045":
                            new_services.append(entry)
                        break
            except Exception:
                continue

    return {
        "network_logons": len(network_logons),
        "failed_logons": len(failed_logons),
        "explicit_credential_use": len(explicit_creds),
        "new_services_installed": len(new_services),
        "recent_network_logons": network_logons[-20:],
        "recent_failures": failed_logons[-20:],
        "new_services": new_services[-10:],
    }


def detect_pass_the_hash_pattern(events):
    """Detect pass-the-hash indicators from auth events."""
    alerts = []
    by_source = defaultdict(list)
    for e in events:
        src = e.get("source", e.get("source_ip", ""))
        by_source[src].append(e)

    for src, src_events in by_source.items():
        unique_dests = set(e.get("destination", e.get("dest_ip", "")) for e in src_events)
        if len(unique_dests) > 5:
            alerts.append({
                "type": "PASS_THE_HASH_CANDIDATE",
                "severity": "HIGH",
                "source": src,
                "unique_destinations": len(unique_dests),
                "destinations": list(unique_dests)[:20],
                "event_count": len(src_events),
            })
    return alerts


def generate_report(zeek_log_dir=None, evtx_path=None):
    """Generate comprehensive lateral movement detection report."""
    report = {"timestamp": datetime.utcnow().isoformat() + "Z"}

    if zeek_log_dir:
        conn_log = os.path.join(zeek_log_dir, "conn.log")
        smb_log = os.path.join(zeek_log_dir, "smb_mapping.log")
        report["zeek_connections"] = parse_zeek_conn_log(conn_log)
        report["zeek_smb"] = parse_zeek_smb_log(smb_log)

    if evtx_path:
        report["windows_auth"] = analyze_windows_auth_logs(evtx_path)

    return report


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "help"
    if action == "zeek-conn" and len(sys.argv) > 2:
        print(json.dumps(parse_zeek_conn_log(sys.argv[2]), indent=2, default=str))
    elif action == "zeek-smb" and len(sys.argv) > 2:
        print(json.dumps(parse_zeek_smb_log(sys.argv[2]), indent=2, default=str))
    elif action == "windows" and len(sys.argv) > 2:
        print(json.dumps(analyze_windows_auth_logs(sys.argv[2]), indent=2, default=str))
    elif action == "report":
        zeek_dir = sys.argv[2] if len(sys.argv) > 2 else None
        evtx_file = sys.argv[3] if len(sys.argv) > 3 else None
        print(json.dumps(generate_report(zeek_dir, evtx_file), indent=2, default=str))
    else:
        print("Usage: agent.py [zeek-conn <conn.log>|zeek-smb <smb.log>|windows <Security.evtx>|report [zeek_dir] [evtx]]")
