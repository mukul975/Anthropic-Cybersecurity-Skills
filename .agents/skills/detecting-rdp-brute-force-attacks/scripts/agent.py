#!/usr/bin/env python3
"""Agent for detecting RDP brute force attacks from Windows Event Logs.

Parses EVTX files for Event ID 4625 (failed logon) and 4624
(successful logon) to identify brute force patterns, source IP
frequency, username spraying, and post-compromise indicators.
"""
# For authorized security monitoring and blue team use only

import argparse
import json
import os
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

try:
    import Evtx.Evtx as evtx
except ImportError:
    evtx = None

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
FAILURE_SUBSTATUS = {
    "0xc0000064": "user_does_not_exist",
    "0xc000006a": "wrong_password",
    "0xc0000072": "account_disabled",
    "0xc000006f": "logon_outside_hours",
    "0xc0000070": "workstation_restriction",
    "0xc0000071": "password_expired",
    "0xc0000234": "account_locked",
    "0xc0000193": "account_expired",
}
RDP_LOGON_TYPES = {"3", "10"}


def _extract_event_data(xml_str):
    """Extract structured fields from a single EVTX record XML."""
    root = ET.fromstring(xml_str)
    sys_node = root.find(f"{NS}System")
    event_id = sys_node.find(f"{NS}EventID").text if sys_node is not None else None
    time_created = None
    tc = sys_node.find(f"{NS}TimeCreated") if sys_node is not None else None
    if tc is not None:
        time_created = tc.get("SystemTime", "")

    data = {}
    for d in root.iter(f"{NS}Data"):
        name = d.get("Name", "")
        data[name] = d.text or ""
    return event_id, time_created, data


class RDPBruteForceDetector:
    """Detects RDP brute force attacks from Windows Security EVTX logs."""

    def __init__(self, evtx_path, threshold=10, time_window_minutes=15,
                 output_dir="./rdp_brute_force_report"):
        self.evtx_path = evtx_path
        self.threshold = threshold
        self.time_window = time_window_minutes
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.failed_logons = []
        self.successful_logons = []

    def parse_events(self):
        """Parse EVTX file and extract logon events."""
        if evtx is None:
            raise RuntimeError("python-evtx not installed: pip install python-evtx")
        with evtx.Evtx(self.evtx_path) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                except Exception:
                    continue
                event_id, ts, data = _extract_event_data(xml_str)
                logon_type = data.get("LogonType", "")
                if event_id == "4625" and logon_type in RDP_LOGON_TYPES:
                    self.failed_logons.append({
                        "timestamp": ts,
                        "source_ip": data.get("IpAddress", "-"),
                        "target_user": data.get("TargetUserName", ""),
                        "target_domain": data.get("TargetDomainName", ""),
                        "sub_status": data.get("SubStatus", "").lower(),
                        "logon_type": logon_type,
                    })
                elif event_id == "4624" and logon_type in RDP_LOGON_TYPES:
                    self.successful_logons.append({
                        "timestamp": ts,
                        "source_ip": data.get("IpAddress", "-"),
                        "target_user": data.get("TargetUserName", ""),
                        "logon_type": logon_type,
                    })

    def analyze(self):
        """Analyze parsed events for brute force patterns."""
        ip_counter = Counter(e["source_ip"] for e in self.failed_logons)
        user_counter = Counter(e["target_user"] for e in self.failed_logons)
        substatus_counter = Counter(
            FAILURE_SUBSTATUS.get(e["sub_status"], e["sub_status"])
            for e in self.failed_logons
        )

        brute_force_ips = {ip: cnt for ip, cnt in ip_counter.items()
                          if cnt >= self.threshold and ip != "-"}

        success_ips = {e["source_ip"] for e in self.successful_logons}
        compromised = []
        for ip in brute_force_ips:
            if ip in success_ips:
                user_list = [e["target_user"] for e in self.successful_logons
                             if e["source_ip"] == ip]
                compromised.append({"ip": ip, "users": list(set(user_list)),
                                    "failed_attempts": brute_force_ips[ip]})

        users_per_ip = defaultdict(set)
        for e in self.failed_logons:
            users_per_ip[e["source_ip"]].add(e["target_user"])
        spray_ips = {ip: len(users) for ip, users in users_per_ip.items()
                     if len(users) >= 5}

        return {
            "total_failed_logons": len(self.failed_logons),
            "total_successful_logons": len(self.successful_logons),
            "unique_source_ips": len(ip_counter),
            "top_attacking_ips": ip_counter.most_common(20),
            "targeted_users": user_counter.most_common(20),
            "failure_reasons": dict(substatus_counter),
            "brute_force_ips": brute_force_ips,
            "password_spray_ips": spray_ips,
            "potential_compromises": compromised,
        }

    def generate_report(self):
        """Parse events and generate full detection report."""
        self.parse_events()
        analysis = self.analyze()

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "evtx_file": str(self.evtx_path),
            "detection_threshold": self.threshold,
            **analysis,
        }
        out = self.output_dir / "rdp_brute_force_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    parser = argparse.ArgumentParser(
        description="Detect RDP brute force attacks from Windows Security EVTX logs"
    )
    parser.add_argument("evtx_file", help="Path to Security.evtx log file")
    parser.add_argument("--threshold", type=int, default=10,
                        help="Min failed logons per IP to flag as brute force (default: 10)")
    parser.add_argument("--output-dir", default="./rdp_brute_force_report",
                        help="Output directory for report")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    detector = RDPBruteForceDetector(args.evtx_file, args.threshold,
                                     output_dir=args.output_dir)
    detector.generate_report()


if __name__ == "__main__":
    main()
