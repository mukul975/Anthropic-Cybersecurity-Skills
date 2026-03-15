#!/usr/bin/env python3
"""Agent for performing lateral movement detection.

Analyzes Windows event logs and network flow data to detect
Pass-the-Hash, PsExec, WMI, RDP, and SMB-based lateral movement
mapped to MITRE ATT&CK TA0008 techniques.
"""

import json
import sys
import csv
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path


class LateralMovementDetector:
    """Detects lateral movement patterns from log data."""

    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.auth_events = []
        self.process_events = []
        self.network_flows = []

    def load_auth_events(self, csv_path):
        """Load Windows authentication events (4624, 4625, 4648, 4672)."""
        with open(csv_path, "r") as f:
            for row in csv.DictReader(f):
                self.auth_events.append(row)

    def load_process_events(self, csv_path):
        """Load Sysmon process creation events (EventCode 1)."""
        with open(csv_path, "r") as f:
            for row in csv.DictReader(f):
                self.process_events.append(row)

    def load_network_flows(self, csv_path):
        """Load network flow data (NetFlow/Zeek)."""
        with open(csv_path, "r") as f:
            for row in csv.DictReader(f):
                self.network_flows.append(row)

    def detect_pass_the_hash(self):
        """Detect Pass-the-Hash via NTLM Type 3 logons to multiple hosts."""
        ntlm_logons = defaultdict(lambda: {"targets": set(), "count": 0, "events": []})

        for event in self.auth_events:
            if (event.get("EventCode") == "4624" and
                event.get("Logon_Type") == "3" and
                event.get("AuthenticationPackageName", "").upper() == "NTLM"):
                user = event.get("TargetUserName", "")
                src = event.get("src_ip", event.get("IpAddress", ""))
                target = event.get("ComputerName", "")
                if user and not user.endswith("$") and user != "ANONYMOUS LOGON":
                    key = f"{src}|{user}"
                    ntlm_logons[key]["targets"].add(target)
                    ntlm_logons[key]["count"] += 1
                    ntlm_logons[key]["events"].append(event)

        findings = []
        for key, data in ntlm_logons.items():
            if len(data["targets"]) > 3:
                src_ip, user = key.split("|", 1)
                findings.append({
                    "technique": "T1550.002",
                    "name": "Pass-the-Hash",
                    "src_ip": src_ip,
                    "user": user,
                    "unique_targets": len(data["targets"]),
                    "total_logons": data["count"],
                    "targets": sorted(data["targets"]),
                })
        return findings

    def detect_psexec(self):
        """Detect PsExec execution via process creation and service events."""
        findings = []
        for event in self.process_events:
            image = event.get("Image", "").lower()
            parent = event.get("ParentImage", "").lower()
            if "psexec" in image or "psexesvc" in image or "psexesvc" in parent:
                findings.append({
                    "technique": "T1021.002",
                    "name": "PsExec Execution",
                    "computer": event.get("Computer", ""),
                    "user": event.get("User", ""),
                    "image": event.get("Image", ""),
                    "parent": event.get("ParentImage", ""),
                    "cmdline": event.get("CommandLine", ""),
                    "timestamp": event.get("timestamp", event.get("UtcTime", "")),
                })
        return findings

    def detect_wmi_execution(self):
        """Detect WMI remote execution via WmiPrvSE child processes."""
        findings = []
        for event in self.process_events:
            parent = event.get("ParentImage", "").lower()
            image = event.get("Image", "").lower()
            if "wmiprvse" in parent and ("cmd.exe" in image or "powershell" in image):
                findings.append({
                    "technique": "T1047",
                    "name": "WMI Remote Execution",
                    "computer": event.get("Computer", ""),
                    "user": event.get("User", ""),
                    "image": event.get("Image", ""),
                    "cmdline": event.get("CommandLine", ""),
                    "timestamp": event.get("timestamp", ""),
                })
        return findings

    def detect_rdp_lateral(self):
        """Detect RDP lateral movement via Logon_Type 10."""
        rdp_sessions = defaultdict(lambda: {"targets": set(), "count": 0})
        for event in self.auth_events:
            if event.get("EventCode") == "4624" and event.get("Logon_Type") == "10":
                src = event.get("src_ip", event.get("IpAddress", ""))
                user = event.get("TargetUserName", "")
                target = event.get("ComputerName", "")
                key = f"{src}|{user}"
                rdp_sessions[key]["targets"].add(target)
                rdp_sessions[key]["count"] += 1

        findings = []
        for key, data in rdp_sessions.items():
            if len(data["targets"]) > 2:
                src_ip, user = key.split("|", 1)
                findings.append({
                    "technique": "T1021.001",
                    "name": "RDP Lateral Movement",
                    "src_ip": src_ip,
                    "user": user,
                    "unique_targets": len(data["targets"]),
                    "targets": sorted(data["targets"]),
                })
        return findings

    def detect_smb_scanning(self):
        """Detect mass SMB connections indicating lateral movement."""
        smb_sources = defaultdict(lambda: {"targets": set(), "bytes": 0})
        for flow in self.network_flows:
            if flow.get("dest_port") == "445":
                src = flow.get("src_ip", "")
                dst = flow.get("dest_ip", "")
                smb_sources[src]["targets"].add(dst)
                smb_sources[src]["bytes"] += int(flow.get("bytes", 0))

        findings = []
        for src, data in smb_sources.items():
            if len(data["targets"]) > 10:
                findings.append({
                    "technique": "T1021.002",
                    "name": "SMB Mass Connection",
                    "src_ip": src,
                    "unique_targets": len(data["targets"]),
                    "total_bytes": data["bytes"],
                    "severity": "CRITICAL" if len(data["targets"]) > 50 else "HIGH",
                })
        return findings

    def build_movement_graph(self):
        """Build a source->destination graph of lateral movement."""
        edges = defaultdict(int)
        for event in self.auth_events:
            if event.get("EventCode") == "4624" and event.get("Logon_Type") in ("3", "10"):
                src = event.get("src_ip", event.get("IpAddress", ""))
                dst = event.get("ComputerName", "")
                user = event.get("TargetUserName", "")
                if src and dst:
                    edges[f"{src} -> {dst} ({user})"] += 1
        return dict(sorted(edges.items(), key=lambda x: x[1], reverse=True)[:50])

    def generate_report(self):
        """Run all detections and generate a comprehensive report."""
        report = {
            "report_date": datetime.utcnow().isoformat(),
            "detections": {
                "pass_the_hash": self.detect_pass_the_hash(),
                "psexec": self.detect_psexec(),
                "wmi_execution": self.detect_wmi_execution(),
                "rdp_lateral": self.detect_rdp_lateral(),
                "smb_scanning": self.detect_smb_scanning(),
            },
            "movement_graph": self.build_movement_graph(),
        }

        total_findings = sum(len(v) for v in report["detections"].values())
        report["summary"] = {
            "total_findings": total_findings,
            "techniques_detected": [k for k, v in report["detections"].items() if v],
        }

        report_path = self.output_dir / "lateral_movement_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=list)
        print(json.dumps(report, indent=2, default=list))
        return report


def main():
    if len(sys.argv) < 3:
        print("Usage: agent.py <auth_events_csv> <output_dir> [process_csv] [flows_csv]")
        sys.exit(1)

    auth_csv = sys.argv[1]
    output_dir = sys.argv[2]

    detector = LateralMovementDetector(output_dir)
    detector.load_auth_events(auth_csv)
    if len(sys.argv) > 3:
        detector.load_process_events(sys.argv[3])
    if len(sys.argv) > 4:
        detector.load_network_flows(sys.argv[4])
    detector.generate_report()


if __name__ == "__main__":
    main()
