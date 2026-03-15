#!/usr/bin/env python3
"""Agent for hunting lateral movement via WMI.

Detects WMI-based lateral movement by parsing Windows Event ID
4688 and Sysmon Event 1 for WmiPrvSE.exe child process patterns,
suspicious command lines, and WMI event subscription persistence.
"""
# For authorized threat hunting and blue team use only

import argparse
import json
import os
import re
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    import Evtx.Evtx as evtx
except ImportError:
    evtx = None

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

WMI_PARENT_NAMES = {"wmiprvse.exe", "wmiprvse"}
SUSPICIOUS_CHILDREN = {"cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe",
                       "cscript.exe", "wscript.exe", "regsvr32.exe", "rundll32.exe"}
WMI_CMD_PATTERNS = [
    re.compile(r"cmd\.exe\s+/[qQ]\s+/[cC]", re.IGNORECASE),
    re.compile(r"\\\\127\.0\.0\.1\\admin\$\\__\d+", re.IGNORECASE),
    re.compile(r"wmic\s+.*process\s+call\s+create", re.IGNORECASE),
    re.compile(r"Win32_Process.*Create", re.IGNORECASE),
]
WMI_ACTIVITY_IDS = {"5857", "5860", "5861"}


def _parse_event(xml_str):
    """Extract event fields from EVTX XML record."""
    root = ET.fromstring(xml_str)
    sys_node = root.find(f"{NS}System")
    event_id = sys_node.find(f"{NS}EventID").text if sys_node is not None else None
    tc = sys_node.find(f"{NS}TimeCreated") if sys_node is not None else None
    timestamp = tc.get("SystemTime", "") if tc is not None else ""
    channel = ""
    ch_node = sys_node.find(f"{NS}Channel") if sys_node is not None else None
    if ch_node is not None:
        channel = ch_node.text or ""
    data = {}
    for d in root.iter(f"{NS}Data"):
        name = d.get("Name", "")
        data[name] = d.text or ""
    return event_id, timestamp, channel, data


class WMILateralMovementHunter:
    """Hunts for WMI-based lateral movement in Windows Event Logs."""

    def __init__(self, output_dir="./wmi_lateral_hunt"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []
        self.wmi_processes = []
        self.wmi_subscriptions = []

    def parse_evtx(self, evtx_path):
        """Parse EVTX file for WMI lateral movement indicators."""
        if evtx is None:
            raise RuntimeError("python-evtx required: pip install python-evtx")
        with evtx.Evtx(evtx_path) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                except Exception:
                    continue
                event_id, ts, channel, data = _parse_event(xml_str)
                if event_id == "4688":
                    self._check_4688(ts, data)
                elif event_id == "1" and "sysmon" in channel.lower():
                    self._check_sysmon1(ts, data)
                elif event_id in WMI_ACTIVITY_IDS:
                    self._check_wmi_activity(event_id, ts, data)

    def _check_4688(self, ts, data):
        """Check Security Event 4688 for WmiPrvSE child processes."""
        parent = data.get("ParentProcessName", "").lower()
        new_proc = data.get("NewProcessName", "").lower()
        cmdline = data.get("CommandLine", "")
        parent_base = Path(parent).name if parent else ""

        if parent_base in WMI_PARENT_NAMES:
            child_base = Path(new_proc).name if new_proc else ""
            entry = {
                "timestamp": ts,
                "source": "Event4688",
                "parent": parent,
                "child": new_proc,
                "command_line": cmdline[:500],
                "user": data.get("SubjectUserName", ""),
                "suspicious": child_base in SUSPICIOUS_CHILDREN,
            }
            self.wmi_processes.append(entry)
            severity = "high" if entry["suspicious"] else "medium"
            self.findings.append({
                "severity": severity,
                "type": "WMI Process Spawn",
                "detail": f"WmiPrvSE spawned {child_base}: {cmdline[:100]}",
                "mitre": "T1047",
            })

            for pattern in WMI_CMD_PATTERNS:
                if pattern.search(cmdline):
                    self.findings.append({
                        "severity": "critical",
                        "type": "WMI Lateral Movement Command",
                        "detail": f"Pattern match in: {cmdline[:150]}",
                        "mitre": "T1047",
                    })
                    break

    def _check_sysmon1(self, ts, data):
        """Check Sysmon Event ID 1 for WmiPrvSE child processes."""
        parent_image = data.get("ParentImage", "").lower()
        image = data.get("Image", "").lower()
        cmdline = data.get("CommandLine", "")
        parent_base = Path(parent_image).name if parent_image else ""

        if parent_base in WMI_PARENT_NAMES:
            child_base = Path(image).name if image else ""
            entry = {
                "timestamp": ts,
                "source": "Sysmon1",
                "parent_image": parent_image,
                "image": image,
                "command_line": cmdline[:500],
                "user": data.get("User", ""),
                "parent_guid": data.get("ParentProcessGuid", ""),
                "process_guid": data.get("ProcessGuid", ""),
                "suspicious": child_base in SUSPICIOUS_CHILDREN,
            }
            self.wmi_processes.append(entry)
            if entry["suspicious"]:
                self.findings.append({
                    "severity": "high",
                    "type": "Sysmon WMI Process Spawn",
                    "detail": f"WmiPrvSE -> {child_base} by {entry['user']}",
                    "mitre": "T1047",
                })

    def _check_wmi_activity(self, event_id, ts, data):
        """Check WMI-Activity/Operational events for persistence."""
        entry = {
            "timestamp": ts,
            "event_id": event_id,
            "operation": data.get("Operation", ""),
            "consumer": data.get("Consumer", data.get("CONSUMER", "")),
            "possible_cause": data.get("PossibleCause", ""),
        }
        self.wmi_subscriptions.append(entry)
        if event_id in ("5860", "5861"):
            self.findings.append({
                "severity": "high",
                "type": "WMI Event Subscription",
                "detail": f"Event consumer created/modified: {entry['consumer'][:100]}",
                "mitre": "T1546.003",
            })

    def generate_report(self, evtx_files):
        for path in evtx_files:
            self.parse_evtx(path)

        child_counts = Counter(
            Path(p["child"] if "child" in p else p.get("image", "")).name
            for p in self.wmi_processes
        )

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "evtx_files_parsed": [str(f) for f in evtx_files],
            "total_wmi_spawned_processes": len(self.wmi_processes),
            "wmi_child_process_counts": dict(child_counts),
            "wmi_processes": self.wmi_processes[:50],
            "wmi_event_subscriptions": self.wmi_subscriptions,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "wmi_lateral_movement_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    parser = argparse.ArgumentParser(
        description="Hunt for WMI-based lateral movement in Windows Event Logs"
    )
    parser.add_argument("evtx_files", nargs="+",
                        help="Path(s) to EVTX files (Security, Sysmon, WMI-Activity)")
    parser.add_argument("--output-dir", default="./wmi_lateral_hunt")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    hunter = WMILateralMovementHunter(output_dir=args.output_dir)
    hunter.generate_report(args.evtx_files)


if __name__ == "__main__":
    main()
