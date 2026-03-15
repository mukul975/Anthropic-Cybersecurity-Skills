#!/usr/bin/env python3
"""Process hollowing (T1055.012) detection agent.

Detects hollowed processes by analyzing Sysmon events for suspended process
creation, memory allocation in remote processes, and thread hijacking.
"""

import argparse
import json
import re
import sys
from datetime import datetime

try:
    import Evtx.Evtx as evtx
except ImportError:
    evtx = None

COMMONLY_HOLLOWED = {
    "svchost.exe", "explorer.exe", "notepad.exe", "calc.exe",
    "dllhost.exe", "regsvr32.exe", "RuntimeBroker.exe",
}

SUSPICIOUS_PARENT_CHILD = [
    ("cmd.exe", "svchost.exe"), ("powershell.exe", "svchost.exe"),
    ("wscript.exe", "svchost.exe"), ("mshta.exe", "svchost.exe"),
    ("winword.exe", "svchost.exe"), ("excel.exe", "svchost.exe"),
]


def detect_hollowing_sysmon(filepath):
    if evtx is None:
        return {"error": "python-evtx not installed: pip install python-evtx"}
    findings = []
    with evtx.Evtx(filepath) as log:
        for record in log.records():
            xml = record.xml()
            eid_match = re.search(r'<EventID[^>]*>(\d+)</EventID>', xml)
            if not eid_match:
                continue
            eid = int(eid_match.group(1))
            time_match = re.search(r'SystemTime="([^"]+)"', xml)
            ts = time_match.group(1) if time_match else ""

            if eid == 1:
                image = re.search(r'<Data Name="Image">([^<]+)', xml)
                parent = re.search(r'<Data Name="ParentImage">([^<]+)', xml)
                cmdline = re.search(r'<Data Name="CommandLine">([^<]+)', xml)
                if image and parent:
                    img = image.group(1).rsplit("\\", 1)[-1].lower()
                    par = parent.group(1).rsplit("\\", 1)[-1].lower()
                    for sp, sc in SUSPICIOUS_PARENT_CHILD:
                        if par == sp.lower() and img == sc.lower():
                            findings.append({
                                "event_id": 1, "timestamp": ts,
                                "type": "suspicious_parent_child",
                                "parent": parent.group(1), "image": image.group(1),
                                "cmdline": cmdline.group(1)[:200] if cmdline else "",
                                "severity": "HIGH", "mitre": "T1055.012",
                            })

            if eid == 8:
                source = re.search(r'<Data Name="SourceImage">([^<]+)', xml)
                target = re.search(r'<Data Name="TargetImage">([^<]+)', xml)
                if target:
                    tgt = target.group(1).rsplit("\\", 1)[-1].lower()
                    if tgt in COMMONLY_HOLLOWED:
                        findings.append({
                            "event_id": 8, "timestamp": ts,
                            "type": "remote_thread_hollowed_target",
                            "source": source.group(1) if source else "",
                            "target": target.group(1),
                            "severity": "CRITICAL", "mitre": "T1055.012",
                        })

            if eid == 10:
                source = re.search(r'<Data Name="SourceImage">([^<]+)', xml)
                target = re.search(r'<Data Name="TargetImage">([^<]+)', xml)
                access = re.search(r'<Data Name="GrantedAccess">([^<]+)', xml)
                if target and access:
                    tgt = target.group(1).rsplit("\\", 1)[-1].lower()
                    mask = access.group(1).lower()
                    if tgt in COMMONLY_HOLLOWED and mask in ("0x1fffff", "0x1f3fff"):
                        findings.append({
                            "event_id": 10, "timestamp": ts,
                            "type": "full_access_hollowed_target",
                            "source": source.group(1) if source else "",
                            "target": target.group(1), "access": mask,
                            "severity": "CRITICAL", "mitre": "T1055.012",
                        })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Process Hollowing Detector")
    parser.add_argument("--sysmon-log", required=True, help="Sysmon EVTX file")
    args = parser.parse_args()
    findings = detect_hollowing_sysmon(args.sysmon_log)
    if isinstance(findings, dict) and "error" in findings:
        results = findings
    else:
        results = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "findings": findings, "total_findings": len(findings),
        }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
