#!/usr/bin/env python3
"""Defense evasion detection agent for endpoint logs.

Detects MITRE ATT&CK TA0005 evasion techniques including log clearing,
timestomping, process injection indicators, and security tool disabling
by analyzing Sysmon and Windows Security event logs.
"""

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

try:
    import Evtx.Evtx as evtx
except ImportError:
    evtx = None

EVASION_EVENT_IDS = {
    1102: {"name": "Audit Log Cleared", "severity": "CRITICAL", "mitre": "T1070.001"},
    4688: {"name": "Process Creation", "severity": "INFO", "mitre": "T1059"},
    4689: {"name": "Process Termination", "severity": "INFO", "mitre": ""},
}

SYSMON_EVASION_IDS = {
    1: "Process Create",
    2: "File creation time changed (Timestomping)",
    8: "CreateRemoteThread",
    10: "Process Access",
    12: "Registry Object Create/Delete",
    13: "Registry Value Set",
}

TIMESTOMP_INDICATORS = [
    r"SetFileTime", r"timestomp", r"\$STANDARD_INFORMATION",
    r"NtSetInformationFile", r"SetFileInformationByHandle",
]

LOG_CLEARING_COMMANDS = [
    r"wevtutil\s+(cl|clear-log)",
    r"Clear-EventLog",
    r"Remove-EventLog",
    r"del\s+.*\.evtx",
    r"wmic\s+nteventlog.*clear",
]

SECURITY_TOOL_DISABLE = [
    r"(Stop|Disable)-Service.*(Windows Defender|WinDefend|MsMpSvc)",
    r"Set-MpPreference\s+-DisableRealtimeMonitoring\s+\$true",
    r"sc\s+(stop|delete)\s+(WinDefend|MsMpSvc|Sense)",
    r"netsh\s+advfirewall\s+set\s+.*state\s+off",
    r"reg\s+add.*DisableAntiSpyware.*1",
    r"taskkill.*/im\s+(MsMpEng|avp|avgui|mbam)",
]

AMSI_BYPASS_PATTERNS = [
    r"amsi(Init|Scan)Buffer",
    r"AmsiUtils",
    r"amsiContext",
    r"[Ref].Assembly.GetType.*AMSI",
]


def analyze_evtx_for_evasion(filepath):
    if evtx is None:
        return {"error": "python-evtx not installed: pip install python-evtx"}
    findings = []
    with evtx.Evtx(filepath) as log:
        for record in log.records():
            xml = record.xml()
            event_id_match = re.search(r'<EventID[^>]*>(\d+)</EventID>', xml)
            if not event_id_match:
                continue
            event_id = int(event_id_match.group(1))
            time_match = re.search(r'SystemTime="([^"]+)"', xml)
            timestamp = time_match.group(1) if time_match else ""

            if event_id == 1102:
                findings.append({
                    "event_id": 1102, "timestamp": timestamp,
                    "severity": "CRITICAL", "mitre": "T1070.001",
                    "description": "Security audit log was cleared",
                })

            if event_id == 2:
                findings.append({
                    "event_id": 2, "timestamp": timestamp,
                    "severity": "HIGH", "mitre": "T1070.006",
                    "description": "File creation time modified (timestomping)",
                })

            if event_id == 8:
                source = re.search(r'<Data Name="SourceImage">([^<]+)', xml)
                target = re.search(r'<Data Name="TargetImage">([^<]+)', xml)
                findings.append({
                    "event_id": 8, "timestamp": timestamp,
                    "source": source.group(1) if source else "",
                    "target": target.group(1) if target else "",
                    "severity": "HIGH", "mitre": "T1055",
                    "description": "CreateRemoteThread detected (process injection)",
                })

            if event_id in (1, 4688):
                cmdline = re.search(r'<Data Name="CommandLine">([^<]+)', xml)
                if not cmdline:
                    cmdline = re.search(r'<Data Name="NewProcessName">([^<]+)', xml)
                if cmdline:
                    cmd = cmdline.group(1)
                    for pattern in LOG_CLEARING_COMMANDS:
                        if re.search(pattern, cmd, re.IGNORECASE):
                            findings.append({
                                "event_id": event_id, "timestamp": timestamp,
                                "command": cmd[:200], "severity": "CRITICAL",
                                "mitre": "T1070.001",
                                "description": "Log clearing command detected",
                            })
                    for pattern in SECURITY_TOOL_DISABLE:
                        if re.search(pattern, cmd, re.IGNORECASE):
                            findings.append({
                                "event_id": event_id, "timestamp": timestamp,
                                "command": cmd[:200], "severity": "CRITICAL",
                                "mitre": "T1562.001",
                                "description": "Security tool disabling detected",
                            })
                    for pattern in AMSI_BYPASS_PATTERNS:
                        if re.search(pattern, cmd, re.IGNORECASE):
                            findings.append({
                                "event_id": event_id, "timestamp": timestamp,
                                "command": cmd[:200], "severity": "HIGH",
                                "mitre": "T1562.001",
                                "description": "AMSI bypass attempt detected",
                            })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Defense Evasion Detector")
    parser.add_argument("--evtx-file", required=True, help="EVTX file (Sysmon or Security)")
    args = parser.parse_args()

    findings = analyze_evtx_for_evasion(args.evtx_file)
    if isinstance(findings, dict) and "error" in findings:
        results = findings
    else:
        results = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source_file": args.evtx_file,
            "findings": findings,
            "total_findings": len(findings),
            "by_severity": {},
        }
        for f in findings:
            sev = f.get("severity", "UNKNOWN")
            results["by_severity"][sev] = results["by_severity"].get(sev, 0) + 1

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
