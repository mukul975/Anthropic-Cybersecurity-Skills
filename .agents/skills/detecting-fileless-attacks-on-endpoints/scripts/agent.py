#!/usr/bin/env python3
"""Fileless attack detection agent for endpoint logs.

Detects in-memory attacks by analyzing PowerShell script block logs (Event 4104),
WMI persistence events, and reflective DLL injection indicators from Sysmon.
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

SUSPICIOUS_PS_PATTERNS = {
    r"Invoke-Expression|IEX\s*\(": ("T1059.001", "HIGH", "Dynamic code execution"),
    r"Invoke-Mimikatz|Invoke-Kerberoast": ("T1003", "CRITICAL", "Credential tool"),
    r"System\.Reflection\.Assembly.*Load": ("T1620", "HIGH", "Reflective assembly load"),
    r"Net\.WebClient.*Download(String|Data|File)": ("T1105", "HIGH", "Remote download"),
    r"FromBase64String|Convert.*Base64": ("T1140", "MEDIUM", "Base64 decode"),
    r"VirtualAlloc|VirtualProtect|CreateThread": ("T1055", "CRITICAL", "Memory injection APIs"),
    r"New-Object.*IO\.MemoryStream": ("T1620", "HIGH", "In-memory stream"),
    r"-enc\s|-encodedcommand\s": ("T1027", "HIGH", "Encoded PowerShell"),
    r"Invoke-Shellcode|Invoke-ReflectivePEInjection": ("T1055", "CRITICAL", "Injection framework"),
    r"Win32_Process.*Create|WMI.*Process": ("T1047", "HIGH", "WMI process creation"),
    r"Register-WMI|__EventFilter|__EventConsumer": ("T1546.003", "CRITICAL", "WMI persistence"),
    r"HKCU:\\.*\\Run|HKLM:\\.*\\Run": ("T1547.001", "HIGH", "Registry run key"),
    r"Add-MpPreference.*ExclusionPath": ("T1562.001", "HIGH", "Defender exclusion"),
}

WMI_PERSISTENCE_EVENTS = {
    19: "WMI EventFilter created",
    20: "WMI EventConsumer created",
    21: "WMI EventConsumerToFilter binding",
}


def parse_powershell_scriptblock(filepath):
    if evtx is None:
        return {"error": "python-evtx not installed: pip install python-evtx"}
    findings = []
    with evtx.Evtx(filepath) as log:
        for record in log.records():
            xml = record.xml()
            if "<EventID>4104</EventID>" not in xml:
                continue
            script_block = re.search(r'<Data Name="ScriptBlockText">([^<]+)', xml)
            if not script_block:
                continue
            script = script_block.group(1)
            time_match = re.search(r'SystemTime="([^"]+)"', xml)

            for pattern, (mitre, severity, desc) in SUSPICIOUS_PS_PATTERNS.items():
                if re.search(pattern, script, re.IGNORECASE):
                    findings.append({
                        "event_id": 4104,
                        "timestamp": time_match.group(1) if time_match else "",
                        "pattern": desc,
                        "mitre": mitre,
                        "severity": severity,
                        "script_excerpt": script[:300],
                    })
    return findings


def parse_sysmon_wmi_persistence(filepath):
    if evtx is None:
        return {"error": "python-evtx not installed"}
    findings = []
    with evtx.Evtx(filepath) as log:
        for record in log.records():
            xml = record.xml()
            event_id_match = re.search(r'<EventID[^>]*>(\d+)</EventID>', xml)
            if not event_id_match:
                continue
            event_id = int(event_id_match.group(1))
            if event_id not in WMI_PERSISTENCE_EVENTS:
                continue
            time_match = re.search(r'SystemTime="([^"]+)"', xml)
            name = re.search(r'<Data Name="Name">([^<]+)', xml)
            operation = re.search(r'<Data Name="Operation">([^<]+)', xml)
            consumer = re.search(r'<Data Name="Destination">([^<]+)', xml)
            user = re.search(r'<Data Name="User">([^<]+)', xml)

            findings.append({
                "event_id": event_id,
                "type": WMI_PERSISTENCE_EVENTS[event_id],
                "timestamp": time_match.group(1) if time_match else "",
                "name": name.group(1) if name else "",
                "operation": operation.group(1) if operation else "",
                "destination": consumer.group(1) if consumer else "",
                "user": user.group(1) if user else "",
                "severity": "CRITICAL",
                "mitre": "T1546.003",
            })
    return findings


def parse_sysmon_injection(filepath):
    if evtx is None:
        return {"error": "python-evtx not installed"}
    findings = []
    with evtx.Evtx(filepath) as log:
        for record in log.records():
            xml = record.xml()
            if "<EventID>8</EventID>" not in xml:
                continue
            source = re.search(r'<Data Name="SourceImage">([^<]+)', xml)
            target = re.search(r'<Data Name="TargetImage">([^<]+)', xml)
            time_match = re.search(r'SystemTime="([^"]+)"', xml)

            findings.append({
                "event_id": 8,
                "timestamp": time_match.group(1) if time_match else "",
                "source_image": source.group(1) if source else "",
                "target_image": target.group(1) if target else "",
                "severity": "HIGH",
                "mitre": "T1055",
                "description": "CreateRemoteThread - possible reflective injection",
            })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Fileless Attack Detector")
    parser.add_argument("--ps-log", help="PowerShell EVTX file (Event 4104)")
    parser.add_argument("--sysmon-log", help="Sysmon EVTX file")
    parser.add_argument("--check-wmi", action="store_true", help="Check WMI persistence")
    parser.add_argument("--check-injection", action="store_true", help="Check injection")
    args = parser.parse_args()

    results = {"timestamp": datetime.utcnow().isoformat() + "Z", "findings": []}

    if args.ps_log:
        ps = parse_powershell_scriptblock(args.ps_log)
        if isinstance(ps, dict) and "error" in ps:
            results["error"] = ps["error"]
        else:
            results["findings"].extend(ps)

    if args.sysmon_log and args.check_wmi:
        wmi = parse_sysmon_wmi_persistence(args.sysmon_log)
        if not isinstance(wmi, dict):
            results["findings"].extend(wmi)

    if args.sysmon_log and args.check_injection:
        inj = parse_sysmon_injection(args.sysmon_log)
        if not isinstance(inj, dict):
            results["findings"].extend(inj)

    results["total_findings"] = len(results["findings"])
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
