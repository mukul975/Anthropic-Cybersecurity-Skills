#!/usr/bin/env python3
"""Mimikatz execution pattern detection agent.

Detects Mimikatz and related credential theft tools by analyzing process
creation logs, LSASS access patterns, and known command-line signatures.
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

MIMIKATZ_CMDLINE_PATTERNS = [
    (r"sekurlsa::logonpasswords", "CRITICAL", "Credential dump via sekurlsa"),
    (r"sekurlsa::wdigest", "CRITICAL", "WDigest credential extraction"),
    (r"sekurlsa::kerberos", "CRITICAL", "Kerberos ticket extraction"),
    (r"lsadump::dcsync", "CRITICAL", "DCSync attack"),
    (r"lsadump::sam", "CRITICAL", "SAM database dump"),
    (r"lsadump::lsa\s*/patch", "CRITICAL", "LSA secrets dump"),
    (r"kerberos::golden", "CRITICAL", "Golden Ticket creation"),
    (r"kerberos::ptt", "HIGH", "Pass-the-Ticket"),
    (r"privilege::debug", "HIGH", "Debug privilege escalation"),
    (r"token::elevate", "HIGH", "Token elevation"),
    (r"crypto::capi", "MEDIUM", "Certificate export"),
    (r"dpapi::chrome", "HIGH", "Chrome credential extraction"),
    (r"vault::cred", "HIGH", "Credential Vault access"),
    (r"misc::skeleton", "CRITICAL", "Skeleton Key injection"),
]

MIMIKATZ_BINARY_INDICATORS = [
    (r"mimikatz\.exe", "CRITICAL"),
    (r"mimi(32|64)\.exe", "CRITICAL"),
    (r"mimikittenz", "CRITICAL"),
    (r"sekurlsa\.dll", "CRITICAL"),
    (r"mimilib\.dll", "CRITICAL"),
    (r"mimidrv\.sys", "CRITICAL"),
    (r"kiwi_passwords", "CRITICAL"),
]

LSASS_DUMP_PATTERNS = [
    (r"rundll32.*comsvcs.*MiniDump", "CRITICAL", "LSASS minidump via comsvcs.dll"),
    (r"procdump.*-ma.*lsass", "HIGH", "LSASS dump via ProcDump"),
    (r"sqldumper.*lsass", "HIGH", "LSASS dump via SQLDumper"),
    (r"createdump.*lsass", "HIGH", "LSASS dump via .NET createdump"),
    (r"taskmgr.*lsass.*dump", "MEDIUM", "LSASS dump via Task Manager"),
    (r"Out-Minidump.*lsass", "CRITICAL", "PowerShell LSASS minidump"),
]


def scan_evtx(filepath):
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
            if event_id not in (1, 4688, 10):
                continue

            cmdline = re.search(r'<Data Name="CommandLine">([^<]+)', xml)
            image = re.search(r'<Data Name="Image">([^<]+)', xml)
            new_proc = re.search(r'<Data Name="NewProcessName">([^<]+)', xml)
            time_match = re.search(r'SystemTime="([^"]+)"', xml)
            user = re.search(r'<Data Name="User">([^<]+)', xml)

            cmd = cmdline.group(1) if cmdline else ""
            proc = image.group(1) if image else (new_proc.group(1) if new_proc else "")

            for pattern, severity in MIMIKATZ_BINARY_INDICATORS:
                if re.search(pattern, proc, re.IGNORECASE):
                    findings.append({
                        "event_id": event_id,
                        "timestamp": time_match.group(1) if time_match else "",
                        "type": "mimikatz_binary",
                        "process": proc,
                        "severity": severity,
                        "mitre": "T1003.001",
                    })

            for pattern, severity, desc in MIMIKATZ_CMDLINE_PATTERNS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    findings.append({
                        "event_id": event_id,
                        "timestamp": time_match.group(1) if time_match else "",
                        "type": "mimikatz_command",
                        "command": cmd[:300],
                        "description": desc,
                        "severity": severity,
                        "mitre": "T1003",
                    })

            for pattern, severity, desc in LSASS_DUMP_PATTERNS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    findings.append({
                        "event_id": event_id,
                        "timestamp": time_match.group(1) if time_match else "",
                        "type": "lsass_dump",
                        "command": cmd[:300],
                        "description": desc,
                        "severity": severity,
                        "mitre": "T1003.001",
                    })

    return findings


def scan_text_log(filepath):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for num, line in enumerate(f, 1):
            for pattern, severity, desc in MIMIKATZ_CMDLINE_PATTERNS + LSASS_DUMP_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "line": num, "severity": severity,
                        "description": desc, "excerpt": line.strip()[:200],
                    })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Mimikatz Execution Pattern Detector")
    parser.add_argument("--evtx-file", help="Sysmon or Security EVTX file")
    parser.add_argument("--text-log", help="Text log file to scan")
    args = parser.parse_args()

    results = {"timestamp": datetime.utcnow().isoformat() + "Z", "findings": []}

    if args.evtx_file:
        evtx_findings = scan_evtx(args.evtx_file)
        if isinstance(evtx_findings, dict):
            results.update(evtx_findings)
        else:
            results["findings"].extend(evtx_findings)

    if args.text_log:
        results["findings"].extend(scan_text_log(args.text_log))

    results["total_findings"] = len(results["findings"])
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
