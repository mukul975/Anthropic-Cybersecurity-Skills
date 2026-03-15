#!/usr/bin/env python3
"""Privilege escalation detection agent for Windows and Linux endpoints.

Detects token manipulation, UAC bypass, sudo abuse, kernel exploits, and
unquoted service paths by analyzing process creation and security logs.
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

WINDOWS_PRIVESC_PATTERNS = [
    (r"eventvwr\.exe|fodhelper\.exe|computerdefaults\.exe", "T1548.002", "CRITICAL", "UAC Bypass"),
    (r"whoami\s+/priv", "T1033", "MEDIUM", "Privilege enumeration"),
    (r"sc\s+(config|create).*binpath", "T1543.003", "HIGH", "Service binary modification"),
    (r"potato.*exploit|juicypotato|sweetpotato|godpotato", "T1134.001", "CRITICAL", "Token impersonation exploit"),
    (r"printspoofer|efspotato", "T1134.001", "CRITICAL", "Named pipe impersonation"),
    (r"schtasks.*\/ru.*system", "T1053.005", "HIGH", "Scheduled task as SYSTEM"),
    (r"reg\s+add.*ImagePath", "T1574.011", "HIGH", "Service registry modification"),
]

LINUX_PRIVESC_PATTERNS = [
    (r"sudo\s+-l|sudo\s+--list", "T1548.003", "MEDIUM", "Sudo enumeration"),
    (r"find.*-perm.*4000|find.*-perm.*/u=s", "T1548.001", "MEDIUM", "SUID binary search"),
    (r"chmod\s+[u+]?s|chmod\s+4\d{3}", "T1548.001", "HIGH", "SUID bit set"),
    (r"linpeas|linenum|linux-exploit-suggester", "T1046", "HIGH", "Privesc enumeration tool"),
    (r"pkexec|CVE-2021-4034|pwnkit", "T1068", "CRITICAL", "Kernel exploit"),
    (r"dirty.*pipe|CVE-2022-0847", "T1068", "CRITICAL", "Kernel exploit"),
]


def analyze_evtx(filepath):
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
            if event_id not in (1, 4688, 4672):
                continue
            cmdline = re.search(r'<Data Name="CommandLine">([^<]+)', xml)
            image = re.search(r'<Data Name="Image">([^<]+)', xml)
            time_match = re.search(r'SystemTime="([^"]+)"', xml)
            cmd = cmdline.group(1) if cmdline else ""
            proc = image.group(1) if image else ""
            text = f"{cmd} {proc}"
            for pattern, mitre, severity, desc in WINDOWS_PRIVESC_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    findings.append({
                        "event_id": event_id,
                        "timestamp": time_match.group(1) if time_match else "",
                        "command": cmd[:200], "technique": desc,
                        "mitre": mitre, "severity": severity,
                    })
            if event_id == 4672:
                privs = re.search(r'<Data Name="PrivilegeList">([^<]+)', xml)
                if privs and "SeDebugPrivilege" in privs.group(1):
                    findings.append({
                        "event_id": 4672,
                        "timestamp": time_match.group(1) if time_match else "",
                        "technique": "SeDebugPrivilege assigned",
                        "mitre": "T1134", "severity": "HIGH",
                    })
    return findings


def analyze_text_log(filepath):
    findings = []
    all_patterns = WINDOWS_PRIVESC_PATTERNS + LINUX_PRIVESC_PATTERNS
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for num, line in enumerate(f, 1):
            for pattern, mitre, severity, desc in all_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "line": num, "technique": desc,
                        "mitre": mitre, "severity": severity,
                        "excerpt": line.strip()[:200],
                    })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Privilege Escalation Detector")
    parser.add_argument("--evtx-file", help="Sysmon or Security EVTX file")
    parser.add_argument("--text-log", help="Text log to scan")
    args = parser.parse_args()
    results = {"timestamp": datetime.utcnow().isoformat() + "Z", "findings": []}
    if args.evtx_file:
        r = analyze_evtx(args.evtx_file)
        if isinstance(r, dict):
            results.update(r)
        else:
            results["findings"].extend(r)
    if args.text_log:
        results["findings"].extend(analyze_text_log(args.text_log))
    results["total_findings"] = len(results["findings"])
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
