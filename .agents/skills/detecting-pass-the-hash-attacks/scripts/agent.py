#!/usr/bin/env python3
"""Pass-the-Hash attack detection agent.

Detects NTLM hash reuse attacks by analyzing Windows Security Event ID 4624
for Type 3 NTLM logons with anomalous patterns across multiple targets.
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime

try:
    import Evtx.Evtx as evtx
except ImportError:
    evtx = None

LEGITIMATE_SOURCES = {"127.0.0.1", "::1", "-", ""}


def parse_logon_events(filepath):
    if evtx is None:
        return {"error": "python-evtx not installed: pip install python-evtx"}
    events = []
    with evtx.Evtx(filepath) as log:
        for record in log.records():
            xml = record.xml()
            if "<EventID>4624</EventID>" not in xml:
                continue
            logon_type = re.search(r'<Data Name="LogonType">(\d+)', xml)
            auth_pkg = re.search(r'<Data Name="AuthenticationPackageName">([^<]+)', xml)
            account = re.search(r'<Data Name="TargetUserName">([^<]+)', xml)
            domain = re.search(r'<Data Name="TargetDomainName">([^<]+)', xml)
            src_ip = re.search(r'<Data Name="IpAddress">([^<]+)', xml)
            computer = re.search(r'<Data Name="Computer">([^<]+)', xml)
            time_match = re.search(r'SystemTime="([^"]+)"', xml)
            lt = logon_type.group(1) if logon_type else ""
            ap = auth_pkg.group(1) if auth_pkg else ""
            if lt == "3" and "NTLM" in ap.upper():
                events.append({
                    "timestamp": time_match.group(1) if time_match else "",
                    "logon_type": int(lt), "auth_package": ap.strip(),
                    "account": account.group(1) if account else "",
                    "domain": domain.group(1) if domain else "",
                    "source_ip": src_ip.group(1) if src_ip else "",
                    "computer": computer.group(1) if computer else "",
                })
    return events


def detect_pth_patterns(events, target_threshold=3):
    if isinstance(events, dict) and "error" in events:
        return [events]
    findings = []
    src_targets = defaultdict(lambda: {"computers": set(), "count": 0,
                                        "source_ip": "", "account": ""})
    for evt in events:
        src = evt.get("source_ip", "")
        if src in LEGITIMATE_SOURCES:
            continue
        key = f"{src}|{evt.get('account', '')}"
        src_targets[key]["computers"].add(evt.get("computer", ""))
        src_targets[key]["count"] += 1
        src_targets[key]["source_ip"] = src
        src_targets[key]["account"] = evt.get("account", "")

    for key, data in src_targets.items():
        target_count = len(data["computers"])
        if target_count >= target_threshold:
            findings.append({
                "type": "ntlm_type3_multi_target",
                "source_ip": data["source_ip"],
                "account": data["account"],
                "target_count": target_count,
                "targets": list(data["computers"])[:20],
                "total_logons": data["count"],
                "severity": "CRITICAL" if target_count >= 10 else "HIGH",
                "mitre": "T1550.002",
            })

    admin_sources = defaultdict(int)
    for evt in events:
        if evt.get("account", "").lower() in ("administrator", "admin"):
            admin_sources[evt.get("source_ip", "")] += 1
    for src, count in admin_sources.items():
        if count >= 2 and src not in LEGITIMATE_SOURCES:
            findings.append({
                "type": "admin_ntlm", "source_ip": src,
                "logon_count": count, "severity": "HIGH", "mitre": "T1550.002",
            })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Pass-the-Hash Detector")
    parser.add_argument("--security-log", required=True, help="Windows Security EVTX")
    parser.add_argument("--target-threshold", type=int, default=3)
    args = parser.parse_args()
    events = parse_logon_events(args.security_log)
    findings = detect_pth_patterns(events, args.target_threshold)
    ntlm_count = len(events) if isinstance(events, list) else 0
    results = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_ntlm_type3_logons": ntlm_count,
        "findings": findings, "total_findings": len(findings),
    }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
