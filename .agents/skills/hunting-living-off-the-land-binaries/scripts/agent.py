#!/usr/bin/env python3
"""Agent for hunting Living Off The Land Binary (LOLBAS) abuse."""

import os
import json
import re
import argparse
from datetime import datetime
from xml.etree import ElementTree as ET

import requests
import Evtx.Evtx as evtx


LOLBAS_PATTERNS = {
    "certutil.exe": [
        r"certutil.*-urlcache.*-split.*-f",
        r"certutil.*-encode",
        r"certutil.*-decode",
    ],
    "mshta.exe": [
        r"mshta.*vbscript",
        r"mshta.*javascript",
        r"mshta.*http[s]?://",
    ],
    "regsvr32.exe": [
        r"regsvr32.*/s.*/n.*/u.*/i:",
        r"regsvr32.*scrobj\.dll",
    ],
    "rundll32.exe": [
        r"rundll32.*javascript:",
        r"rundll32.*vbscript:",
        r"rundll32.*shell32\.dll.*ShellExec_RunDLL",
    ],
    "wmic.exe": [
        r"wmic.*process.*call.*create",
        r"wmic.*/node:.*process",
        r"wmic.*os.*get.*/format:",
    ],
    "bitsadmin.exe": [
        r"bitsadmin.*/transfer",
        r"bitsadmin.*/create.*addfile",
    ],
    "cmstp.exe": [
        r"cmstp.*/s.*\.inf",
        r"cmstp.*/ni.*\.inf",
    ],
    "msiexec.exe": [
        r"msiexec.*/q.*http[s]?://",
        r"msiexec.*/y.*\.dll",
    ],
    "powershell.exe": [
        r"powershell.*-enc",
        r"powershell.*downloadstring",
        r"powershell.*iex.*new-object",
        r"powershell.*bypass",
    ],
    "cmd.exe": [
        r"cmd.*/c.*powershell",
        r"cmd.*/c.*certutil",
    ],
}


def fetch_lolbas_database():
    """Fetch the LOLBAS project database from GitHub."""
    url = "https://lolbas-project.github.io/api/lolbas.json"
    resp = requests.get(url, timeout=15)
    resp.raise_for_status()
    return resp.json()


def scan_evtx_for_lolbas(evtx_path, patterns=None):
    """Scan Windows Event Log for LOLBAS abuse patterns."""
    if patterns is None:
        patterns = LOLBAS_PATTERNS
    findings = []
    ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                root = ET.fromstring(xml_str)
                event_id_el = root.find(".//ns:EventID", ns)
                if event_id_el is None:
                    continue
                event_id = event_id_el.text
                if event_id not in ("1", "4688"):
                    continue
                cmd_line = ""
                image = ""
                for data in root.findall(".//ns:Data", ns):
                    name = data.get("Name", "")
                    if name == "CommandLine":
                        cmd_line = data.text or ""
                    elif name == "Image" or name == "NewProcessName":
                        image = data.text or ""
                if not cmd_line:
                    continue
                for binary, regex_list in patterns.items():
                    if binary.lower() in image.lower() or binary.lower() in cmd_line.lower():
                        for regex in regex_list:
                            if re.search(regex, cmd_line, re.IGNORECASE):
                                findings.append({
                                    "event_id": event_id,
                                    "binary": binary,
                                    "command_line": cmd_line,
                                    "image": image,
                                    "pattern": regex,
                                    "timestamp": str(record.timestamp()),
                                })
            except Exception:
                continue
    return findings


def scan_sysmon_log(evtx_path):
    """Scan Sysmon log specifically for process creation with LOLBAS."""
    return scan_evtx_for_lolbas(evtx_path)


def generate_sigma_rules(lolbas_db):
    """Generate Sigma detection rules from LOLBAS database entries."""
    rules = []
    for entry in lolbas_db[:20]:
        name = entry.get("Name", "unknown")
        commands = entry.get("Commands", [])
        for cmd in commands:
            command_str = cmd.get("Command", "")
            if not command_str:
                continue
            rule = {
                "title": f"LOLBAS - {name} Abuse",
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {
                        "Image|endswith": f"\\{name}",
                        "CommandLine|contains": command_str.split()[1:2],
                    },
                    "condition": "selection",
                },
                "level": "high",
            }
            rules.append(rule)
    return rules


def build_lolbas_summary(lolbas_db):
    """Build a summary of LOLBAS binaries by category."""
    summary = {}
    for entry in lolbas_db:
        for cmd in entry.get("Commands", []):
            category = cmd.get("Category", "Unknown")
            if category not in summary:
                summary[category] = []
            summary[category].append(entry["Name"])
    for cat in summary:
        summary[cat] = list(set(summary[cat]))
    return summary


def main():
    parser = argparse.ArgumentParser(description="LOLBAS Hunting Agent")
    parser.add_argument("--evtx", help="Path to Windows Event Log (.evtx)")
    parser.add_argument("--output", default="lolbas_report.json")
    parser.add_argument("--action", choices=[
        "scan_evtx", "fetch_db", "generate_sigma", "full_hunt"
    ], default="full_hunt")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.action in ("fetch_db", "generate_sigma", "full_hunt"):
        lolbas_db = fetch_lolbas_database()
        report["findings"]["lolbas_summary"] = build_lolbas_summary(lolbas_db)
        print(f"[+] LOLBAS database: {len(lolbas_db)} entries")

    if args.action in ("scan_evtx", "full_hunt") and args.evtx:
        findings = scan_evtx_for_lolbas(args.evtx)
        report["findings"]["evtx_detections"] = findings
        print(f"[+] LOLBAS detections in EVTX: {len(findings)}")

    if args.action in ("generate_sigma", "full_hunt"):
        rules = generate_sigma_rules(lolbas_db)
        report["findings"]["sigma_rules"] = rules
        print(f"[+] Sigma rules generated: {len(rules)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
