#!/usr/bin/env python3
"""Agent for hunting LOLBin execution patterns in endpoint logs (Sysmon, EDR)."""

import json
import argparse
import re
import csv
from datetime import datetime
from pathlib import Path

LOLBIN_SIGNATURES = {
    "certutil.exe": {"mitre": "T1140", "patterns": [r"-urlcache", r"-decode", r"-encode", r"-split.*http"]},
    "mshta.exe": {"mitre": "T1218.005", "patterns": [r"vbscript:", r"javascript:", r"https?://"]},
    "regsvr32.exe": {"mitre": "T1218.010", "patterns": [r"/s\s+/n\s+/u\s+/i:", r"scrobj\.dll"]},
    "rundll32.exe": {"mitre": "T1218.011", "patterns": [r"javascript:", r"shell32.*ShellExec"]},
    "bitsadmin.exe": {"mitre": "T1197", "patterns": [r"/transfer", r"/download", r"https?://"]},
    "wmic.exe": {"mitre": "T1047", "patterns": [r"process\s+call\s+create", r"/node:"]},
    "msiexec.exe": {"mitre": "T1218.007", "patterns": [r"/q.*https?://", r"/q.*/i\s+"]},
    "cmstp.exe": {"mitre": "T1218.003", "patterns": [r"/ni\s+/s", r"\.inf"]},
    "forfiles.exe": {"mitre": "T1202", "patterns": [r"/c\s+cmd", r"/c\s+powershell"]},
    "pcalua.exe": {"mitre": "T1202", "patterns": [r"-a\s+.*\.exe", r"-a\s+.*\.dll"]},
    "csc.exe": {"mitre": "T1127", "patterns": [r"/out:.*\\temp\\", r"/out:.*\\appdata\\"]},
    "installutil.exe": {"mitre": "T1218.004", "patterns": [r"/logfile=", r"/U\s+"]},
    "msbuild.exe": {"mitre": "T1127.001", "patterns": [r"\.xml$", r"\.csproj$", r"\\temp\\"]},
    "powershell.exe": {"mitre": "T1059.001", "patterns": [
        r"-enc\s+", r"IEX", r"Invoke-Expression", r"DownloadString",
        r"Net\.WebClient", r"-w\s+hidden", r"-nop\s+",
    ]},
}


def scan_csv_logs(csv_file, process_col="Image", cmdline_col="CommandLine"):
    """Scan exported CSV endpoint logs for LOLBin execution."""
    findings = []
    with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row_num, row in enumerate(reader, 2):
            proc = row.get(process_col, "")
            cmdline = row.get(cmdline_col, "")
            proc_name = proc.split("\\")[-1].lower() if proc else ""
            if proc_name in LOLBIN_SIGNATURES:
                sig = LOLBIN_SIGNATURES[proc_name]
                for pattern in sig["patterns"]:
                    if re.search(pattern, cmdline, re.I):
                        findings.append({
                            "row": row_num,
                            "binary": proc_name,
                            "mitre": sig["mitre"],
                            "command_line": cmdline[:500],
                            "matched_pattern": pattern,
                            "user": row.get("User", row.get("user", "")),
                            "host": row.get("Computer", row.get("hostname", "")),
                            "timestamp": row.get("UtcTime", row.get("@timestamp", "")),
                        })
                        break
    severity_map = {"T1059.001": "high", "T1218.005": "high", "T1140": "medium"}
    for f_item in findings:
        f_item["severity"] = severity_map.get(f_item["mitre"], "medium")
    return {
        "file": str(csv_file),
        "total_findings": len(findings),
        "by_binary": _count_by(findings, "binary"),
        "by_mitre": _count_by(findings, "mitre"),
        "findings": findings[:500],
    }


def scan_evtx_sysmon(evtx_file):
    """Parse Sysmon EVTX for Event ID 1 matching LOLBin patterns."""
    try:
        import Evtx.Evtx as evtx_lib
    except ImportError:
        return {"error": "python-evtx not installed. Install: pip install python-evtx"}
    findings = []
    lolbin_set = set(LOLBIN_SIGNATURES.keys())
    with evtx_lib.Evtx(evtx_file) as log:
        for record in log.records():
            xml_str = record.xml()
            if "<EventID>1</EventID>" not in xml_str:
                continue
            xml_lower = xml_str.lower()
            for binary in lolbin_set:
                if binary in xml_lower:
                    sig = LOLBIN_SIGNATURES[binary]
                    for pattern in sig["patterns"]:
                        if re.search(pattern, xml_str, re.I):
                            findings.append({
                                "record_id": record.record_num(),
                                "binary": binary,
                                "mitre": sig["mitre"],
                                "pattern": pattern,
                                "xml_snippet": xml_str[:600],
                            })
                            break
                    break
    return {"file": evtx_file, "total_findings": len(findings), "findings": findings[:300]}


def _count_by(items, key):
    counts = {}
    for item in items:
        val = item.get(key, "unknown")
        counts[val] = counts.get(val, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))


def main():
    parser = argparse.ArgumentParser(description="Hunt for LOLBin execution in endpoint logs")
    sub = parser.add_subparsers(dest="command")
    c = sub.add_parser("csv", help="Scan CSV-exported endpoint logs")
    c.add_argument("--file", required=True, help="CSV log file path")
    c.add_argument("--process-col", default="Image", help="Column name for process path")
    c.add_argument("--cmdline-col", default="CommandLine", help="Column name for command line")
    e = sub.add_parser("evtx", help="Scan Sysmon EVTX log")
    e.add_argument("--file", required=True, help="EVTX file path")
    args = parser.parse_args()
    if args.command == "csv":
        result = scan_csv_logs(args.file, args.process_col, args.cmdline_col)
    elif args.command == "evtx":
        result = scan_evtx_sysmon(args.file)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
