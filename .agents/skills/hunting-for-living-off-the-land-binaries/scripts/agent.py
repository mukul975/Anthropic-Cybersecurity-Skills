#!/usr/bin/env python3
"""Agent for hunting Living-off-the-Land Binaries (LOLBins) execution patterns."""

import json
import argparse
import re
from datetime import datetime
from pathlib import Path

try:
    from elasticsearch import Elasticsearch
except ImportError:
    Elasticsearch = None

LOLBINS = {
    "certutil.exe": {
        "mitre": "T1140,T1105",
        "suspicious_args": [r"-urlcache", r"-split", r"-decode", r"-encode", r"-f\s+http"],
        "description": "Certificate utility abused for download and decode",
    },
    "mshta.exe": {
        "mitre": "T1218.005",
        "suspicious_args": [r"vbscript:", r"javascript:", r"http://", r"https://"],
        "description": "HTML Application host for script execution",
    },
    "regsvr32.exe": {
        "mitre": "T1218.010",
        "suspicious_args": [r"/s\s+/n\s+/u\s+/i:", r"scrobj\.dll", r"http://", r"https://"],
        "description": "COM registration abused for proxy execution",
    },
    "rundll32.exe": {
        "mitre": "T1218.011",
        "suspicious_args": [r"javascript:", r"shell32\.dll.*ShellExec_RunDLL", r"url\.dll.*FileProtocolHandler"],
        "description": "DLL loader abused for proxy execution",
    },
    "bitsadmin.exe": {
        "mitre": "T1197",
        "suspicious_args": [r"/transfer", r"/download", r"/create", r"http://", r"https://"],
        "description": "BITS service abused for file download",
    },
    "wmic.exe": {
        "mitre": "T1047",
        "suspicious_args": [r"process\s+call\s+create", r"/node:", r"os\s+get"],
        "description": "WMI command-line for remote execution",
    },
    "msiexec.exe": {
        "mitre": "T1218.007",
        "suspicious_args": [r"/q.*http://", r"/q.*https://", r"/q.*/i\s+"],
        "description": "MSI installer abused for code execution",
    },
    "cmstp.exe": {
        "mitre": "T1218.003",
        "suspicious_args": [r"/ni\s+/s\s+", r"\.inf"],
        "description": "Connection Manager Profile Installer bypass",
    },
    "wscript.exe": {
        "mitre": "T1059.005",
        "suspicious_args": [r"\.js$", r"\.vbs$", r"\.wsf$", r"//e:jscript", r"//e:vbscript"],
        "description": "Windows Script Host for script execution",
    },
    "cscript.exe": {
        "mitre": "T1059.005",
        "suspicious_args": [r"\.js$", r"\.vbs$", r"\.wsf$"],
        "description": "Console Script Host for script execution",
    },
    "powershell.exe": {
        "mitre": "T1059.001",
        "suspicious_args": [
            r"-enc\s+", r"-encodedcommand", r"-nop\s+", r"-noprofile",
            r"IEX\s*\(", r"Invoke-Expression", r"DownloadString",
            r"Net\.WebClient", r"bitstransfer", r"-w\s+hidden",
        ],
        "description": "PowerShell with obfuscation or download cradles",
    },
    "forfiles.exe": {
        "mitre": "T1202",
        "suspicious_args": [r"/p\s+.*\s+/c\s+", r"cmd\s+/c"],
        "description": "Indirect command execution via forfiles",
    },
}


def hunt_lolbins_elastic(es_host, es_index, api_key=None, hours=24):
    """Query Elasticsearch for LOLBin execution with suspicious arguments."""
    if Elasticsearch is None:
        return {"error": "elasticsearch-py not installed"}
    kwargs = {"hosts": [es_host]}
    if api_key:
        kwargs["api_key"] = api_key
    es = Elasticsearch(**kwargs)
    results = {"timestamp": datetime.utcnow().isoformat(), "detections": [], "total_suspicious": 0}
    for binary, info in LOLBINS.items():
        query = {"bool": {"must": [
            {"term": {"process.name": binary}},
            {"range": {"@timestamp": {"gte": f"now-{hours}h"}}}
        ]}}
        resp = es.search(index=es_index, body={"query": query, "size": 200, "sort": [{"@timestamp": "desc"}]})
        suspicious = []
        for hit in resp["hits"]["hits"]:
            src = hit["_source"]
            cmdline = src.get("process", {}).get("command_line", "")
            for pattern in info["suspicious_args"]:
                if re.search(pattern, cmdline, re.I):
                    suspicious.append({
                        "timestamp": src.get("@timestamp"),
                        "host": src.get("host", {}).get("name"),
                        "user": src.get("user", {}).get("name"),
                        "command_line": cmdline[:500],
                        "parent_process": src.get("process", {}).get("parent", {}).get("name"),
                        "matched_pattern": pattern,
                    })
                    break
        if suspicious:
            results["detections"].append({
                "binary": binary, "mitre": info["mitre"],
                "description": info["description"],
                "count": len(suspicious), "events": suspicious[:50],
            })
            results["total_suspicious"] += len(suspicious)
    return results


def scan_sysmon_log(evtx_file):
    """Parse Sysmon EVTX for LOLBin process creation (Event ID 1)."""
    try:
        import Evtx.Evtx as evtx_lib
        import Evtx.Views as evtx_views
    except ImportError:
        return {"error": "python-evtx not installed"}
    findings = []
    lolbin_names = {b.lower() for b in LOLBINS}
    with evtx_lib.Evtx(evtx_file) as log:
        for record in log.records():
            xml = record.xml()
            if "<EventID>1</EventID>" not in xml:
                continue
            for binary in lolbin_names:
                if binary in xml.lower():
                    findings.append({"record_id": record.record_num(), "xml_snippet": xml[:800]})
                    break
    return {"file": evtx_file, "lolbin_events": len(findings), "findings": findings[:200]}


def main():
    parser = argparse.ArgumentParser(description="Hunt for LOLBin execution patterns")
    sub = parser.add_subparsers(dest="command")
    h = sub.add_parser("hunt", help="Hunt LOLBins in Elasticsearch")
    h.add_argument("--es-host", required=True)
    h.add_argument("--index", default="logs-*")
    h.add_argument("--api-key")
    h.add_argument("--hours", type=int, default=24)
    s = sub.add_parser("sysmon", help="Scan Sysmon EVTX for LOLBins")
    s.add_argument("--evtx-file", required=True)
    args = parser.parse_args()
    if args.command == "hunt":
        result = hunt_lolbins_elastic(args.es_host, args.index, args.api_key, args.hours)
    elif args.command == "sysmon":
        result = scan_sysmon_log(args.evtx_file)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
