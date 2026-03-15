#!/usr/bin/env python3
"""Agent for detecting suspicious PowerShell execution patterns."""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone


SUSPICIOUS_CMDLETS = [
    "Invoke-Expression", "IEX", "Invoke-WebRequest", "Invoke-RestMethod",
    "Start-Process", "New-Object Net.WebClient", "DownloadString",
    "DownloadFile", "System.Reflection.Assembly", "FromBase64String",
    "Invoke-Mimikatz", "Invoke-Shellcode", "Invoke-DllInjection",
    "Invoke-ReflectivePEInjection", "Get-Keystrokes", "Get-GPPPassword",
    "Invoke-CredentialInjection", "Invoke-TokenManipulation",
    "Add-Exfiltration", "Get-TimedScreenshot",
]

OBFUSCATION_PATTERNS = [
    (r'\-[eE][nN][cC]\s', "Encoded command (-enc)"),
    (r'[Ff][Rr][Oo][Mm][Bb][Aa][Ss][Ee]64', "Base64 decoding"),
    (r'\$\{[^}]+\}', "Variable obfuscation ${...}"),
    (r"'[^']*'\s*\+\s*'[^']*'", "String concatenation obfuscation"),
    (r'\-[Ww]indow[Ss]tyle\s+[Hh]idden', "Hidden window execution"),
    (r'\-[Nn]o[Pp]rofile', "NoProfile flag"),
    (r'\-[Ee]xecution[Pp]olicy\s+[Bb]ypass', "Execution policy bypass"),
    (r'[Ss]et-[Mm]pPreference.*-[Dd]isable', "Defender bypass attempt"),
    (r'[Aa][Mm][Ss][Ii]', "AMSI reference"),
]


def parse_script_block_logs():
    """Parse PowerShell script block logging events (Event ID 4104)."""
    events = []
    if sys.platform != "win32":
        return events
    ps_cmd = (
        "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';"
        "Id=4104} -MaxEvents 200 | Select-Object TimeCreated,"
        "@{N='ScriptBlock';E={$_.Properties[2].Value}},"
        "@{N='Path';E={$_.Properties[4].Value}} | ConvertTo-Json -Depth 3"
    )
    try:
        result = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            text=True, errors="replace", timeout=30
        )
        data = json.loads(result) if result.strip() else []
        return data if isinstance(data, list) else [data]
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return []


def analyze_script_content(script_text):
    """Analyze a PowerShell script for suspicious patterns."""
    findings = []
    if not script_text:
        return findings

    for cmdlet in SUSPICIOUS_CMDLETS:
        if cmdlet.lower() in script_text.lower():
            findings.append({"type": "suspicious_cmdlet", "cmdlet": cmdlet})

    for pattern, desc in OBFUSCATION_PATTERNS:
        if re.search(pattern, script_text):
            findings.append({"type": "obfuscation", "pattern": desc})

    b64_match = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', script_text)
    for b64 in b64_match[:3]:
        try:
            import base64
            decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
            if any(c.lower() in decoded.lower() for c in SUSPICIOUS_CMDLETS[:10]):
                findings.append({"type": "encoded_payload", "preview": decoded[:100]})
        except Exception:
            pass

    return findings


def analyze_log_file(log_path):
    """Analyze a text file containing PowerShell commands."""
    findings = []
    try:
        with open(log_path, "r", errors="replace") as f:
            content = f.read()
        results = analyze_script_content(content)
        if results:
            findings.append({
                "file": log_path,
                "indicators": results,
                "indicator_count": len(results),
            })
    except FileNotFoundError:
        print(f"[!] File not found: {log_path}")
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Detect suspicious PowerShell execution patterns"
    )
    parser.add_argument("--event-logs", action="store_true",
                        help="Parse Windows PowerShell event logs")
    parser.add_argument("--script", help="Analyze a PowerShell script file")
    parser.add_argument("--log-dir", help="Directory of PS log files to scan")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    print("[*] Suspicious PowerShell Execution Detection Agent")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "findings": []}

    if args.event_logs:
        events = parse_script_block_logs()
        for evt in events:
            script = evt.get("ScriptBlock", "")
            indicators = analyze_script_content(script)
            if indicators:
                report["findings"].append({
                    "source": "event_log",
                    "time": evt.get("TimeCreated", ""),
                    "path": evt.get("Path", ""),
                    "indicators": indicators,
                    "preview": script[:200] if args.verbose else "",
                })
        print(f"[*] Analyzed {len(events)} script block events")

    if args.script:
        findings = analyze_log_file(args.script)
        report["findings"].extend(findings)

    if args.log_dir and os.path.isdir(args.log_dir):
        for root, _, files in os.walk(args.log_dir):
            for f in files:
                if f.lower().endswith((".ps1", ".psm1", ".psd1", ".log", ".txt")):
                    findings = analyze_log_file(os.path.join(root, f))
                    report["findings"].extend(findings)

    report["total_suspicious"] = len(report["findings"])
    report["risk_level"] = (
        "CRITICAL" if len(report["findings"]) >= 10
        else "HIGH" if len(report["findings"]) >= 5
        else "MEDIUM" if report["findings"]
        else "LOW"
    )
    print(f"[*] Suspicious findings: {len(report['findings'])}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
