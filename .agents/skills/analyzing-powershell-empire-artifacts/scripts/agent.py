#!/usr/bin/env python3
"""Detect PowerShell Empire framework artifacts in Windows event logs."""

import argparse
import base64
import json
import re
import subprocess
import sys
from datetime import datetime, timezone


EMPIRE_LAUNCHER_PATTERN = re.compile(
    r"powershell\s+-noP\s+-sta\s+-w\s+1\s+-enc\s+", re.IGNORECASE
)

EMPIRE_STAGER_PATTERNS = [
    re.compile(r"System\.Net\.WebClient", re.IGNORECASE),
    re.compile(r"\.DownloadString\(", re.IGNORECASE),
    re.compile(r"\.DownloadData\(", re.IGNORECASE),
    re.compile(r"FromBase64String", re.IGNORECASE),
    re.compile(r"IEX\s*\(", re.IGNORECASE),
    re.compile(r"Invoke-Expression", re.IGNORECASE),
    re.compile(r"New-Object\s+System\.Net\.WebClient", re.IGNORECASE),
    re.compile(r"\[System\.Convert\]::FromBase64String", re.IGNORECASE),
]

EMPIRE_MODULE_SIGNATURES = [
    "Invoke-Mimikatz",
    "Invoke-Kerberoast",
    "Invoke-TokenManipulation",
    "Invoke-PSInject",
    "Invoke-DCOM",
    "Invoke-RunAs",
    "Invoke-PSRemoting",
    "Invoke-SessionGopher",
    "Invoke-ReflectivePEInjection",
    "Install-SSP",
    "New-GPOImmediateTask",
    "Get-Keystrokes",
    "Get-Screenshot",
    "Get-ClipboardContents",
    "Invoke-Portscan",
    "Invoke-SMBExec",
    "Invoke-WMIExec",
]

EMPIRE_DEFAULT_URIS = [
    "/login/process.php",
    "/admin/get.php",
    "/admin/news.php",
    "/news.php",
    "/login/process.jsp",
]

EMPIRE_DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
]


def query_event_log(event_id, log_name="Microsoft-Windows-PowerShell/Operational", max_events=1000):
    """Query Windows Event Log for specific event ID using wevtutil."""
    cmd = [
        "wevtutil", "qe", log_name,
        "/q:*[System[(EventID={})]]".format(event_id),
        "/c:{}".format(max_events),
        "/f:xml", "/rd:true"
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return proc.stdout
    except FileNotFoundError:
        return ""
    except subprocess.TimeoutExpired:
        return ""


def parse_script_block_events(xml_data):
    """Parse Event ID 4104 Script Block Logging events from XML."""
    events = []
    if not xml_data:
        return events

    blocks = re.split(r"<Event\s+xmlns=", xml_data)
    for block in blocks[1:]:
        time_match = re.search(r"<TimeCreated\s+SystemTime='([^']+)'", block)
        computer_match = re.search(r"<Computer>([^<]+)</Computer>", block)
        script_match = re.search(r"<Data Name='ScriptBlockText'>([^<]+)</Data>", block)
        sid_match = re.search(r"<Security\s+UserID='([^']+)'", block)

        if script_match:
            events.append({
                "timestamp": time_match.group(1) if time_match else "",
                "computer": computer_match.group(1) if computer_match else "",
                "user_sid": sid_match.group(1) if sid_match else "",
                "script_block": script_match.group(1),
                "event_id": 4104
            })
    return events


def decode_base64_payload(encoded_string):
    """Attempt to decode Base64 encoded PowerShell payload."""
    try:
        decoded_bytes = base64.b64decode(encoded_string)
        decoded = decoded_bytes.decode("utf-16-le", errors="replace")
        return decoded
    except Exception:
        try:
            decoded_bytes = base64.b64decode(encoded_string)
            return decoded_bytes.decode("utf-8", errors="replace")
        except Exception:
            return None


def analyze_script_block(script_text):
    """Analyze a script block for Empire indicators."""
    findings = []

    # Check for default launcher pattern
    if EMPIRE_LAUNCHER_PATTERN.search(script_text):
        findings.append({
            "indicator": "empire_default_launcher",
            "severity": "Critical",
            "description": "Default Empire launcher pattern detected: 'powershell -noP -sta -w 1 -enc'",
            "mitre": "T1059.001"
        })
        # Try to extract and decode the Base64 payload
        b64_match = re.search(r"-enc\s+([A-Za-z0-9+/=]+)", script_text)
        if b64_match:
            decoded = decode_base64_payload(b64_match.group(1))
            if decoded:
                findings[-1]["decoded_payload_preview"] = decoded[:500]

    # Check for stager patterns
    matched_stagers = []
    for pattern in EMPIRE_STAGER_PATTERNS:
        if pattern.search(script_text):
            matched_stagers.append(pattern.pattern)
    if len(matched_stagers) >= 2:
        findings.append({
            "indicator": "empire_stager_patterns",
            "severity": "High",
            "description": f"Multiple Empire stager patterns detected: {', '.join(matched_stagers[:5])}",
            "matched_count": len(matched_stagers),
            "mitre": "T1059.001"
        })

    # Check for known Empire module signatures
    for module in EMPIRE_MODULE_SIGNATURES:
        if module.lower() in script_text.lower():
            findings.append({
                "indicator": "empire_module",
                "severity": "Critical",
                "module_name": module,
                "description": f"Empire post-exploitation module detected: {module}",
                "mitre": "T1059.001"
            })

    # Check for Empire default URIs
    for uri in EMPIRE_DEFAULT_URIS:
        if uri in script_text:
            findings.append({
                "indicator": "empire_staging_uri",
                "severity": "High",
                "uri": uri,
                "description": f"Default Empire staging URI detected: {uri}",
                "mitre": "T1071.001"
            })

    # Check for Empire user agents
    for ua in EMPIRE_DEFAULT_USER_AGENTS:
        if ua in script_text:
            findings.append({
                "indicator": "empire_default_useragent",
                "severity": "Medium",
                "user_agent": ua,
                "description": "Default Empire HTTP listener user agent detected",
                "mitre": "T1071.001"
            })

    # Check for encoded command patterns
    b64_blocks = re.findall(r"[A-Za-z0-9+/]{100,}={0,2}", script_text)
    for b64 in b64_blocks[:5]:
        decoded = decode_base64_payload(b64)
        if decoded and any(p.search(decoded) for p in EMPIRE_STAGER_PATTERNS):
            findings.append({
                "indicator": "encoded_empire_payload",
                "severity": "Critical",
                "description": "Base64 encoded payload contains Empire stager patterns",
                "decoded_preview": decoded[:300],
                "mitre": "T1027"
            })

    return findings


def scan_event_logs(max_events=1000):
    """Scan PowerShell event logs for Empire artifacts."""
    results = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "events_analyzed": 0,
        "suspicious_events": [],
        "summary": {
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0
        }
    }

    # Query Event ID 4104 (Script Block Logging)
    xml_data = query_event_log(4104, "Microsoft-Windows-PowerShell/Operational", max_events)
    events = parse_script_block_events(xml_data)
    results["events_analyzed"] = len(events)

    for event in events:
        findings = analyze_script_block(event["script_block"])
        if findings:
            results["suspicious_events"].append({
                "timestamp": event["timestamp"],
                "computer": event["computer"],
                "user_sid": event["user_sid"],
                "findings": findings,
                "script_preview": event["script_block"][:200]
            })
            for f in findings:
                results["summary"]["total_findings"] += 1
                sev = f.get("severity", "").lower()
                if sev in results["summary"]:
                    results["summary"][sev] += 1

    # Also check Event ID 4103 (Module Logging)
    xml_4103 = query_event_log(4103, "Microsoft-Windows-PowerShell/Operational", max_events)
    events_4103 = parse_script_block_events(xml_4103)
    for event in events_4103:
        for module in EMPIRE_MODULE_SIGNATURES:
            if module.lower() in event.get("script_block", "").lower():
                results["suspicious_events"].append({
                    "timestamp": event["timestamp"],
                    "computer": event["computer"],
                    "event_id": 4103,
                    "findings": [{
                        "indicator": "empire_module_in_module_log",
                        "severity": "Critical",
                        "module_name": module,
                        "mitre": "T1059.001"
                    }]
                })
                results["summary"]["total_findings"] += 1
                results["summary"]["critical"] += 1

    return results


def analyze_script_file(filepath):
    """Analyze a PowerShell script file or exported log for Empire artifacts."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    findings = analyze_script_block(content)
    return {
        "file": filepath,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "finding_count": len(findings)
    }


def main():
    parser = argparse.ArgumentParser(
        description="Detect PowerShell Empire artifacts in event logs and scripts"
    )
    subparsers = parser.add_subparsers(dest="command", help="Analysis mode")

    scan_parser = subparsers.add_parser("scan-logs", help="Scan Windows event logs for Empire IOCs")
    scan_parser.add_argument("--max-events", type=int, default=1000, help="Max events to query (default: 1000)")

    file_parser = subparsers.add_parser("analyze-file", help="Analyze a PowerShell script or log file")
    file_parser.add_argument("file", help="Path to script or log file")

    decode_parser = subparsers.add_parser("decode", help="Decode Base64 encoded PowerShell payload")
    decode_parser.add_argument("payload", help="Base64 encoded string")

    args = parser.parse_args()

    if args.command == "scan-logs":
        result = scan_event_logs(args.max_events)
    elif args.command == "analyze-file":
        result = analyze_script_file(args.file)
    elif args.command == "decode":
        decoded = decode_base64_payload(args.payload)
        result = {
            "encoded": args.payload[:100] + "..." if len(args.payload) > 100 else args.payload,
            "decoded": decoded,
            "empire_indicators": analyze_script_block(decoded) if decoded else []
        }
    else:
        parser.print_help()
        sys.exit(0)

    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
