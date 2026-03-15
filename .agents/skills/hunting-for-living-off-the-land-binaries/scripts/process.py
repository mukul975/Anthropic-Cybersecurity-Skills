#!/usr/bin/env python3
"""
LOLBin Threat Hunt Automation Script
Queries Windows Event Logs and Sysmon for suspicious LOLBin activity.
Supports Splunk API, Elastic API, and local Windows Event Log parsing.
"""

import json
import csv
import argparse
import datetime
import re
import sys
from collections import defaultdict
from pathlib import Path

try:
    import xml.etree.ElementTree as ET
except ImportError:
    pass

# Known LOLBins and their suspicious argument patterns
LOLBIN_SIGNATURES = {
    "certutil.exe": {
        "attack_id": "T1140",
        "suspicious_args": [
            r"-urlcache\s+-split\s+-f",
            r"-encode",
            r"-decode",
            r"-verifyctl",
            r"http[s]?://",
        ],
        "description": "Certificate utility abused for download/encode",
    },
    "mshta.exe": {
        "attack_id": "T1218.005",
        "suspicious_args": [
            r"javascript:",
            r"vbscript:",
            r"http[s]?://",
            r"\.hta",
        ],
        "description": "HTML Application host for script execution",
    },
    "rundll32.exe": {
        "attack_id": "T1218.011",
        "suspicious_args": [
            r"javascript:",
            r"shell32\.dll.*ShellExec_RunDLL",
            r"url\.dll.*FileProtocolHandler",
            r"advpack\.dll.*RegisterOCX",
            r"pcwutl\.dll.*LaunchApplication",
        ],
        "description": "DLL loader abused for proxy execution",
    },
    "regsvr32.exe": {
        "attack_id": "T1218.010",
        "suspicious_args": [
            r"/s\s+/n\s+/u\s+/i:",
            r"scrobj\.dll",
            r"http[s]?://",
        ],
        "description": "COM registration utility for Squiblydoo attacks",
    },
    "msiexec.exe": {
        "attack_id": "T1218.007",
        "suspicious_args": [
            r"/q.*http[s]?://",
            r"/quiet.*http[s]?://",
            r"/i\s+http[s]?://",
        ],
        "description": "Windows Installer abused for remote MSI execution",
    },
    "bitsadmin.exe": {
        "attack_id": "T1197",
        "suspicious_args": [
            r"/transfer",
            r"/create.*http[s]?://",
            r"/addfile.*http[s]?://",
            r"/SetNotifyCmdLine",
        ],
        "description": "BITS service abused for download and persistence",
    },
    "cmstp.exe": {
        "attack_id": "T1218.003",
        "suspicious_args": [
            r"/s\s+/ns",
            r"\.inf",
            r"/au",
        ],
        "description": "Connection Manager for UAC bypass and execution",
    },
    "wmic.exe": {
        "attack_id": "T1047",
        "suspicious_args": [
            r"process\s+call\s+create",
            r"/node:",
            r"os\s+get",
            r"format:",
            r"http[s]?://",
        ],
        "description": "WMI command-line for remote execution",
    },
    "msbuild.exe": {
        "attack_id": "T1127.001",
        "suspicious_args": [
            r"\.xml",
            r"\.csproj",
            r"\.proj",
            r"inline.*task",
        ],
        "description": "Build tool abused for inline task execution",
    },
    "installutil.exe": {
        "attack_id": "T1218.004",
        "suspicious_args": [
            r"/logfile=",
            r"/LogToConsole=false",
            r"/U",
        ],
        "description": ".NET utility for managed code execution",
    },
    "forfiles.exe": {
        "attack_id": "T1202",
        "suspicious_args": [
            r"/c\s+cmd",
            r"/c\s+powershell",
            r"/p\s+c:\\windows",
        ],
        "description": "Indirect command execution utility",
    },
    "pcalua.exe": {
        "attack_id": "T1202",
        "suspicious_args": [
            r"-a\s+.*\.exe",
            r"-a\s+.*\.dll",
        ],
        "description": "Program Compatibility Assistant for proxy execution",
    },
}

# Suspicious parent processes for LOLBins
SUSPICIOUS_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "wmiprvse.exe", "w3wp.exe", "php-cgi.exe", "httpd.exe",
    "nginx.exe", "tomcat.exe", "sqlservr.exe", "python.exe",
    "wscript.exe", "cscript.exe",
}


def parse_sysmon_xml(xml_path: str) -> list[dict]:
    """Parse exported Sysmon Event ID 1 (Process Creation) XML logs."""
    events = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

        for event in root.findall(".//ns:Event", ns):
            event_data = {}
            for data in event.findall(".//ns:Data", ns):
                name = data.get("Name", "")
                event_data[name] = data.text or ""
            if event_data.get("Image"):
                events.append(event_data)
    except ET.ParseError as e:
        print(f"[ERROR] Failed to parse XML: {e}")
    except FileNotFoundError:
        print(f"[ERROR] File not found: {xml_path}")
    return events


def parse_csv_logs(csv_path: str) -> list[dict]:
    """Parse CSV-exported process creation logs."""
    events = []
    try:
        with open(csv_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                events.append(dict(row))
    except FileNotFoundError:
        print(f"[ERROR] File not found: {csv_path}")
    return events


def parse_json_logs(json_path: str) -> list[dict]:
    """Parse JSON-exported process creation logs."""
    events = []
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                events = data
            elif isinstance(data, dict) and "events" in data:
                events = data["events"]
            elif isinstance(data, dict) and "hits" in data:
                events = [h.get("_source", h) for h in data["hits"].get("hits", [])]
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[ERROR] Failed to parse JSON: {e}")
    return events


def normalize_event(event: dict) -> dict:
    """Normalize event fields across different log formats."""
    normalized = {}
    field_mappings = {
        "image": ["Image", "image", "process_name", "FileName", "process.executable"],
        "command_line": ["CommandLine", "command_line", "ProcessCommandLine", "process.command_line", "cmdline"],
        "parent_image": ["ParentImage", "parent_image", "InitiatingProcessFileName", "process.parent.executable"],
        "user": ["User", "user", "AccountName", "user.name", "SubjectUserName"],
        "timestamp": ["UtcTime", "timestamp", "Timestamp", "@timestamp", "TimeCreated"],
        "hostname": ["Computer", "hostname", "DeviceName", "host.name", "ComputerName"],
        "pid": ["ProcessId", "pid", "process_id", "process.pid"],
        "parent_pid": ["ParentProcessId", "parent_pid", "ppid", "process.parent.pid"],
    }
    for target_field, source_fields in field_mappings.items():
        for src in source_fields:
            if src in event and event[src]:
                normalized[target_field] = str(event[src])
                break
        if target_field not in normalized:
            normalized[target_field] = ""
    return normalized


def analyze_lolbin_event(event: dict) -> dict | None:
    """Analyze a single process event for LOLBin abuse indicators."""
    image = event.get("image", "").lower()
    command_line = event.get("command_line", "")
    parent_image = event.get("parent_image", "").lower()

    binary_name = image.split("\\")[-1].split("/")[-1] if image else ""

    if binary_name not in LOLBIN_SIGNATURES:
        return None

    sig = LOLBIN_SIGNATURES[binary_name]
    finding = {
        "binary": binary_name,
        "attack_id": sig["attack_id"],
        "description": sig["description"],
        "command_line": command_line,
        "parent_process": parent_image.split("\\")[-1].split("/")[-1] if parent_image else "unknown",
        "user": event.get("user", "unknown"),
        "hostname": event.get("hostname", "unknown"),
        "timestamp": event.get("timestamp", "unknown"),
        "risk_score": 0,
        "indicators": [],
    }

    # Check for suspicious command-line arguments
    for pattern in sig["suspicious_args"]:
        if re.search(pattern, command_line, re.IGNORECASE):
            finding["risk_score"] += 30
            finding["indicators"].append(f"Suspicious argument pattern: {pattern}")

    # Check for suspicious parent processes
    parent_name = finding["parent_process"]
    if parent_name in SUSPICIOUS_PARENTS:
        finding["risk_score"] += 25
        finding["indicators"].append(f"Suspicious parent process: {parent_name}")

    # Check for network-related indicators in command line
    if re.search(r"http[s]?://", command_line, re.IGNORECASE):
        finding["risk_score"] += 20
        finding["indicators"].append("Contains URL - possible download/C2")

    # Check for encoded content
    if re.search(r"(base64|encode|decode|-enc\s)", command_line, re.IGNORECASE):
        finding["risk_score"] += 15
        finding["indicators"].append("Contains encoding/decoding operation")

    # Check for execution from unusual paths
    unusual_paths = [r"\\temp\\", r"\\tmp\\", r"\\appdata\\", r"\\programdata\\", r"\\public\\", r"\\downloads\\"]
    for path_pattern in unusual_paths:
        if re.search(path_pattern, command_line, re.IGNORECASE):
            finding["risk_score"] += 10
            finding["indicators"].append(f"References unusual path: {path_pattern}")

    # Only return if there are actual indicators
    if finding["indicators"]:
        finding["risk_level"] = (
            "CRITICAL" if finding["risk_score"] >= 60
            else "HIGH" if finding["risk_score"] >= 40
            else "MEDIUM" if finding["risk_score"] >= 20
            else "LOW"
        )
        return finding
    return None


def generate_splunk_queries() -> dict[str, str]:
    """Generate Splunk SPL queries for LOLBin hunting."""
    queries = {}

    # General LOLBin network activity
    queries["lolbin_network_activity"] = """index=sysmon EventCode=3
| where match(Image, "(?i)(certutil|mshta|rundll32|regsvr32|msiexec|bitsadmin|cmstp|wmic)\.exe$")
| stats count values(DestinationIp) as dest_ips values(DestinationPort) as dest_ports by Image Computer User
| where count > 0
| sort -count"""

    # Certutil download cradle
    queries["certutil_download"] = """index=sysmon EventCode=1 Image="*\\certutil.exe"
| where match(CommandLine, "(?i)(urlcache|split|decode|encode|http)")
| table _time Computer User Image CommandLine ParentImage"""

    # Regsvr32 Squiblydoo
    queries["regsvr32_squiblydoo"] = """index=sysmon EventCode=1 Image="*\\regsvr32.exe"
| where match(CommandLine, "(?i)(scrobj|/i:http|/s /n /u)")
| table _time Computer User CommandLine ParentImage"""

    # Mshta script execution
    queries["mshta_script_exec"] = """index=sysmon EventCode=1 Image="*\\mshta.exe"
| where match(CommandLine, "(?i)(javascript|vbscript|http)")
| table _time Computer User CommandLine ParentImage"""

    # LOLBin with suspicious parent
    queries["lolbin_suspicious_parent"] = """index=sysmon EventCode=1
| where match(Image, "(?i)(certutil|mshta|rundll32|regsvr32|bitsadmin)\.exe$")
| where match(ParentImage, "(?i)(winword|excel|powerpnt|outlook|wmiprvse|w3wp)\.exe$")
| table _time Computer User Image CommandLine ParentImage"""

    return queries


def generate_kql_queries() -> dict[str, str]:
    """Generate KQL queries for Microsoft Defender for Endpoint."""
    queries = {}

    queries["lolbin_suspicious_execution"] = """DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("certutil.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","cmstp.exe","msiexec.exe","wmic.exe")
| where ProcessCommandLine has_any ("http","ftp","urlcache","-decode","-encode","scrobj","javascript","vbscript","transfer","/i:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc"""

    queries["lolbin_network_connections"] = """DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("certutil.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe")
| where RemoteIPType == "Public"
| summarize ConnectionCount=count(), RemoteIPs=make_set(RemoteIP) by InitiatingProcessFileName, DeviceName
| order by ConnectionCount desc"""

    queries["lolbin_from_office"] = """DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| where FileName in~ ("certutil.exe","mshta.exe","rundll32.exe","regsvr32.exe","powershell.exe","cmd.exe","wscript.exe","cscript.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine"""

    return queries


def run_hunt(input_path: str, output_dir: str, log_format: str = "auto") -> None:
    """Execute the LOLBin threat hunt against provided log data."""
    print(f"[*] LOLBin Threat Hunt Starting - {datetime.datetime.now().isoformat()}")
    print(f"[*] Input: {input_path}")
    print(f"[*] Output: {output_dir}")

    # Parse input logs
    if log_format == "auto":
        if input_path.endswith(".xml"):
            log_format = "xml"
        elif input_path.endswith(".csv"):
            log_format = "csv"
        elif input_path.endswith(".json"):
            log_format = "json"
        else:
            print("[ERROR] Cannot determine log format. Use --format flag.")
            sys.exit(1)

    print(f"[*] Parsing {log_format} logs...")
    if log_format == "xml":
        raw_events = parse_sysmon_xml(input_path)
    elif log_format == "csv":
        raw_events = parse_csv_logs(input_path)
    elif log_format == "json":
        raw_events = parse_json_logs(input_path)
    else:
        print(f"[ERROR] Unsupported format: {log_format}")
        sys.exit(1)

    print(f"[*] Parsed {len(raw_events)} events")

    # Normalize and analyze
    findings = []
    stats = defaultdict(int)

    for raw_event in raw_events:
        event = normalize_event(raw_event)
        result = analyze_lolbin_event(event)
        if result:
            findings.append(result)
            stats[result["binary"]] += 1
            stats[result["risk_level"]] += 1

    print(f"[*] Analysis complete - {len(findings)} suspicious events found")

    # Output results
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Write findings JSON
    findings_file = output_path / "lolbin_findings.json"
    with open(findings_file, "w", encoding="utf-8") as f:
        json.dump({
            "hunt_id": f"TH-LOLBIN-{datetime.date.today().isoformat()}",
            "timestamp": datetime.datetime.now().isoformat(),
            "total_events_analyzed": len(raw_events),
            "total_findings": len(findings),
            "statistics": dict(stats),
            "findings": findings,
        }, f, indent=2)
    print(f"[+] Findings written to {findings_file}")

    # Write CSV summary
    csv_file = output_path / "lolbin_findings.csv"
    if findings:
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=findings[0].keys())
            writer.writeheader()
            for finding in findings:
                row = dict(finding)
                row["indicators"] = "; ".join(row["indicators"])
                writer.writerow(row)
        print(f"[+] CSV summary written to {csv_file}")

    # Write hunt report
    report_file = output_path / "hunt_report.md"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(f"# LOLBin Threat Hunt Report\n\n")
        f.write(f"**Hunt ID**: TH-LOLBIN-{datetime.date.today().isoformat()}\n")
        f.write(f"**Date**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Events Analyzed**: {len(raw_events)}\n")
        f.write(f"**Findings**: {len(findings)}\n\n")
        f.write("## Statistics\n\n")
        f.write("| Metric | Count |\n|--------|-------|\n")
        for key, count in sorted(stats.items()):
            f.write(f"| {key} | {count} |\n")
        f.write("\n## Top Findings\n\n")
        for finding in sorted(findings, key=lambda x: x["risk_score"], reverse=True)[:20]:
            f.write(f"### [{finding['risk_level']}] {finding['binary']} - {finding['attack_id']}\n")
            f.write(f"- **Host**: {finding['hostname']}\n")
            f.write(f"- **User**: {finding['user']}\n")
            f.write(f"- **Parent**: {finding['parent_process']}\n")
            f.write(f"- **Command**: `{finding['command_line'][:200]}`\n")
            f.write(f"- **Indicators**: {', '.join(finding['indicators'])}\n\n")
    print(f"[+] Hunt report written to {report_file}")

    # Print summary
    print("\n" + "=" * 60)
    print("HUNT SUMMARY")
    print("=" * 60)
    print(f"Total Events Analyzed: {len(raw_events)}")
    print(f"Suspicious Findings:   {len(findings)}")
    print(f"  CRITICAL: {stats.get('CRITICAL', 0)}")
    print(f"  HIGH:     {stats.get('HIGH', 0)}")
    print(f"  MEDIUM:   {stats.get('MEDIUM', 0)}")
    print(f"  LOW:      {stats.get('LOW', 0)}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="LOLBin Threat Hunt - Detect abuse of Living-off-the-Land Binaries"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Hunt command
    hunt_parser = subparsers.add_parser("hunt", help="Run LOLBin hunt against log data")
    hunt_parser.add_argument("--input", "-i", required=True, help="Path to log file (XML, CSV, JSON)")
    hunt_parser.add_argument("--output", "-o", default="./hunt_output", help="Output directory")
    hunt_parser.add_argument("--format", "-f", default="auto", choices=["auto", "xml", "csv", "json"])

    # Queries command
    queries_parser = subparsers.add_parser("queries", help="Generate hunting queries")
    queries_parser.add_argument("--platform", "-p", choices=["splunk", "kql", "all"], default="all")
    queries_parser.add_argument("--output", "-o", help="Output file for queries")

    # Signatures command
    subparsers.add_parser("signatures", help="List LOLBin signatures and indicators")

    args = parser.parse_args()

    if args.command == "hunt":
        run_hunt(args.input, args.output, args.format)
    elif args.command == "queries":
        if args.platform in ("splunk", "all"):
            print("\n=== SPLUNK SPL QUERIES ===\n")
            for name, query in generate_splunk_queries().items():
                print(f"--- {name} ---")
                print(query)
                print()
        if args.platform in ("kql", "all"):
            print("\n=== KQL QUERIES (Microsoft Defender) ===\n")
            for name, query in generate_kql_queries().items():
                print(f"--- {name} ---")
                print(query)
                print()
    elif args.command == "signatures":
        print("\n=== LOLBin Signatures ===\n")
        print(f"{'Binary':<20} {'ATT&CK ID':<15} {'Description'}")
        print("-" * 80)
        for binary, sig in LOLBIN_SIGNATURES.items():
            print(f"{binary:<20} {sig['attack_id']:<15} {sig['description']}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
