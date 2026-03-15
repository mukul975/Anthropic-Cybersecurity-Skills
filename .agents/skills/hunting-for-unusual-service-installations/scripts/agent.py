#!/usr/bin/env python3
"""Agent for hunting suspicious Windows service installations (T1543.003) via Event ID 7045."""

import json
import re
import argparse
from datetime import datetime
from collections import Counter

try:
    from lxml import etree
except ImportError:
    etree = None

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as evtx_views
except ImportError:
    evtx = None

SUSPICIOUS_PATH_PATTERNS = [
    (r"\\temp\\", "temp_directory"),
    (r"\\tmp\\", "temp_directory"),
    (r"\\appdata\\", "appdata_directory"),
    (r"\\users\\public\\", "public_user_directory"),
    (r"\\programdata\\[^\\]+\.[^\\]+$", "loose_file_in_programdata"),
    (r"powershell\.exe", "powershell_execution"),
    (r"cmd\.exe\s*/c", "cmd_execution"),
    (r"-enc\s+", "encoded_command"),
    (r"-encodedcommand", "encoded_command"),
    (r"frombase64string", "base64_decode"),
    (r"downloadstring|downloadfile|webclient", "download_pattern"),
    (r"invoke-expression|iex\s", "invoke_expression"),
    (r"\\windows\\temp\\", "windows_temp"),
    (r"mshta\.exe|regsvr32\.exe|rundll32\.exe|msiexec\.exe", "lolbin_execution"),
    (r"sc\.exe\s+create", "sc_create_chain"),
    (r"\\\$recycle\.bin\\", "recycle_bin"),
    (r"\\perflog", "perflog_abuse"),
]

LEGITIMATE_SERVICE_PATHS = [
    r"^\"?C:\\Windows\\System32\\",
    r"^\"?C:\\Windows\\SysWOW64\\",
    r"^\"?C:\\Program Files\\",
    r"^\"?C:\\Program Files \(x86\)\\",
    r"^\"?C:\\Windows\\Microsoft\.NET\\",
]


def parse_evtx_events(evtx_path):
    """Parse System.evtx and extract Event ID 7045 records."""
    if not evtx:
        raise RuntimeError("python-evtx not installed: pip install python-evtx")
    events = []
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            try:
                xml = record.xml()
                root = etree.fromstring(xml.encode("utf-8") if isinstance(xml, str) else xml)
                event_id_el = root.find(".//e:System/e:EventID", ns)
                if event_id_el is None or event_id_el.text != "7045":
                    continue
                system = root.find(".//e:System", ns)
                event_data = root.find(".//e:EventData", ns)
                data_fields = {}
                if event_data is not None:
                    for data in event_data.findall("e:Data", ns):
                        name = data.get("Name", "")
                        data_fields[name] = data.text or ""
                time_el = system.find("e:TimeCreated", ns)
                timestamp = time_el.get("SystemTime", "") if time_el is not None else ""
                computer_el = system.find("e:Computer", ns)
                computer = computer_el.text if computer_el is not None else ""
                events.append({
                    "timestamp": timestamp,
                    "event_id": 7045,
                    "computer": computer,
                    "service_name": data_fields.get("ServiceName", ""),
                    "image_path": data_fields.get("ImagePath", ""),
                    "service_type": data_fields.get("ServiceType", ""),
                    "start_type": data_fields.get("StartType", ""),
                    "account_name": data_fields.get("AccountName", ""),
                })
            except Exception:
                continue
    return events


def analyze_service_path(image_path):
    """Analyze a service binary path for suspicious indicators."""
    findings = []
    path_lower = image_path.lower()
    for pattern, indicator in SUSPICIOUS_PATH_PATTERNS:
        if re.search(pattern, path_lower, re.IGNORECASE):
            findings.append(indicator)
    is_legitimate = any(re.match(p, image_path, re.IGNORECASE) for p in LEGITIMATE_SERVICE_PATHS)
    risk_score = 0
    if not is_legitimate:
        risk_score += 20
    risk_score += len(findings) * 15
    risk_score = min(risk_score, 100)
    return {
        "suspicious_indicators": findings,
        "legitimate_path": is_legitimate,
        "risk_score": risk_score,
        "risk_level": "CRITICAL" if risk_score >= 70 else "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 20 else "LOW",
    }


def hunt_suspicious_services(evtx_path):
    """Main hunting function: parse events and analyze each service."""
    events = parse_evtx_events(evtx_path)
    results = []
    for event in events:
        analysis = analyze_service_path(event.get("image_path", ""))
        entry = {**event, **analysis}
        if entry.get("account_name", "").lower() == "localsystem" and not analysis["legitimate_path"]:
            entry["risk_score"] = min(entry["risk_score"] + 20, 100)
            entry["risk_level"] = "CRITICAL" if entry["risk_score"] >= 70 else entry["risk_level"]
            entry["suspicious_indicators"].append("localsystem_nonstandard_path")
        results.append(entry)
    results.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    return results


def generate_statistics(results):
    """Generate summary statistics from hunting results."""
    total = len(results)
    risk_counts = Counter(r.get("risk_level", "LOW") for r in results)
    indicator_counts = Counter()
    account_counts = Counter()
    for r in results:
        for ind in r.get("suspicious_indicators", []):
            indicator_counts[ind] += 1
        account_counts[r.get("account_name", "Unknown")] += 1
    return {
        "total_service_installations": total,
        "risk_distribution": dict(risk_counts),
        "top_indicators": dict(indicator_counts.most_common(10)),
        "service_accounts": dict(account_counts.most_common(10)),
        "critical_count": risk_counts.get("CRITICAL", 0),
        "high_count": risk_counts.get("HIGH", 0),
    }


def full_hunt(evtx_path):
    """Run comprehensive service installation threat hunt."""
    results = hunt_suspicious_services(evtx_path)
    stats = generate_statistics(results)
    suspicious = [r for r in results if r.get("risk_score", 0) >= 20]
    return {
        "hunt_type": "Unusual Service Installation (T1543.003)",
        "timestamp": datetime.utcnow().isoformat(),
        "evtx_file": evtx_path,
        "statistics": stats,
        "suspicious_services": suspicious[:30],
        "mitre_technique": {
            "id": "T1543.003",
            "name": "Create or Modify System Process: Windows Service",
            "tactic": "Persistence, Privilege Escalation",
        },
        "recommendation": "Investigate CRITICAL and HIGH services. Verify binary hashes against known-good baselines." if stats["critical_count"] + stats["high_count"] > 0
            else "No high-risk service installations detected.",
    }


def main():
    parser = argparse.ArgumentParser(description="Service Installation Threat Hunting Agent (T1543.003)")
    parser.add_argument("evtx", help="Path to System.evtx file")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("parse", help="Parse and list all Event ID 7045 records")
    sub.add_parser("hunt", help="Hunt for suspicious service installations")
    sub.add_parser("stats", help="Generate hunting statistics")
    sub.add_parser("full", help="Full threat hunt report")
    args = parser.parse_args()

    if args.command == "parse":
        result = parse_evtx_events(args.evtx)
    elif args.command == "hunt":
        result = hunt_suspicious_services(args.evtx)
    elif args.command == "stats":
        results = hunt_suspicious_services(args.evtx)
        result = generate_statistics(results)
    elif args.command == "full" or args.command is None:
        result = full_hunt(args.evtx)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
