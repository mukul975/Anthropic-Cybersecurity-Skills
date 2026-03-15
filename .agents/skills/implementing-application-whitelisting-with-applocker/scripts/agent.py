#!/usr/bin/env python3
"""Agent for implementing and auditing AppLocker application whitelisting policies."""

import json
import argparse
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path


APPLOCKER_EVENT_IDS = {
    8002: ("EXE/DLL allowed", "INFO"),
    8003: ("EXE/DLL denied", "HIGH"),
    8004: ("EXE/DLL would be denied (audit)", "MEDIUM"),
    8005: ("Script allowed", "INFO"),
    8006: ("Script denied", "HIGH"),
    8007: ("Script would be denied (audit)", "MEDIUM"),
    8020: ("Packaged app allowed", "INFO"),
    8021: ("Packaged app denied", "HIGH"),
    8022: ("Packaged app would be denied (audit)", "MEDIUM"),
}


def parse_applocker_policy(xml_path):
    """Parse an exported AppLocker policy XML file."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns = {"al": "http://schemas.microsoft.com/windows/2006/applocker"}
    rules = []
    for collection in root.findall(".//al:RuleCollection", ns):
        rule_type = collection.get("Type", "")
        mode = collection.get("EnforcementMode", "NotConfigured")
        for rule in collection:
            rule_data = {
                "collection": rule_type,
                "enforcement_mode": mode,
                "name": rule.get("Name", ""),
                "action": rule.get("Action", ""),
                "user_or_group": rule.get("UserOrGroupSid", ""),
                "type": rule.tag.replace(f"{{{ns.get('al', '')}}}", ""),
            }
            conditions = rule.findall(".//*")
            for cond in conditions:
                if "Path" in cond.tag:
                    rule_data["path"] = cond.get("Path", "")
                elif "Publisher" in cond.tag:
                    rule_data["publisher"] = cond.get("PublisherName", "")
                elif "Hash" in cond.tag:
                    rule_data["hash"] = cond.get("Data", "")
            rules.append(rule_data)
    return rules


def audit_applocker_rules(rules):
    """Audit AppLocker rules for security weaknesses."""
    findings = []
    for rule in rules:
        if rule.get("enforcement_mode") == "AuditOnly":
            findings.append({
                "collection": rule["collection"],
                "issue": "audit_mode_only",
                "severity": "MEDIUM",
                "recommendation": "Switch to Enforce mode after validation",
            })
        if rule.get("enforcement_mode") == "NotConfigured":
            findings.append({
                "collection": rule["collection"],
                "issue": "not_configured",
                "severity": "HIGH",
                "recommendation": "Enable enforcement for this rule collection",
            })
        path = rule.get("path", "")
        if path and rule.get("action") == "Allow":
            risky_paths = [r"\\Users\\", r"\\Temp\\", r"\\Downloads\\",
                          r"\\AppData\\", r"\\ProgramData\\"]
            for rp in risky_paths:
                if re.search(rp, path, re.IGNORECASE):
                    findings.append({
                        "rule_name": rule["name"],
                        "path": path,
                        "issue": "allow_from_user_writable_path",
                        "severity": "CRITICAL",
                    })
                    break
        if rule.get("user_or_group") == "S-1-1-0" and rule.get("action") == "Allow":
            findings.append({
                "rule_name": rule["name"],
                "issue": "allow_for_everyone",
                "severity": "MEDIUM",
            })
    return findings


def analyze_applocker_events(log_path):
    """Analyze AppLocker event logs for blocked and audit events."""
    events = []
    with open(log_path) as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            event_id = int(entry.get("EventID", entry.get("event_id", 0)))
            if event_id in APPLOCKER_EVENT_IDS:
                desc, severity = APPLOCKER_EVENT_IDS[event_id]
                events.append({
                    "event_id": event_id,
                    "description": desc,
                    "severity": severity,
                    "timestamp": entry.get("TimeCreated", entry.get("timestamp", "")),
                    "computer": entry.get("Computer", entry.get("hostname", "")),
                    "user": entry.get("User", entry.get("user", "")),
                    "file_path": entry.get("FilePath", entry.get("file_path", "")),
                    "publisher": entry.get("Publisher", ""),
                })
    denied = [e for e in events if "denied" in e["description"].lower()]
    audit = [e for e in events if "audit" in e["description"].lower()]
    return {"total_events": len(events), "denied": denied, "audit_blocks": audit}


def generate_baseline_policy():
    """Generate a baseline AppLocker policy recommendation."""
    return {
        "exe_rules": {
            "enforcement_mode": "Enforce",
            "default_rules": [
                {"action": "Allow", "path": "%PROGRAMFILES%\\*", "scope": "Everyone"},
                {"action": "Allow", "path": "%WINDIR%\\*", "scope": "Everyone"},
                {"action": "Allow", "path": "*", "scope": "BUILTIN\\Administrators"},
            ],
        },
        "script_rules": {
            "enforcement_mode": "Enforce",
            "default_rules": [
                {"action": "Allow", "path": "%PROGRAMFILES%\\*", "scope": "Everyone"},
                {"action": "Allow", "path": "%WINDIR%\\*", "scope": "Everyone"},
            ],
        },
        "dll_rules": {
            "enforcement_mode": "AuditOnly",
            "note": "Start with audit mode due to high volume",
        },
    }


def main():
    parser = argparse.ArgumentParser(description="AppLocker Whitelisting Agent")
    parser.add_argument("--policy", help="Exported AppLocker policy XML")
    parser.add_argument("--events", help="AppLocker event log (JSON lines)")
    parser.add_argument("--output", default="applocker_audit_report.json")
    parser.add_argument("--action", choices=["audit", "events", "baseline", "full"],
                        default="full")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.action in ("audit", "full") and args.policy:
        rules = parse_applocker_policy(args.policy)
        findings = audit_applocker_rules(rules)
        report["findings"]["policy_audit"] = findings
        report["findings"]["total_rules"] = len(rules)
        print(f"[+] Policy rules: {len(rules)}, Issues: {len(findings)}")

    if args.action in ("events", "full") and args.events:
        result = analyze_applocker_events(args.events)
        report["findings"]["event_analysis"] = result
        print(f"[+] Events: {result['total_events']}, Denied: {len(result['denied'])}")

    if args.action in ("baseline", "full"):
        baseline = generate_baseline_policy()
        report["findings"]["baseline_policy"] = baseline
        print("[+] Baseline policy generated")

    with open(args.output, "w") as fout:
        json.dump(report, fout, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
