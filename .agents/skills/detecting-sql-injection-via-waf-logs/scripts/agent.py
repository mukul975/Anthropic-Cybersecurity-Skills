#!/usr/bin/env python3
"""SQL Injection WAF Log Analysis Agent - Detects SQLi attacks from ModSecurity and WAF logs."""

import json
import re
import os
import logging
import argparse
from datetime import datetime
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SQLI_PATTERNS = [
    (r"(?i)\bUNION\s+(?:ALL\s+)?SELECT\b", "UNION-based", "critical"),
    (r"(?i)\bOR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", "Tautology (OR 1=1)", "high"),
    (r"(?i)\bAND\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", "Tautology (AND 1=1)", "high"),
    (r"(?i)\bSLEEP\s*\(\s*\d+\s*\)", "Time-based blind (SLEEP)", "critical"),
    (r"(?i)\bBENCHMARK\s*\(", "Time-based blind (BENCHMARK)", "critical"),
    (r"(?i)\bWAITFOR\s+DELAY\b", "Time-based blind (WAITFOR)", "critical"),
    (r"(?i)['\"]\s*;\s*(?:DROP|DELETE|UPDATE|INSERT)\b", "Stacked query", "critical"),
    (r"(?i)\bINFORMATION_SCHEMA\b", "Schema enumeration", "high"),
    (r"(?i)\bLOAD_FILE\s*\(", "File read (LOAD_FILE)", "critical"),
    (r"(?i)\bINTO\s+(?:OUT|DUMP)FILE\b", "File write (INTO OUTFILE)", "critical"),
    (r"(?i)\bCONCAT\s*\(.*\bSELECT\b", "Nested SELECT in CONCAT", "high"),
    (r"(?i)\bGROUP_CONCAT\s*\(", "Data extraction (GROUP_CONCAT)", "high"),
    (r"(?i)\bEXTRACTVALUE\s*\(", "Error-based (EXTRACTVALUE)", "high"),
    (r"(?i)\bUPDATEXML\s*\(", "Error-based (UPDATEXML)", "high"),
    (r"(?i)(?:--|#|/\*)\s*$", "Comment termination", "medium"),
    (r"(?i)\bCHAR\s*\(\s*\d+(?:\s*,\s*\d+)*\s*\)", "CHAR() encoding bypass", "medium"),
    (r"(?i)0x[0-9a-f]{6,}", "Hex encoding bypass", "medium"),
]

MODSEC_RULE_MAP = {
    "942100": "SQL Injection via libinjection",
    "942110": "SQL Injection (common keywords)",
    "942120": "SQL Injection operator",
    "942130": "SQL Injection tautology",
    "942140": "SQL Injection (DB names)",
    "942150": "SQL Injection (functions)",
    "942160": "SQL Injection blind test (sleep/benchmark)",
    "942170": "SQL Injection (UNION query)",
    "942180": "SQL Injection bypass (basic auth)",
    "942190": "SQL Injection (MSSQL exec)",
    "942200": "SQL Injection (MySQL comment/space obfuscation)",
    "942210": "SQL Injection (chained)",
    "942220": "SQL Injection (integer overflow)",
    "942230": "SQL Injection (conditional)",
    "942240": "SQL Injection (MySQL charset switch)",
    "942250": "SQL Injection (MATCH AGAINST)",
    "942260": "SQL Injection bypass (basic auth 2)",
    "942270": "SQL Injection (common DB names)",
    "942280": "SQL Injection (pg_sleep/waitfor)",
    "942290": "SQL Injection (MongoDB)",
}


def parse_modsecurity_audit_log(log_file):
    """Parse ModSecurity audit log format."""
    entries = []
    current_entry = {}
    current_section = None

    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip()
            if line.startswith("--") and line.endswith("-A--"):
                if current_entry:
                    entries.append(current_entry)
                current_entry = {"id": line.strip("-A-").strip("-"), "sections": {}}
                current_section = "A"
            elif line.startswith("--") and re.match(r"--\w+-[A-Z]--$", line):
                current_section = line[-3]
            elif current_section:
                current_entry.setdefault("sections", {})
                current_entry["sections"].setdefault(current_section, [])
                current_entry["sections"][current_section].append(line)

    if current_entry:
        entries.append(current_entry)
    logger.info("Parsed %d ModSecurity audit log entries", len(entries))
    return entries


def parse_json_waf_log(log_file):
    """Parse JSON-formatted WAF logs (AWS WAF, Cloudflare)."""
    entries = []
    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                entries.append(entry)
            except json.JSONDecodeError:
                continue
    logger.info("Parsed %d JSON WAF log entries", len(entries))
    return entries


def classify_sqli(payload):
    """Classify SQL injection type and severity from payload string."""
    matches = []
    for pattern, attack_type, severity in SQLI_PATTERNS:
        if re.search(pattern, payload):
            matches.append({"type": attack_type, "severity": severity})
    return matches


def analyze_modsecurity_entries(entries):
    """Analyze parsed ModSecurity entries for SQLi attacks."""
    findings = []
    for entry in entries:
        sections = entry.get("sections", {})
        request_lines = sections.get("B", [])
        header_lines = sections.get("H", [])

        request_uri = ""
        source_ip = ""
        rule_ids = []

        if request_lines:
            first_line = request_lines[0]
            parts = first_line.split(" ")
            if len(parts) >= 2:
                request_uri = parts[1]

        for line in header_lines:
            m = re.search(r"id\s*\"(\d+)\"", line)
            if m:
                rule_ids.append(m.group(1))
            m = re.search(r"Remote-Addr:\s*(\S+)", line)
            if m:
                source_ip = m.group(1)

        sqli_rules = [rid for rid in rule_ids if rid in MODSEC_RULE_MAP]
        if sqli_rules:
            sqli_classes = classify_sqli(request_uri)
            findings.append({
                "source_ip": source_ip,
                "request_uri": request_uri[:500],
                "rules_triggered": [{"id": r, "desc": MODSEC_RULE_MAP.get(r, "Unknown")} for r in sqli_rules],
                "sqli_classification": sqli_classes if sqli_classes else [{"type": "WAF rule match", "severity": "high"}],
                "severity": "critical" if any(c["severity"] == "critical" for c in sqli_classes) else "high",
            })
    return findings


def analyze_json_waf_entries(entries):
    """Analyze JSON WAF log entries for SQLi patterns."""
    findings = []
    for entry in entries:
        uri = entry.get("httpRequest", {}).get("uri", "") or entry.get("ClientRequestURI", "")
        args = entry.get("httpRequest", {}).get("args", "") or entry.get("queryString", "")
        source_ip = entry.get("httpRequest", {}).get("clientIp", "") or entry.get("ClientIP", "")
        action = entry.get("action", "") or entry.get("Action", "")

        payload = f"{uri}?{args}" if args else uri
        sqli_classes = classify_sqli(payload)

        if sqli_classes:
            findings.append({
                "source_ip": source_ip,
                "request_uri": payload[:500],
                "action": action,
                "sqli_classification": sqli_classes,
                "severity": max((c["severity"] for c in sqli_classes), key=lambda s: {"critical": 3, "high": 2, "medium": 1}.get(s, 0)),
            })
    return findings


def correlate_campaigns(findings, time_window_sec=300, min_requests=5):
    """Identify SQLi attack campaigns by source IP clustering."""
    ip_groups = defaultdict(list)
    for f in findings:
        ip_groups[f["source_ip"]].append(f)

    campaigns = []
    for ip, group in ip_groups.items():
        if len(group) >= min_requests:
            attack_types = set()
            for f in group:
                for c in f.get("sqli_classification", []):
                    attack_types.add(c["type"])
            campaigns.append({
                "source_ip": ip,
                "request_count": len(group),
                "attack_types": list(attack_types),
                "severity": "critical" if len(attack_types) > 2 else "high",
                "classification": "automated" if len(group) > 20 else "manual",
            })
            logger.warning("SQLi campaign: %s (%d requests, %d attack types)", ip, len(group), len(attack_types))
    return campaigns


def generate_report(findings, campaigns):
    """Generate SQLi detection report."""
    critical = [f for f in findings if f.get("severity") == "critical"]
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_sqli_events": len(findings),
        "critical_events": len(critical),
        "unique_sources": len(set(f["source_ip"] for f in findings if f.get("source_ip"))),
        "campaigns_detected": len(campaigns),
        "campaigns": campaigns,
        "top_findings": findings[:100],
    }
    print(f"SQLI REPORT: {len(findings)} events, {len(campaigns)} campaigns, {len(critical)} critical")
    return report


def main():
    parser = argparse.ArgumentParser(description="SQL Injection WAF Log Analysis Agent")
    parser.add_argument("--log-file", required=True, help="WAF log file path")
    parser.add_argument("--format", choices=["modsecurity", "json"], default="modsecurity")
    parser.add_argument("--output", default="sqli_report.json")
    args = parser.parse_args()

    if args.format == "modsecurity":
        entries = parse_modsecurity_audit_log(args.log_file)
        findings = analyze_modsecurity_entries(entries)
    else:
        entries = parse_json_waf_log(args.log_file)
        findings = analyze_json_waf_entries(entries)

    campaigns = correlate_campaigns(findings)
    report = generate_report(findings, campaigns)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
