#!/usr/bin/env python3
"""Attack Pattern Library Builder Agent - Extracts attack patterns from CTI reports and maps to MITRE ATT&CK."""

import json
import re
import logging
import argparse
from datetime import datetime
from collections import Counter, defaultdict

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

TECHNIQUE_PATTERNS = {
    "T1566.001": [r"spearphish(?:ing)?\s+attach", r"malicious\s+(?:email\s+)?attachment"],
    "T1566.002": [r"spearphish(?:ing)?\s+link", r"phishing\s+(?:url|link)"],
    "T1059.001": [r"powershell", r"invoke-(?:expression|command|webrequest)"],
    "T1059.003": [r"cmd\.exe", r"command\s+(?:prompt|shell|line)"],
    "T1053.005": [r"scheduled\s+task", r"schtasks"],
    "T1547.001": [r"registry\s+run\s+key", r"autostart", r"CurrentVersion\\\\Run"],
    "T1003.001": [r"lsass", r"credential\s+dump", r"mimikatz"],
    "T1021.001": [r"remote\s+desktop", r"rdp\s+lateral"],
    "T1021.002": [r"smb\s+share", r"admin\s*\$", r"C\s*\$\s+share"],
    "T1071.001": [r"http\s+c2", r"web\s+(?:beacon|c2)", r"https?\s+callback"],
    "T1486": [r"encrypt(?:ion|ed)\s+(?:file|data)", r"ransomware\s+encrypt"],
    "T1048": [r"exfiltrat(?:e|ion)", r"data\s+(?:theft|steal|upload)"],
    "T1105": [r"download(?:ed)?\s+(?:payload|malware|tool)", r"ingress\s+tool\s+transfer"],
    "T1027": [r"obfuscat(?:e|ion|ed)", r"encoded\s+(?:payload|script)"],
    "T1562.001": [r"disable\s+(?:antivirus|defender|security)", r"tamper\s+protection"],
}


def extract_techniques_from_text(text):
    """Extract MITRE ATT&CK techniques from report text."""
    text_lower = text.lower()
    matched = {}
    for tech_id, patterns in TECHNIQUE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_lower):
                matched[tech_id] = {"pattern_matched": pattern, "technique_id": tech_id}
                break
    explicit = re.findall(r"T\d{4}(?:\.\d{3})?", text)
    for tid in explicit:
        if tid not in matched:
            matched[tid] = {"pattern_matched": "explicit_reference", "technique_id": tid}
    return matched


def extract_iocs_from_text(text):
    """Extract IOCs from report text."""
    iocs = {
        "ips": list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))),
        "domains": list(set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|xyz|top|info|ru|cn)\b", text))),
        "hashes_md5": list(set(re.findall(r"\b[a-fA-F0-9]{32}\b", text))),
        "hashes_sha256": list(set(re.findall(r"\b[a-fA-F0-9]{64}\b", text))),
        "urls": list(set(re.findall(r"hxxps?://[^\s<>\"]+", text))),
    }
    return iocs


def process_report(report_text, report_name=""):
    """Process a single CTI report to extract attack patterns."""
    techniques = extract_techniques_from_text(report_text)
    iocs = extract_iocs_from_text(report_text)
    return {
        "report_name": report_name,
        "techniques_found": len(techniques),
        "technique_ids": list(techniques.keys()),
        "technique_details": techniques,
        "ioc_counts": {k: len(v) for k, v in iocs.items()},
        "iocs": iocs,
    }


def build_pattern_library(processed_reports):
    """Build a consolidated attack pattern library from multiple reports."""
    technique_frequency = Counter()
    technique_reports = defaultdict(list)
    for report in processed_reports:
        for tid in report["technique_ids"]:
            technique_frequency[tid] += 1
            technique_reports[tid].append(report["report_name"])
    library = {
        "technique_frequency": dict(technique_frequency.most_common()),
        "technique_report_map": {t: r for t, r in technique_reports.items()},
        "total_unique_techniques": len(technique_frequency),
        "total_reports_processed": len(processed_reports),
    }
    return library


def generate_report(processed_reports, library):
    """Generate attack pattern library report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "library": library,
        "report_details": processed_reports,
    }
    print(f"PATTERN LIBRARY: {library['total_unique_techniques']} techniques from {library['total_reports_processed']} reports")
    return report


def main():
    parser = argparse.ArgumentParser(description="Attack Pattern Library Builder Agent")
    parser.add_argument("--report-files", nargs="+", required=True, help="CTI report text files")
    parser.add_argument("--output", default="pattern_library.json")
    args = parser.parse_args()

    processed = []
    for filepath in args.report_files:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        result = process_report(text, filepath)
        processed.append(result)
        logger.info("Processed %s: %d techniques", filepath, result["techniques_found"])

    library = build_pattern_library(processed)
    report = generate_report(processed, library)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
