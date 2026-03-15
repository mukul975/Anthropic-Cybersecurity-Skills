#!/usr/bin/env python3
"""
Phishing Report Triage Engine

Processes user-reported phishing emails, extracts IOCs,
performs automated analysis, and classifies the report.

Usage:
    python process.py triage --eml-file reported_email.eml
    python process.py metrics --reports-file reports.json
    python process.py extract-iocs --eml-file reported_email.eml
"""

import argparse
import json
import re
import hashlib
import sys
from dataclasses import dataclass, field, asdict
from collections import Counter
from datetime import datetime


@dataclass
class ExtractedIOCs:
    """IOCs extracted from reported email."""
    sender_address: str = ""
    sender_domain: str = ""
    reply_to: str = ""
    urls: list = field(default_factory=list)
    domains: list = field(default_factory=list)
    attachment_names: list = field(default_factory=list)
    attachment_hashes: list = field(default_factory=list)
    ip_addresses: list = field(default_factory=list)
    subject: str = ""


@dataclass
class TriageResult:
    """Triage classification result."""
    report_id: str = ""
    reporter: str = ""
    classification: str = ""
    confidence: float = 0.0
    iocs: dict = field(default_factory=dict)
    indicators: list = field(default_factory=list)
    recommended_action: str = ""
    auto_actionable: bool = False


@dataclass
class ReportingMetrics:
    """Phishing reporting program metrics."""
    total_reports: int = 0
    confirmed_phishing: int = 0
    confirmed_spam: int = 0
    simulation_reports: int = 0
    false_positives: int = 0
    mean_triage_time_min: float = 0.0
    top_reporters: list = field(default_factory=list)
    report_rate: float = 0.0


PHISHING_INDICATORS = [
    (r'\burgent\b.*\b(action|response|attention)\b', "Urgency language", 15),
    (r'\b(verify|confirm|validate)\s+your\s+(account|identity|password)\b', "Credential request", 20),
    (r'\b(click|follow)\s+(here|this|the)\s+(link|button)\b', "Click-bait language", 10),
    (r'\b(suspended|locked|disabled|compromised)\s+(account|access)\b', "Fear language", 15),
    (r'\b(wire\s+transfer|payment|invoice|bank)\b', "Financial language", 10),
    (r'\bgift\s+card\b', "Gift card request", 20),
    (r'\bdo\s+not\s+(share|tell|discuss)\b', "Secrecy language", 15),
]


def extract_iocs(eml_content: str) -> ExtractedIOCs:
    """Extract IOCs from email content."""
    iocs = ExtractedIOCs()

    # Extract From
    from_match = re.search(r'^From:\s*(?:.*<)?([^>\s]+@[^>\s]+)', eml_content,
                           re.MULTILINE | re.IGNORECASE)
    if from_match:
        iocs.sender_address = from_match.group(1).strip()
        domain_match = re.search(r'@([\w.-]+)', iocs.sender_address)
        if domain_match:
            iocs.sender_domain = domain_match.group(1)

    # Extract Reply-To
    reply_match = re.search(r'^Reply-To:\s*(?:.*<)?([^>\s]+@[^>\s]+)', eml_content,
                            re.MULTILINE | re.IGNORECASE)
    if reply_match:
        iocs.reply_to = reply_match.group(1).strip()

    # Extract Subject
    subj_match = re.search(r'^Subject:\s*(.+)$', eml_content, re.MULTILINE | re.IGNORECASE)
    if subj_match:
        iocs.subject = subj_match.group(1).strip()

    # Extract URLs
    urls = re.findall(r'https?://[^\s<>"\']+', eml_content)
    iocs.urls = list(set(urls))

    # Extract domains from URLs
    for url in iocs.urls:
        domain_match = re.search(r'https?://([^/:\s]+)', url)
        if domain_match:
            domain = domain_match.group(1).lower()
            if domain not in iocs.domains:
                iocs.domains.append(domain)

    # Extract IP addresses from headers
    ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', eml_content)
    iocs.ip_addresses = list(set(ips))

    # Extract attachment filenames
    attachments = re.findall(
        r'filename[*]?=(?:"([^"]+)"|([^\s;]+))',
        eml_content, re.IGNORECASE
    )
    for groups in attachments:
        name = groups[0] or groups[1]
        if name and name not in iocs.attachment_names:
            iocs.attachment_names.append(name)

    return iocs


def triage_report(eml_content: str, simulation_subjects: list = None) -> TriageResult:
    """Classify a reported email."""
    result = TriageResult()
    iocs = extract_iocs(eml_content)
    result.iocs = asdict(iocs)

    score = 0
    body_lower = eml_content.lower()

    # Check if it's a known simulation
    if simulation_subjects:
        for sim_subj in simulation_subjects:
            if sim_subj.lower() in iocs.subject.lower():
                result.classification = "simulation"
                result.confidence = 0.95
                result.recommended_action = "Credit reporter in training platform"
                result.auto_actionable = True
                return result

    # Check phishing indicators
    for pattern, desc, weight in PHISHING_INDICATORS:
        if re.search(pattern, body_lower):
            result.indicators.append(desc)
            score += weight

    # Check for authentication failures
    auth_results = re.search(r'Authentication-Results:.*?(spf=fail|dkim=fail|dmarc=fail)',
                             eml_content, re.IGNORECASE | re.DOTALL)
    if auth_results:
        result.indicators.append(f"Authentication failure: {auth_results.group(1)}")
        score += 20

    # Check Reply-To mismatch
    if iocs.reply_to and iocs.sender_address:
        reply_domain = re.search(r'@([\w.-]+)', iocs.reply_to)
        sender_domain = re.search(r'@([\w.-]+)', iocs.sender_address)
        if reply_domain and sender_domain:
            if reply_domain.group(1) != sender_domain.group(1):
                result.indicators.append("Reply-To domain mismatch")
                score += 15

    # Check for suspicious attachment types
    risky_extensions = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs',
                        '.js', '.wsf', '.hta', '.iso', '.img']
    for att in iocs.attachment_names:
        if any(att.lower().endswith(ext) for ext in risky_extensions):
            result.indicators.append(f"Risky attachment: {att}")
            score += 25

    # Classify
    if score >= 50:
        result.classification = "confirmed_phishing"
        result.confidence = min(score / 100, 0.95)
        result.recommended_action = "Retract from all inboxes, block sender domain"
        result.auto_actionable = True
    elif score >= 25:
        result.classification = "suspicious"
        result.confidence = score / 100
        result.recommended_action = "Escalate to SOC analyst for manual review"
        result.auto_actionable = False
    elif score >= 10:
        result.classification = "spam"
        result.confidence = 0.6
        result.recommended_action = "Move to junk for all recipients"
        result.auto_actionable = True
    else:
        result.classification = "clean"
        result.confidence = 0.7
        result.recommended_action = "Return to inbox, notify reporter"
        result.auto_actionable = True

    return result


def calculate_metrics(reports: list) -> ReportingMetrics:
    """Calculate phishing reporting program metrics."""
    metrics = ReportingMetrics()
    metrics.total_reports = len(reports)

    reporter_counts = Counter()
    triage_times = []

    for report in reports:
        classification = report.get("classification", "")
        if classification == "confirmed_phishing":
            metrics.confirmed_phishing += 1
        elif classification == "spam":
            metrics.confirmed_spam += 1
        elif classification == "simulation":
            metrics.simulation_reports += 1
        elif classification == "clean":
            metrics.false_positives += 1

        reporter = report.get("reporter", "")
        if reporter:
            reporter_counts[reporter] += 1

        triage_time = report.get("triage_time_minutes", 0)
        if triage_time > 0:
            triage_times.append(triage_time)

    if triage_times:
        metrics.mean_triage_time_min = sum(triage_times) / len(triage_times)

    metrics.top_reporters = [
        {"reporter": r, "count": c}
        for r, c in reporter_counts.most_common(10)
    ]

    if metrics.total_reports > 0:
        metrics.report_rate = (
            (metrics.confirmed_phishing + metrics.simulation_reports) /
            metrics.total_reports * 100
        )

    return metrics


def main():
    parser = argparse.ArgumentParser(description="Phishing Report Triage Engine")
    subparsers = parser.add_subparsers(dest="command")

    triage_parser = subparsers.add_parser("triage", help="Triage reported email")
    triage_parser.add_argument("--eml-file", required=True)
    triage_parser.add_argument("--sim-subjects", nargs="*", default=[])

    metrics_parser = subparsers.add_parser("metrics", help="Calculate reporting metrics")
    metrics_parser.add_argument("--reports-file", required=True)

    ioc_parser = subparsers.add_parser("extract-iocs", help="Extract IOCs from email")
    ioc_parser.add_argument("--eml-file", required=True)

    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.command == "triage":
        with open(args.eml_file, 'r', errors='replace') as f:
            content = f.read()
        result = triage_report(content, args.sim_subjects)
        if args.json:
            print(json.dumps(asdict(result), indent=2))
        else:
            print(f"Classification: {result.classification}")
            print(f"Confidence: {result.confidence:.0%}")
            print(f"Action: {result.recommended_action}")
            print(f"Auto-actionable: {'Yes' if result.auto_actionable else 'No'}")
            if result.indicators:
                print(f"Indicators:")
                for ind in result.indicators:
                    print(f"  - {ind}")

    elif args.command == "metrics":
        with open(args.reports_file) as f:
            reports = json.load(f)
        result = calculate_metrics(reports)
        if args.json:
            print(json.dumps(asdict(result), indent=2))
        else:
            print(f"Total reports: {result.total_reports}")
            print(f"Confirmed phishing: {result.confirmed_phishing}")
            print(f"Spam: {result.confirmed_spam}")
            print(f"Simulations reported: {result.simulation_reports}")
            print(f"False positives: {result.false_positives}")
            print(f"Mean triage time: {result.mean_triage_time_min:.1f} min")

    elif args.command == "extract-iocs":
        with open(args.eml_file, 'r', errors='replace') as f:
            content = f.read()
        iocs = extract_iocs(content)
        print(json.dumps(asdict(iocs), indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
