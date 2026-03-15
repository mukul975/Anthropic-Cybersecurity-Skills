#!/usr/bin/env python3
"""
Phishing Email Header Analyzer

Parses raw email headers to extract authentication results, routing information,
and phishing indicators. Performs IP geolocation, domain age checks, and
generates a risk assessment report.

Usage:
    python process.py --file email_headers.txt
    python process.py --eml suspicious_email.eml
    python process.py --stdin < headers.txt
"""

import argparse
import email
import re
import json
import sys
import socket
import hashlib
from datetime import datetime, timezone
from email import policy
from email.parser import HeaderParser, BytesParser
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, asdict

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class ReceivedHop:
    """Represents a single hop in the email routing chain."""
    server_from: str = ""
    server_by: str = ""
    ip_address: str = ""
    timestamp: str = ""
    protocol: str = ""
    hop_number: int = 0
    geo_location: str = ""
    reverse_dns: str = ""


@dataclass
class AuthenticationResult:
    """Email authentication check results."""
    spf: str = "none"
    spf_domain: str = ""
    dkim: str = "none"
    dkim_domain: str = ""
    dmarc: str = "none"
    dmarc_domain: str = ""
    compauth: str = ""


@dataclass
class PhishingIndicator:
    """A single phishing indicator found in headers."""
    category: str = ""
    description: str = ""
    severity: str = "low"  # low, medium, high, critical
    raw_value: str = ""


@dataclass
class HeaderAnalysis:
    """Complete header analysis results."""
    message_id: str = ""
    from_address: str = ""
    from_domain: str = ""
    return_path: str = ""
    return_path_domain: str = ""
    reply_to: str = ""
    reply_to_domain: str = ""
    subject: str = ""
    date: str = ""
    x_originating_ip: str = ""
    x_mailer: str = ""
    received_hops: list = field(default_factory=list)
    authentication: AuthenticationResult = field(default_factory=AuthenticationResult)
    indicators: list = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "unknown"
    urls_in_headers: list = field(default_factory=list)
    file_hash: str = ""


def extract_ip_from_received(received_value: str) -> str:
    """Extract IP address from a Received header value."""
    ip_patterns = [
        r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]',
        r'\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)',
        r'from\s+\S+\s+\(.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    ]
    for pattern in ip_patterns:
        match = re.search(pattern, received_value)
        if match:
            ip = match.group(1)
            if not ip.startswith(('10.', '172.16.', '172.17.', '172.18.',
                                  '172.19.', '172.2', '172.30.', '172.31.',
                                  '192.168.', '127.')):
                return ip
    return ""


def extract_domain(email_address: str) -> str:
    """Extract domain from an email address."""
    if not email_address:
        return ""
    match = re.search(r'@([\w.-]+)', email_address)
    return match.group(1).lower() if match else ""


def parse_received_header(received_value: str, hop_num: int) -> ReceivedHop:
    """Parse a single Received header into structured data."""
    hop = ReceivedHop(hop_number=hop_num)

    from_match = re.search(r'from\s+([\w.\-]+)', received_value, re.IGNORECASE)
    if from_match:
        hop.server_from = from_match.group(1)

    by_match = re.search(r'by\s+([\w.\-]+)', received_value, re.IGNORECASE)
    if by_match:
        hop.server_by = by_match.group(1)

    hop.ip_address = extract_ip_from_received(received_value)

    date_match = re.search(r';\s*(.+)$', received_value)
    if date_match:
        hop.timestamp = date_match.group(1).strip()

    proto_match = re.search(r'with\s+(ESMTP[SA]*|SMTP[SA]*|HTTP[S]?|LMTP)',
                            received_value, re.IGNORECASE)
    if proto_match:
        hop.protocol = proto_match.group(1).upper()

    return hop


def parse_authentication_results(auth_header: str) -> AuthenticationResult:
    """Parse Authentication-Results header."""
    result = AuthenticationResult()

    spf_match = re.search(r'spf=(pass|fail|softfail|neutral|none|temperror|permerror)',
                          auth_header, re.IGNORECASE)
    if spf_match:
        result.spf = spf_match.group(1).lower()

    spf_domain_match = re.search(r'smtp\.mailfrom=([\w.\-@]+)', auth_header, re.IGNORECASE)
    if spf_domain_match:
        result.spf_domain = spf_domain_match.group(1)

    dkim_match = re.search(r'dkim=(pass|fail|none|neutral|temperror|permerror)',
                           auth_header, re.IGNORECASE)
    if dkim_match:
        result.dkim = dkim_match.group(1).lower()

    dkim_domain_match = re.search(r'header\.[di]=([\w.\-]+)', auth_header, re.IGNORECASE)
    if dkim_domain_match:
        result.dkim_domain = dkim_domain_match.group(1)

    dmarc_match = re.search(r'dmarc=(pass|fail|none|bestguesspass|temperror|permerror)',
                            auth_header, re.IGNORECASE)
    if dmarc_match:
        result.dmarc = dmarc_match.group(1).lower()

    dmarc_domain_match = re.search(r'header\.from=([\w.\-]+)', auth_header, re.IGNORECASE)
    if dmarc_domain_match:
        result.dmarc_domain = dmarc_domain_match.group(1)

    compauth_match = re.search(r'compauth=(\w+)', auth_header, re.IGNORECASE)
    if compauth_match:
        result.compauth = compauth_match.group(1)

    return result


def geolocate_ip(ip_address: str) -> str:
    """Geolocate an IP address using ip-api.com (free, no key required)."""
    if not HAS_REQUESTS or not ip_address:
        return "unknown"
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip_address}",
                            timeout=5,
                            params={"fields": "country,city,org,status"})
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return f"{data.get('city', '')}, {data.get('country', '')} ({data.get('org', '')})"
    except Exception:
        pass
    return "unknown"


def reverse_dns_lookup(ip_address: str) -> str:
    """Perform reverse DNS lookup on an IP address."""
    if not ip_address:
        return ""
    try:
        hostname = socket.gethostbyaddr(ip_address)
        return hostname[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def check_abuseipdb(ip_address: str, api_key: str = "") -> dict:
    """Check IP against AbuseIPDB (requires API key)."""
    if not HAS_REQUESTS or not api_key or not ip_address:
        return {}
    try:
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
        resp = requests.get("https://api.abuseipdb.com/api/v2/check",
                            headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("data", {})
    except Exception:
        pass
    return {}


def analyze_indicators(analysis: HeaderAnalysis) -> list:
    """Detect phishing indicators from parsed header data."""
    indicators = []

    # Check From vs Return-Path mismatch
    if (analysis.from_domain and analysis.return_path_domain and
            analysis.from_domain != analysis.return_path_domain):
        indicators.append(PhishingIndicator(
            category="sender_mismatch",
            description=f"From domain ({analysis.from_domain}) differs from "
                        f"Return-Path domain ({analysis.return_path_domain})",
            severity="high",
            raw_value=f"From: {analysis.from_domain}, Return-Path: {analysis.return_path_domain}"
        ))

    # Check From vs Reply-To mismatch
    if (analysis.from_domain and analysis.reply_to_domain and
            analysis.from_domain != analysis.reply_to_domain):
        indicators.append(PhishingIndicator(
            category="reply_to_mismatch",
            description=f"From domain ({analysis.from_domain}) differs from "
                        f"Reply-To domain ({analysis.reply_to_domain})",
            severity="high",
            raw_value=f"From: {analysis.from_domain}, Reply-To: {analysis.reply_to_domain}"
        ))

    # Check SPF failure
    if analysis.authentication.spf in ("fail", "softfail"):
        indicators.append(PhishingIndicator(
            category="authentication_failure",
            description=f"SPF check returned {analysis.authentication.spf}",
            severity="high" if analysis.authentication.spf == "fail" else "medium",
            raw_value=f"spf={analysis.authentication.spf}"
        ))

    # Check DKIM failure
    if analysis.authentication.dkim == "fail":
        indicators.append(PhishingIndicator(
            category="authentication_failure",
            description="DKIM signature verification failed",
            severity="high",
            raw_value="dkim=fail"
        ))

    # Check DMARC failure
    if analysis.authentication.dmarc == "fail":
        indicators.append(PhishingIndicator(
            category="authentication_failure",
            description="DMARC policy check failed",
            severity="critical",
            raw_value="dmarc=fail"
        ))

    # Check for missing Message-ID
    if not analysis.message_id:
        indicators.append(PhishingIndicator(
            category="missing_header",
            description="Message-ID header is missing",
            severity="medium",
            raw_value=""
        ))

    # Check for suspicious X-Mailer
    suspicious_mailers = [
        "PHPMailer", "King Phisher", "GoPhish", "Swaks",
        "Sendinblue", "Mass Mailer", "Bulk Mailer"
    ]
    if analysis.x_mailer:
        for mailer in suspicious_mailers:
            if mailer.lower() in analysis.x_mailer.lower():
                indicators.append(PhishingIndicator(
                    category="suspicious_mailer",
                    description=f"Suspicious X-Mailer detected: {analysis.x_mailer}",
                    severity="high",
                    raw_value=analysis.x_mailer
                ))
                break

    # Check for too few received hops (direct injection)
    if len(analysis.received_hops) <= 1:
        indicators.append(PhishingIndicator(
            category="routing_anomaly",
            description="Very few Received hops - possible direct SMTP injection",
            severity="medium",
            raw_value=f"Hop count: {len(analysis.received_hops)}"
        ))

    # Check for missing authentication results
    auth = analysis.authentication
    if auth.spf == "none" and auth.dkim == "none" and auth.dmarc == "none":
        indicators.append(PhishingIndicator(
            category="no_authentication",
            description="No email authentication results found (SPF, DKIM, DMARC all absent)",
            severity="high",
            raw_value=""
        ))

    return indicators


def calculate_risk_score(indicators: list) -> tuple:
    """Calculate risk score from indicators. Returns (score, level)."""
    severity_weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
    score = 0
    for indicator in indicators:
        score += severity_weights.get(indicator.severity, 0)

    score = min(score, 100)

    if score >= 70:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    elif score >= 10:
        level = "LOW"
    else:
        level = "CLEAN"

    return score, level


def analyze_headers(raw_headers: str, enrich: bool = False,
                    abuseipdb_key: str = "") -> HeaderAnalysis:
    """
    Main analysis function. Parses raw email headers and produces
    a complete HeaderAnalysis report.
    """
    analysis = HeaderAnalysis()

    # Calculate hash of raw input for evidence tracking
    analysis.file_hash = hashlib.sha256(raw_headers.encode()).hexdigest()

    # Parse using Python's email library
    parser = HeaderParser()
    msg = parser.parsestr(raw_headers)

    # Extract basic fields
    analysis.from_address = msg.get("From", "")
    analysis.from_domain = extract_domain(analysis.from_address)
    analysis.return_path = msg.get("Return-Path", "")
    analysis.return_path_domain = extract_domain(analysis.return_path)
    analysis.reply_to = msg.get("Reply-To", "")
    analysis.reply_to_domain = extract_domain(analysis.reply_to)
    analysis.message_id = msg.get("Message-ID", "")
    analysis.subject = msg.get("Subject", "")
    analysis.date = msg.get("Date", "")
    analysis.x_mailer = msg.get("X-Mailer", "") or msg.get("User-Agent", "")

    # Extract X-Originating-IP
    x_orig = msg.get("X-Originating-IP", "")
    if x_orig:
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', x_orig)
        if ip_match:
            analysis.x_originating_ip = ip_match.group(1)

    # Parse Received headers (they appear in reverse order)
    received_headers = msg.get_all("Received", [])
    for i, received in enumerate(received_headers):
        hop = parse_received_header(received, len(received_headers) - i)
        if enrich and hop.ip_address:
            hop.geo_location = geolocate_ip(hop.ip_address)
            hop.reverse_dns = reverse_dns_lookup(hop.ip_address)
        analysis.received_hops.append(hop)

    # Reverse to chronological order (first hop first)
    analysis.received_hops.reverse()

    # Parse Authentication-Results
    auth_results = msg.get("Authentication-Results", "")
    if auth_results:
        analysis.authentication = parse_authentication_results(auth_results)

    # Also check ARC-Authentication-Results
    arc_auth = msg.get("ARC-Authentication-Results", "")
    if arc_auth and analysis.authentication.spf == "none":
        analysis.authentication = parse_authentication_results(arc_auth)

    # Extract URLs from headers
    url_pattern = r'https?://[^\s<>"\')\]>]+'
    all_header_text = raw_headers
    analysis.urls_in_headers = list(set(re.findall(url_pattern, all_header_text)))

    # Detect phishing indicators
    analysis.indicators = analyze_indicators(analysis)

    # Calculate risk score
    analysis.risk_score, analysis.risk_level = calculate_risk_score(analysis.indicators)

    # Enrich with threat intelligence if requested
    if enrich and analysis.x_originating_ip and abuseipdb_key:
        abuse_data = check_abuseipdb(analysis.x_originating_ip, abuseipdb_key)
        if abuse_data and abuse_data.get("abuseConfidenceScore", 0) > 50:
            analysis.indicators.append(PhishingIndicator(
                category="threat_intelligence",
                description=f"IP {analysis.x_originating_ip} has abuse confidence "
                            f"score of {abuse_data['abuseConfidenceScore']}%",
                severity="critical",
                raw_value=json.dumps(abuse_data)
            ))
            # Recalculate risk
            analysis.risk_score, analysis.risk_level = calculate_risk_score(analysis.indicators)

    return analysis


def format_report(analysis: HeaderAnalysis) -> str:
    """Format analysis results as a human-readable report."""
    lines = []
    lines.append("=" * 70)
    lines.append("  PHISHING EMAIL HEADER ANALYSIS REPORT")
    lines.append("=" * 70)
    lines.append(f"  Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"  Evidence Hash: {analysis.file_hash[:16]}...")
    lines.append("")

    # Risk Assessment
    lines.append(f"  RISK LEVEL: {analysis.risk_level} (Score: {analysis.risk_score}/100)")
    lines.append("-" * 70)

    # Sender Information
    lines.append("\n[SENDER INFORMATION]")
    lines.append(f"  From:        {analysis.from_address}")
    lines.append(f"  Return-Path: {analysis.return_path}")
    lines.append(f"  Reply-To:    {analysis.reply_to}")
    lines.append(f"  Subject:     {analysis.subject}")
    lines.append(f"  Date:        {analysis.date}")
    lines.append(f"  Message-ID:  {analysis.message_id}")
    lines.append(f"  X-Mailer:    {analysis.x_mailer}")
    if analysis.x_originating_ip:
        lines.append(f"  Origin IP:   {analysis.x_originating_ip}")

    # Authentication Results
    lines.append("\n[AUTHENTICATION RESULTS]")
    auth = analysis.authentication
    spf_icon = "PASS" if auth.spf == "pass" else "FAIL" if auth.spf in ("fail", "softfail") else "NONE"
    dkim_icon = "PASS" if auth.dkim == "pass" else "FAIL" if auth.dkim == "fail" else "NONE"
    dmarc_icon = "PASS" if auth.dmarc == "pass" else "FAIL" if auth.dmarc == "fail" else "NONE"
    lines.append(f"  SPF:   {spf_icon} ({auth.spf}) domain={auth.spf_domain}")
    lines.append(f"  DKIM:  {dkim_icon} ({auth.dkim}) domain={auth.dkim_domain}")
    lines.append(f"  DMARC: {dmarc_icon} ({auth.dmarc}) domain={auth.dmarc_domain}")

    # Routing Path
    lines.append(f"\n[ROUTING PATH] ({len(analysis.received_hops)} hops)")
    for hop in analysis.received_hops:
        lines.append(f"  Hop {hop.hop_number}: {hop.server_from} -> {hop.server_by}")
        if hop.ip_address:
            lines.append(f"           IP: {hop.ip_address}")
        if hop.geo_location and hop.geo_location != "unknown":
            lines.append(f"           Location: {hop.geo_location}")
        if hop.protocol:
            lines.append(f"           Protocol: {hop.protocol}")
        if hop.timestamp:
            lines.append(f"           Time: {hop.timestamp}")

    # Phishing Indicators
    if analysis.indicators:
        lines.append(f"\n[PHISHING INDICATORS] ({len(analysis.indicators)} found)")
        for i, ind in enumerate(analysis.indicators, 1):
            lines.append(f"  {i}. [{ind.severity.upper()}] {ind.description}")
            if ind.raw_value:
                lines.append(f"     Value: {ind.raw_value}")
    else:
        lines.append("\n[PHISHING INDICATORS] None detected")

    # URLs in Headers
    if analysis.urls_in_headers:
        lines.append(f"\n[URLS IN HEADERS] ({len(analysis.urls_in_headers)} found)")
        for url in analysis.urls_in_headers[:10]:
            lines.append(f"  - {url}")

    lines.append("\n" + "=" * 70)
    lines.append("  END OF REPORT")
    lines.append("=" * 70)

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze email headers for phishing indicators"
    )
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--file", "-f", help="Path to file containing raw headers")
    input_group.add_argument("--eml", "-e", help="Path to .eml file")
    input_group.add_argument("--stdin", action="store_true", help="Read headers from stdin")

    parser.add_argument("--enrich", action="store_true",
                        help="Enrich with IP geolocation and reverse DNS")
    parser.add_argument("--abuseipdb-key", default="",
                        help="AbuseIPDB API key for threat intelligence")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--output", "-o", help="Write report to file")

    args = parser.parse_args()

    # Read input
    if args.stdin:
        raw_headers = sys.stdin.read()
    elif args.eml:
        with open(args.eml, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
            raw_headers = str(msg)
    else:
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            raw_headers = f.read()

    # Analyze
    analysis = analyze_headers(
        raw_headers,
        enrich=args.enrich,
        abuseipdb_key=args.abuseipdb_key
    )

    # Output
    if args.json:
        output = json.dumps(asdict(analysis), indent=2, default=str)
    else:
        output = format_report(analysis)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Report written to {args.output}")
    else:
        print(output)

    # Exit code based on risk
    if analysis.risk_level in ("CRITICAL", "HIGH"):
        sys.exit(2)
    elif analysis.risk_level == "MEDIUM":
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
