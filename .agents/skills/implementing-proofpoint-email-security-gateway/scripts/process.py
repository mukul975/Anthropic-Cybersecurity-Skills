#!/usr/bin/env python3
"""
Proofpoint Email Security Gateway Configuration Validator

Validates MX records, SPF/DKIM/DMARC alignment, and Proofpoint
mail flow configuration for a given domain. Uses DNS lookups to
verify that email is routing through Proofpoint correctly.

Usage:
    python process.py check-mx --domain example.com
    python process.py check-auth --domain example.com
    python process.py validate-headers --eml-file message.eml
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


@dataclass
class MXCheckResult:
    """MX record validation result."""
    domain: str = ""
    mx_records: list = field(default_factory=list)
    routes_through_proofpoint: bool = False
    proofpoint_mx: str = ""
    issues: list = field(default_factory=list)


@dataclass
class AuthCheckResult:
    """Email authentication check result."""
    domain: str = ""
    spf_record: str = ""
    spf_includes_proofpoint: bool = False
    dmarc_record: str = ""
    dmarc_policy: str = ""
    dkim_selector: str = ""
    issues: list = field(default_factory=list)


@dataclass
class HeaderAnalysis:
    """Email header forensic analysis."""
    from_address: str = ""
    return_path: str = ""
    received_chain: list = field(default_factory=list)
    spf_result: str = ""
    dkim_result: str = ""
    dmarc_result: str = ""
    proofpoint_headers: list = field(default_factory=list)
    x_proofpoint_spam_details: str = ""
    x_proofpoint_virus_version: str = ""
    passed_through_proofpoint: bool = False
    issues: list = field(default_factory=list)


PROOFPOINT_MX_PATTERNS = [
    r'\.pphosted\.com$',
    r'\.proofpoint\.com$',
    r'mail\.protection\.proofpoint\.com$',
]

PROOFPOINT_SPF_INCLUDES = [
    'spf-a.proofpoint.com',
    'spf-b.proofpoint.com',
    'spf.proofpoint.com',
    'pphosted.com',
]

PROOFPOINT_HEADER_MARKERS = [
    'X-Proofpoint-Spam-Details',
    'X-Proofpoint-Virus-Version',
    'X-Proofpoint-GUID',
    'X-Proofpoint-ORIG-GUID',
]


def check_mx_records(domain: str) -> MXCheckResult:
    """Check if domain MX records route through Proofpoint."""
    result = MXCheckResult(domain=domain)

    if not HAS_DNS:
        result.issues.append("dnspython not installed. Install with: pip install dnspython")
        return result

    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in sorted(answers, key=lambda r: r.preference):
            mx_host = str(rdata.exchange).rstrip('.')
            result.mx_records.append({
                "priority": rdata.preference,
                "host": mx_host
            })
            for pattern in PROOFPOINT_MX_PATTERNS:
                if re.search(pattern, mx_host, re.IGNORECASE):
                    result.routes_through_proofpoint = True
                    result.proofpoint_mx = mx_host
                    break
    except dns.resolver.NXDOMAIN:
        result.issues.append(f"Domain {domain} does not exist")
    except dns.resolver.NoAnswer:
        result.issues.append(f"No MX records found for {domain}")
    except Exception as e:
        result.issues.append(f"DNS query failed: {str(e)}")

    if not result.routes_through_proofpoint and result.mx_records:
        result.issues.append(
            "MX records do not point to Proofpoint. "
            "Expected pattern: *.pphosted.com or *.proofpoint.com"
        )

    return result


def check_authentication(domain: str) -> AuthCheckResult:
    """Check SPF, DKIM, and DMARC records for Proofpoint alignment."""
    result = AuthCheckResult(domain=domain)

    if not HAS_DNS:
        result.issues.append("dnspython not installed. Install with: pip install dnspython")
        return result

    # Check SPF
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('v=spf1'):
                result.spf_record = txt
                for include in PROOFPOINT_SPF_INCLUDES:
                    if include in txt:
                        result.spf_includes_proofpoint = True
                        break
                break
    except Exception:
        result.issues.append("Could not retrieve SPF record")

    if result.spf_record and not result.spf_includes_proofpoint:
        result.issues.append(
            "SPF record does not include Proofpoint. "
            "Add: include:spf-a.proofpoint.com"
        )

    # Check DMARC
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('v=DMARC1'):
                result.dmarc_record = txt
                policy_match = re.search(r'p=(\w+)', txt)
                if policy_match:
                    result.dmarc_policy = policy_match.group(1)
                break
    except Exception:
        result.issues.append("No DMARC record found")

    if result.dmarc_policy == "none":
        result.issues.append(
            "DMARC policy is set to 'none' (monitoring only). "
            "Plan rollout to 'quarantine' then 'reject'"
        )

    # Check Proofpoint DKIM selector
    try:
        dkim_domain = f"proofpoint._domainkey.{domain}"
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        for rdata in answers:
            result.dkim_selector = "proofpoint"
            break
    except Exception:
        pass

    return result


def analyze_headers(eml_content: str) -> HeaderAnalysis:
    """Analyze email headers for Proofpoint routing and authentication."""
    analysis = HeaderAnalysis()

    # Extract From header
    from_match = re.search(r'^From:\s*(.+)$', eml_content, re.MULTILINE | re.IGNORECASE)
    if from_match:
        analysis.from_address = from_match.group(1).strip()

    # Extract Return-Path
    rp_match = re.search(r'^Return-Path:\s*(.+)$', eml_content, re.MULTILINE | re.IGNORECASE)
    if rp_match:
        analysis.return_path = rp_match.group(1).strip()

    # Extract Received chain
    received_headers = re.findall(
        r'^Received:\s*(.*?)(?=\n\S|\nReceived:|\n\n)',
        eml_content, re.MULTILINE | re.DOTALL | re.IGNORECASE
    )
    for hdr in received_headers:
        clean = ' '.join(hdr.split())
        analysis.received_chain.append(clean)
        if any(p.replace(r'$', '').replace(r'\.', '.') in clean.lower()
               for p in ['pphosted.com', 'proofpoint.com']):
            analysis.passed_through_proofpoint = True

    # Extract Authentication-Results
    auth_match = re.search(
        r'^Authentication-Results:\s*(.*?)(?=\n\S)',
        eml_content, re.MULTILINE | re.DOTALL | re.IGNORECASE
    )
    if auth_match:
        auth_text = auth_match.group(1)
        spf_match = re.search(r'spf=(\w+)', auth_text)
        if spf_match:
            analysis.spf_result = spf_match.group(1)
        dkim_match = re.search(r'dkim=(\w+)', auth_text)
        if dkim_match:
            analysis.dkim_result = dkim_match.group(1)
        dmarc_match = re.search(r'dmarc=(\w+)', auth_text)
        if dmarc_match:
            analysis.dmarc_result = dmarc_match.group(1)

    # Check for Proofpoint-specific headers
    for marker in PROOFPOINT_HEADER_MARKERS:
        marker_match = re.search(
            rf'^{re.escape(marker)}:\s*(.+)$',
            eml_content, re.MULTILINE | re.IGNORECASE
        )
        if marker_match:
            analysis.proofpoint_headers.append({
                "header": marker,
                "value": marker_match.group(1).strip()
            })
            if marker == 'X-Proofpoint-Spam-Details':
                analysis.x_proofpoint_spam_details = marker_match.group(1).strip()
            elif marker == 'X-Proofpoint-Virus-Version':
                analysis.x_proofpoint_virus_version = marker_match.group(1).strip()

    if not analysis.passed_through_proofpoint and not analysis.proofpoint_headers:
        analysis.issues.append("Email does not appear to have routed through Proofpoint")

    if analysis.spf_result and analysis.spf_result != 'pass':
        analysis.issues.append(f"SPF check failed: {analysis.spf_result}")
    if analysis.dkim_result and analysis.dkim_result != 'pass':
        analysis.issues.append(f"DKIM check failed: {analysis.dkim_result}")
    if analysis.dmarc_result and analysis.dmarc_result != 'pass':
        analysis.issues.append(f"DMARC check failed: {analysis.dmarc_result}")

    return analysis


def format_report(title: str, data: dict) -> str:
    """Format check results as a readable report."""
    lines = []
    lines.append("=" * 60)
    lines.append(f"  {title}")
    lines.append("=" * 60)

    for key, value in data.items():
        if key == 'issues':
            if value:
                lines.append(f"\n  [ISSUES]")
                for i, issue in enumerate(value, 1):
                    lines.append(f"    {i}. {issue}")
        elif isinstance(value, list):
            lines.append(f"\n  {key}:")
            for item in value:
                if isinstance(item, dict):
                    lines.append(f"    - {json.dumps(item)}")
                else:
                    lines.append(f"    - {item}")
        elif isinstance(value, bool):
            status = "YES" if value else "NO"
            lines.append(f"  {key}: {status}")
        else:
            lines.append(f"  {key}: {value}")

    lines.append("=" * 60)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Proofpoint Email Gateway Validator")
    subparsers = parser.add_subparsers(dest="command")

    mx_parser = subparsers.add_parser("check-mx", help="Check MX records for Proofpoint routing")
    mx_parser.add_argument("--domain", required=True, help="Domain to check")

    auth_parser = subparsers.add_parser("check-auth", help="Check email authentication records")
    auth_parser.add_argument("--domain", required=True, help="Domain to check")

    hdr_parser = subparsers.add_parser("validate-headers", help="Analyze email headers")
    hdr_parser.add_argument("--eml-file", required=True, help="Path to .eml file")

    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    if args.command == "check-mx":
        result = check_mx_records(args.domain)
        if args.json:
            print(json.dumps(asdict(result), indent=2))
        else:
            print(format_report("PROOFPOINT MX RECORD CHECK", asdict(result)))

    elif args.command == "check-auth":
        result = check_authentication(args.domain)
        if args.json:
            print(json.dumps(asdict(result), indent=2))
        else:
            print(format_report("EMAIL AUTHENTICATION CHECK", asdict(result)))

    elif args.command == "validate-headers":
        with open(args.eml_file, 'r', errors='replace') as f:
            content = f.read()
        result = analyze_headers(content)
        if args.json:
            print(json.dumps(asdict(result), indent=2))
        else:
            print(format_report("EMAIL HEADER ANALYSIS", asdict(result)))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
