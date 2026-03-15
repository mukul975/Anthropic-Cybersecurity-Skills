#!/usr/bin/env python3
"""
DMARC Policy Enforcement Rollout Analyzer

Checks current DMARC, SPF, and DKIM status for a domain and provides
rollout recommendations. Parses DMARC aggregate reports to identify
sending sources and authentication failures.

Usage:
    python process.py check --domain example.com
    python process.py parse-report --report-file aggregate.xml
    python process.py spf-audit --domain example.com
"""

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from collections import defaultdict

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


@dataclass
class DMARCStatus:
    """Current DMARC deployment status."""
    domain: str = ""
    dmarc_record: str = ""
    dmarc_policy: str = ""
    dmarc_pct: int = 100
    subdomain_policy: str = ""
    rua_configured: bool = False
    ruf_configured: bool = False
    spf_record: str = ""
    spf_valid: bool = False
    spf_lookup_count: int = 0
    dkim_found: bool = False
    current_phase: str = ""
    next_action: str = ""
    issues: list = field(default_factory=list)


@dataclass
class ReportSummary:
    """DMARC aggregate report summary."""
    report_org: str = ""
    report_domain: str = ""
    date_range: str = ""
    total_messages: int = 0
    pass_count: int = 0
    fail_count: int = 0
    pass_rate: float = 0.0
    sources: list = field(default_factory=list)
    failing_sources: list = field(default_factory=list)


def count_spf_lookups(spf_record: str) -> int:
    """Count DNS lookups in SPF record (max 10 allowed)."""
    lookup_count = 0
    lookup_mechanisms = ['include:', 'a:', 'mx:', 'redirect=', 'exists:']
    for mechanism in lookup_mechanisms:
        lookup_count += spf_record.lower().count(mechanism)
    # bare 'a' and 'mx' without ':' also count
    parts = spf_record.split()
    for part in parts:
        p = part.lstrip('+').lstrip('-').lstrip('~').lstrip('?')
        if p in ('a', 'mx'):
            lookup_count += 1
    return lookup_count


def check_dmarc_status(domain: str) -> DMARCStatus:
    """Check DMARC, SPF, and DKIM status for a domain."""
    status = DMARCStatus(domain=domain)

    if not HAS_DNS:
        status.issues.append("dnspython not installed. Install with: pip install dnspython")
        return status

    # Check DMARC
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('v=DMARC1'):
                status.dmarc_record = txt
                policy = re.search(r'p=(\w+)', txt)
                if policy:
                    status.dmarc_policy = policy.group(1)
                pct = re.search(r'pct=(\d+)', txt)
                if pct:
                    status.dmarc_pct = int(pct.group(1))
                sp = re.search(r'sp=(\w+)', txt)
                if sp:
                    status.subdomain_policy = sp.group(1)
                status.rua_configured = 'rua=' in txt
                status.ruf_configured = 'ruf=' in txt
                break
    except Exception:
        status.issues.append("No DMARC record found - start with p=none")

    # Check SPF
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('v=spf1'):
                status.spf_record = txt
                status.spf_lookup_count = count_spf_lookups(txt)
                status.spf_valid = status.spf_lookup_count <= 10
                if not status.spf_valid:
                    status.issues.append(
                        f"SPF record exceeds 10 lookup limit "
                        f"({status.spf_lookup_count} lookups). Use SPF flattening."
                    )
                break
    except Exception:
        status.issues.append("No SPF record found")

    # Check common DKIM selectors
    selectors = ['default', 'google', 'selector1', 'selector2', 'proofpoint',
                 'mimecast', 's1', 's2', 'k1']
    for selector in selectors:
        try:
            dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
            status.dkim_found = True
            break
        except Exception:
            continue

    if not status.dkim_found:
        status.issues.append("No DKIM record found for common selectors")

    # Determine current phase and next action
    if not status.dmarc_record:
        status.current_phase = "Not started"
        status.next_action = "Publish DMARC record with p=none and rua= for monitoring"
    elif status.dmarc_policy == "none":
        status.current_phase = "Monitoring (p=none)"
        status.next_action = "Analyze reports, fix auth issues, then move to p=quarantine pct=10"
    elif status.dmarc_policy == "quarantine":
        if status.dmarc_pct < 100:
            status.current_phase = f"Quarantine at {status.dmarc_pct}%"
            next_pct = min(status.dmarc_pct * 2, 100)
            status.next_action = f"Increase pct to {next_pct} after reviewing reports"
        else:
            status.current_phase = "Quarantine at 100%"
            status.next_action = "Move to p=reject pct=10 after stable period"
    elif status.dmarc_policy == "reject":
        if status.dmarc_pct < 100:
            status.current_phase = f"Reject at {status.dmarc_pct}%"
            next_pct = min(status.dmarc_pct * 2, 100)
            status.next_action = f"Increase pct to {next_pct} after reviewing reports"
        else:
            status.current_phase = "FULL ENFORCEMENT (p=reject 100%)"
            status.next_action = "Maintain: monitor reports, update auth for new sources"

    if not status.rua_configured and status.dmarc_record:
        status.issues.append("No rua= tag - add aggregate report destination")

    if status.dmarc_policy == "reject" and not status.subdomain_policy:
        status.issues.append("No subdomain policy (sp=) - subdomains can still be spoofed")

    return status


def parse_dmarc_report(xml_file: str) -> ReportSummary:
    """Parse DMARC aggregate report XML."""
    summary = ReportSummary()

    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Report metadata
    metadata = root.find('.//report_metadata')
    if metadata is not None:
        org = metadata.find('org_name')
        if org is not None:
            summary.report_org = org.text or ""

    policy = root.find('.//policy_published')
    if policy is not None:
        domain = policy.find('domain')
        if domain is not None:
            summary.report_domain = domain.text or ""

    date_range = root.find('.//date_range')
    if date_range is not None:
        begin = date_range.find('begin')
        end = date_range.find('end')
        if begin is not None and end is not None:
            summary.date_range = f"{begin.text} - {end.text}"

    # Process records
    for record in root.findall('.//record'):
        row = record.find('row')
        if row is None:
            continue

        source_ip = ""
        count = 0
        spf_result = ""
        dkim_result = ""
        disposition = ""

        ip_elem = row.find('source_ip')
        if ip_elem is not None:
            source_ip = ip_elem.text or ""

        count_elem = row.find('count')
        if count_elem is not None:
            count = int(count_elem.text or 0)

        policy_eval = row.find('policy_evaluated')
        if policy_eval is not None:
            dkim_elem = policy_eval.find('dkim')
            spf_elem = policy_eval.find('spf')
            disp_elem = policy_eval.find('disposition')
            if dkim_elem is not None:
                dkim_result = dkim_elem.text or ""
            if spf_elem is not None:
                spf_result = spf_elem.text or ""
            if disp_elem is not None:
                disposition = disp_elem.text or ""

        summary.total_messages += count
        passed = (spf_result == "pass" or dkim_result == "pass")

        source_info = {
            "source_ip": source_ip,
            "count": count,
            "spf": spf_result,
            "dkim": dkim_result,
            "disposition": disposition,
            "passed": passed
        }
        summary.sources.append(source_info)

        if passed:
            summary.pass_count += count
        else:
            summary.fail_count += count
            summary.failing_sources.append(source_info)

    if summary.total_messages > 0:
        summary.pass_rate = (summary.pass_count / summary.total_messages) * 100

    return summary


def format_status_report(status: DMARCStatus) -> str:
    """Format DMARC status as readable report."""
    lines = []
    lines.append("=" * 60)
    lines.append("  DMARC ENFORCEMENT ROLLOUT STATUS")
    lines.append("=" * 60)
    lines.append(f"  Domain: {status.domain}")
    lines.append(f"  Current Phase: {status.current_phase}")
    lines.append(f"  Next Action: {status.next_action}")
    lines.append("")
    lines.append(f"  DMARC Record: {status.dmarc_record or 'NOT FOUND'}")
    lines.append(f"  DMARC Policy: {status.dmarc_policy or 'N/A'}")
    lines.append(f"  DMARC pct: {status.dmarc_pct}%")
    lines.append(f"  Subdomain Policy: {status.subdomain_policy or 'Not set'}")
    lines.append(f"  RUA Reports: {'Yes' if status.rua_configured else 'No'}")
    lines.append(f"  RUF Reports: {'Yes' if status.ruf_configured else 'No'}")
    lines.append("")
    lines.append(f"  SPF Record: {status.spf_record or 'NOT FOUND'}")
    lines.append(f"  SPF Lookups: {status.spf_lookup_count}/10")
    lines.append(f"  SPF Valid: {'Yes' if status.spf_valid else 'No'}")
    lines.append(f"  DKIM Found: {'Yes' if status.dkim_found else 'No'}")

    if status.issues:
        lines.append(f"\n  [ISSUES] ({len(status.issues)})")
        for i, issue in enumerate(status.issues, 1):
            lines.append(f"    {i}. {issue}")

    lines.append("=" * 60)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="DMARC Policy Enforcement Rollout Analyzer")
    subparsers = parser.add_subparsers(dest="command")

    check_parser = subparsers.add_parser("check", help="Check DMARC deployment status")
    check_parser.add_argument("--domain", required=True)

    report_parser = subparsers.add_parser("parse-report", help="Parse DMARC aggregate report")
    report_parser.add_argument("--report-file", required=True)

    spf_parser = subparsers.add_parser("spf-audit", help="Audit SPF record")
    spf_parser.add_argument("--domain", required=True)

    parser.add_argument("--json", action="store_true")

    args = parser.parse_args()

    if args.command == "check":
        result = check_dmarc_status(args.domain)
        if args.json:
            print(json.dumps(asdict(result), indent=2))
        else:
            print(format_status_report(result))

    elif args.command == "parse-report":
        result = parse_dmarc_report(args.report_file)
        if args.json:
            print(json.dumps(asdict(result), indent=2))
        else:
            print(f"Report from: {result.report_org}")
            print(f"Domain: {result.report_domain}")
            print(f"Total messages: {result.total_messages}")
            print(f"Pass rate: {result.pass_rate:.1f}%")
            if result.failing_sources:
                print(f"\nFailing sources ({len(result.failing_sources)}):")
                for src in result.failing_sources:
                    print(f"  IP: {src['source_ip']} | Count: {src['count']} | "
                          f"SPF: {src['spf']} | DKIM: {src['dkim']}")

    elif args.command == "spf-audit":
        status = check_dmarc_status(args.domain)
        print(f"SPF Record: {status.spf_record}")
        print(f"DNS Lookups: {status.spf_lookup_count}/10")
        print(f"Valid: {'Yes' if status.spf_valid else 'OVER LIMIT'}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
