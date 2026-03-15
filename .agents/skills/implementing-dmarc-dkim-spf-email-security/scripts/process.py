#!/usr/bin/env python3
"""
DMARC/DKIM/SPF Validator and DMARC Report Parser

Validates email authentication DNS records and parses DMARC aggregate
XML reports to identify unauthorized senders and authentication failures.

Usage:
    python process.py --check-domain example.com
    python process.py --parse-report dmarc_report.xml
    python process.py --parse-report-dir /path/to/reports/
"""

import argparse
import json
import sys
import xml.etree.ElementTree as ET
import gzip
import zipfile
import io
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from collections import defaultdict

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class SPFRecord:
    """Parsed SPF record details."""
    raw: str = ""
    version: str = ""
    mechanisms: list = field(default_factory=list)
    includes: list = field(default_factory=list)
    ip4_ranges: list = field(default_factory=list)
    ip6_ranges: list = field(default_factory=list)
    qualifier: str = ""
    dns_lookup_count: int = 0
    valid: bool = False
    errors: list = field(default_factory=list)


@dataclass
class DKIMRecord:
    """Parsed DKIM record details."""
    selector: str = ""
    raw: str = ""
    version: str = ""
    key_type: str = ""
    public_key: str = ""
    key_length: int = 0
    valid: bool = False
    errors: list = field(default_factory=list)


@dataclass
class DMARCRecord:
    """Parsed DMARC record details."""
    raw: str = ""
    version: str = ""
    policy: str = ""
    subdomain_policy: str = ""
    pct: int = 100
    rua: list = field(default_factory=list)
    ruf: list = field(default_factory=list)
    adkim: str = "r"
    aspf: str = "r"
    fo: str = "0"
    valid: bool = False
    errors: list = field(default_factory=list)


@dataclass
class DMARCReportRecord:
    """Single record from a DMARC aggregate report."""
    source_ip: str = ""
    count: int = 0
    disposition: str = ""
    dkim_result: str = ""
    dkim_domain: str = ""
    spf_result: str = ""
    spf_domain: str = ""
    header_from: str = ""
    envelope_from: str = ""
    dkim_aligned: bool = False
    spf_aligned: bool = False


@dataclass
class DMARCReportSummary:
    """Summary of a parsed DMARC aggregate report."""
    org_name: str = ""
    report_id: str = ""
    date_begin: str = ""
    date_end: str = ""
    domain: str = ""
    total_messages: int = 0
    pass_count: int = 0
    fail_count: int = 0
    records: list = field(default_factory=list)
    top_failing_ips: list = field(default_factory=list)
    unauthorized_senders: list = field(default_factory=list)


def query_dns_txt(domain: str) -> list:
    """Query DNS TXT records for a domain."""
    if HAS_DNSPYTHON:
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            results = []
            for rdata in answers:
                txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
                results.append(txt)
            return results
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.resolver.Timeout):
            return []
    elif HAS_REQUESTS:
        try:
            resp = requests.get(
                f"https://dns.google/resolve?name={domain}&type=TXT",
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                results = []
                for answer in data.get("Answer", []):
                    txt = answer.get("data", "").strip('"')
                    results.append(txt)
                return results
        except Exception:
            pass
    return []


def check_spf(domain: str) -> SPFRecord:
    """Check and validate SPF record for a domain."""
    record = SPFRecord()
    txt_records = query_dns_txt(domain)

    spf_records = [r for r in txt_records if r.startswith("v=spf1")]

    if not spf_records:
        record.errors.append("No SPF record found")
        return record

    if len(spf_records) > 1:
        record.errors.append(f"Multiple SPF records found ({len(spf_records)}) - RFC violation")

    record.raw = spf_records[0]
    record.version = "spf1"

    parts = record.raw.split()
    lookup_count = 0

    for part in parts[1:]:
        if part.startswith("include:"):
            domain_ref = part.split(":", 1)[1]
            record.includes.append(domain_ref)
            record.mechanisms.append(part)
            lookup_count += 1
        elif part.startswith("ip4:"):
            record.ip4_ranges.append(part.split(":", 1)[1])
            record.mechanisms.append(part)
        elif part.startswith("ip6:"):
            record.ip6_ranges.append(part.split(":", 1)[1])
            record.mechanisms.append(part)
        elif part.startswith(("a:", "a")):
            record.mechanisms.append(part)
            lookup_count += 1
        elif part.startswith(("mx:", "mx")):
            record.mechanisms.append(part)
            lookup_count += 1
        elif part.startswith("redirect="):
            record.mechanisms.append(part)
            lookup_count += 1
        elif part.startswith("exists:"):
            record.mechanisms.append(part)
            lookup_count += 1
        elif part in ("-all", "~all", "?all", "+all"):
            record.qualifier = part

    record.dns_lookup_count = lookup_count

    if lookup_count > 10:
        record.errors.append(f"SPF exceeds 10 DNS lookup limit ({lookup_count} lookups)")

    if record.qualifier == "+all":
        record.errors.append("SPF uses +all which allows any sender (insecure)")
    elif record.qualifier == "?all":
        record.errors.append("SPF uses ?all (neutral) - provides no protection")

    if not record.qualifier:
        record.errors.append("SPF record has no terminating mechanism (-all/~all)")

    record.valid = len(record.errors) == 0
    return record


def check_dkim(domain: str, selectors: list = None) -> list:
    """Check DKIM records for common selectors."""
    if selectors is None:
        selectors = [
            "selector1", "selector2",  # Microsoft 365
            "google", "default",  # Google Workspace
            "s1", "s2",  # Generic
            "dkim", "mail",  # Common
            "k1", "k2",  # Mailchimp
            "sm1", "sm2",  # SendGrid
        ]

    results = []
    for selector in selectors:
        record = DKIMRecord(selector=selector)
        dkim_domain = f"{selector}._domainkey.{domain}"
        txt_records = query_dns_txt(dkim_domain)

        dkim_records = [r for r in txt_records if "DKIM1" in r or "p=" in r]

        if dkim_records:
            record.raw = dkim_records[0]

            if "v=DKIM1" in record.raw:
                record.version = "DKIM1"

            import re
            key_match = re.search(r'k=(\w+)', record.raw)
            if key_match:
                record.key_type = key_match.group(1)
            else:
                record.key_type = "rsa"  # default

            pub_match = re.search(r'p=([A-Za-z0-9+/=]+)', record.raw)
            if pub_match:
                record.public_key = pub_match.group(1)
                import base64
                try:
                    key_bytes = base64.b64decode(record.public_key)
                    record.key_length = len(key_bytes) * 8
                except Exception:
                    pass

            if record.key_length and record.key_length < 2048:
                record.errors.append(
                    f"DKIM key is {record.key_length}-bit (2048-bit minimum recommended per RFC 8301)"
                )

            if not record.public_key:
                record.errors.append("DKIM record has empty public key (revoked)")

            record.valid = len(record.errors) == 0
            results.append(record)

    return results


def check_dmarc(domain: str) -> DMARCRecord:
    """Check and validate DMARC record for a domain."""
    record = DMARCRecord()
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = query_dns_txt(dmarc_domain)

    dmarc_records = [r for r in txt_records if r.startswith("v=DMARC1")]

    if not dmarc_records:
        record.errors.append("No DMARC record found")
        return record

    record.raw = dmarc_records[0]
    record.version = "DMARC1"

    import re
    tags = {}
    for tag_match in re.finditer(r'(\w+)\s*=\s*([^;]+)', record.raw):
        tags[tag_match.group(1).strip()] = tag_match.group(2).strip()

    record.policy = tags.get("p", "")
    record.subdomain_policy = tags.get("sp", record.policy)
    record.adkim = tags.get("adkim", "r")
    record.aspf = tags.get("aspf", "r")
    record.fo = tags.get("fo", "0")

    if "pct" in tags:
        try:
            record.pct = int(tags["pct"])
        except ValueError:
            record.errors.append(f"Invalid pct value: {tags['pct']}")

    if "rua" in tags:
        record.rua = [uri.strip() for uri in tags["rua"].split(",")]
    if "ruf" in tags:
        record.ruf = [uri.strip() for uri in tags["ruf"].split(",")]

    if not record.policy:
        record.errors.append("DMARC record missing required p= tag")
    elif record.policy not in ("none", "quarantine", "reject"):
        record.errors.append(f"Invalid DMARC policy: {record.policy}")

    if record.policy == "none":
        record.errors.append("DMARC policy is 'none' (monitor only) - not enforcing")

    if not record.rua:
        record.errors.append("No aggregate report URI (rua) configured")

    record.valid = len([e for e in record.errors if "monitor only" not in e and "rua" not in e]) == 0
    return record


def parse_dmarc_report(xml_content: str) -> DMARCReportSummary:
    """Parse a DMARC aggregate XML report."""
    summary = DMARCReportSummary()

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}", file=sys.stderr)
        return summary

    # Report metadata
    metadata = root.find("report_metadata")
    if metadata is not None:
        summary.org_name = metadata.findtext("org_name", "")
        summary.report_id = metadata.findtext("report_id", "")
        date_range = metadata.find("date_range")
        if date_range is not None:
            begin = date_range.findtext("begin", "")
            end = date_range.findtext("end", "")
            if begin:
                summary.date_begin = datetime.fromtimestamp(
                    int(begin), tz=timezone.utc
                ).strftime("%Y-%m-%d")
            if end:
                summary.date_end = datetime.fromtimestamp(
                    int(end), tz=timezone.utc
                ).strftime("%Y-%m-%d")

    # Policy published
    policy = root.find("policy_published")
    if policy is not None:
        summary.domain = policy.findtext("domain", "")

    # Records
    failing_ips = defaultdict(int)

    for record_el in root.findall("record"):
        rec = DMARCReportRecord()

        row = record_el.find("row")
        if row is not None:
            rec.source_ip = row.findtext("source_ip", "")
            rec.count = int(row.findtext("count", "0"))

            policy_evaluated = row.find("policy_evaluated")
            if policy_evaluated is not None:
                rec.disposition = policy_evaluated.findtext("disposition", "")
                dkim_el = policy_evaluated.findtext("dkim", "")
                spf_el = policy_evaluated.findtext("spf", "")
                rec.dkim_aligned = dkim_el == "pass"
                rec.spf_aligned = spf_el == "pass"

        identifiers = record_el.find("identifiers")
        if identifiers is not None:
            rec.header_from = identifiers.findtext("header_from", "")
            rec.envelope_from = identifiers.findtext("envelope_from", "")

        auth_results = record_el.find("auth_results")
        if auth_results is not None:
            dkim_el = auth_results.find("dkim")
            if dkim_el is not None:
                rec.dkim_domain = dkim_el.findtext("domain", "")
                rec.dkim_result = dkim_el.findtext("result", "")

            spf_el = auth_results.find("spf")
            if spf_el is not None:
                rec.spf_domain = spf_el.findtext("domain", "")
                rec.spf_result = spf_el.findtext("result", "")

        summary.total_messages += rec.count
        if rec.dkim_aligned or rec.spf_aligned:
            summary.pass_count += rec.count
        else:
            summary.fail_count += rec.count
            failing_ips[rec.source_ip] += rec.count

        summary.records.append(rec)

    # Top failing IPs
    summary.top_failing_ips = sorted(
        failing_ips.items(), key=lambda x: x[1], reverse=True
    )[:20]

    return summary


def load_report_file(filepath: str) -> str:
    """Load a DMARC report file (handles .xml, .xml.gz, .zip)."""
    path = Path(filepath)

    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            return f.read()
    elif path.suffix == ".zip":
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name.endswith(".xml"):
                    with zf.open(name) as xf:
                        return xf.read().decode("utf-8", errors="replace")
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    return ""


def format_domain_check(domain: str, spf: SPFRecord, dkim_records: list,
                        dmarc: DMARCRecord) -> str:
    """Format domain authentication check results."""
    lines = []
    lines.append("=" * 70)
    lines.append(f"  EMAIL AUTHENTICATION CHECK: {domain}")
    lines.append("=" * 70)
    lines.append(f"  Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("")

    # SPF
    status = "PASS" if spf.valid else "ISSUES"
    lines.append(f"[SPF] {status}")
    lines.append(f"  Record: {spf.raw}")
    lines.append(f"  IP4 Ranges: {', '.join(spf.ip4_ranges) or 'none'}")
    lines.append(f"  Includes: {', '.join(spf.includes) or 'none'}")
    lines.append(f"  Qualifier: {spf.qualifier}")
    lines.append(f"  DNS Lookups: {spf.dns_lookup_count}/10")
    for err in spf.errors:
        lines.append(f"  WARNING: {err}")
    lines.append("")

    # DKIM
    if dkim_records:
        for dkim in dkim_records:
            status = "PASS" if dkim.valid else "ISSUES"
            lines.append(f"[DKIM] {status} (selector: {dkim.selector})")
            lines.append(f"  Key Type: {dkim.key_type}")
            lines.append(f"  Key Length: {dkim.key_length} bits")
            for err in dkim.errors:
                lines.append(f"  WARNING: {err}")
    else:
        lines.append("[DKIM] NO RECORDS FOUND")
        lines.append("  Checked selectors: selector1, selector2, google, default, s1, s2, dkim, mail")
    lines.append("")

    # DMARC
    status = "PASS" if dmarc.valid else "ISSUES"
    lines.append(f"[DMARC] {status}")
    lines.append(f"  Record: {dmarc.raw}")
    lines.append(f"  Policy: {dmarc.policy}")
    lines.append(f"  Subdomain Policy: {dmarc.subdomain_policy}")
    lines.append(f"  Percentage: {dmarc.pct}%")
    lines.append(f"  DKIM Alignment: {dmarc.adkim} ({'relaxed' if dmarc.adkim == 'r' else 'strict'})")
    lines.append(f"  SPF Alignment: {dmarc.aspf} ({'relaxed' if dmarc.aspf == 'r' else 'strict'})")
    lines.append(f"  Aggregate Reports: {', '.join(dmarc.rua) or 'not configured'}")
    lines.append(f"  Forensic Reports: {', '.join(dmarc.ruf) or 'not configured'}")
    for err in dmarc.errors:
        lines.append(f"  WARNING: {err}")
    lines.append("")

    # Overall assessment
    lines.append("-" * 70)
    all_valid = spf.valid and dmarc.valid and any(d.valid for d in dkim_records)
    if all_valid and dmarc.policy == "reject":
        lines.append("  OVERALL: STRONG - Full email authentication with reject policy")
    elif all_valid and dmarc.policy == "quarantine":
        lines.append("  OVERALL: GOOD - Full authentication, consider upgrading to reject")
    elif all_valid:
        lines.append("  OVERALL: MONITORING - Authentication configured but DMARC not enforcing")
    else:
        lines.append("  OVERALL: WEAK - Email authentication has gaps")
    lines.append("=" * 70)

    return "\n".join(lines)


def format_report_summary(summary: DMARCReportSummary) -> str:
    """Format DMARC report summary."""
    lines = []
    lines.append("=" * 70)
    lines.append("  DMARC AGGREGATE REPORT SUMMARY")
    lines.append("=" * 70)
    lines.append(f"  Reporting Org: {summary.org_name}")
    lines.append(f"  Report ID: {summary.report_id}")
    lines.append(f"  Period: {summary.date_begin} to {summary.date_end}")
    lines.append(f"  Domain: {summary.domain}")
    lines.append("")
    lines.append(f"  Total Messages: {summary.total_messages}")
    lines.append(f"  Passed: {summary.pass_count} ({summary.pass_count*100//max(summary.total_messages,1)}%)")
    lines.append(f"  Failed: {summary.fail_count} ({summary.fail_count*100//max(summary.total_messages,1)}%)")
    lines.append("")

    if summary.top_failing_ips:
        lines.append("[TOP FAILING SOURCE IPs]")
        for ip, count in summary.top_failing_ips[:10]:
            lines.append(f"  {ip}: {count} messages")
        lines.append("")

    lines.append("[DETAILED RECORDS]")
    for rec in summary.records[:50]:
        status = "PASS" if (rec.dkim_aligned or rec.spf_aligned) else "FAIL"
        lines.append(f"  {rec.source_ip} ({rec.count} msgs) - {status}")
        lines.append(f"    Disposition: {rec.disposition} | "
                     f"DKIM: {rec.dkim_result} ({rec.dkim_domain}) | "
                     f"SPF: {rec.spf_result} ({rec.spf_domain})")

    lines.append("=" * 70)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="DMARC/DKIM/SPF validator and DMARC report parser"
    )
    subparsers = parser.add_subparsers(dest="command")

    check_parser = subparsers.add_parser("check", help="Check domain authentication records")
    check_parser.add_argument("domain", help="Domain to check")
    check_parser.add_argument("--selectors", nargs="+", help="DKIM selectors to check")
    check_parser.add_argument("--json", action="store_true", help="Output as JSON")

    report_parser = subparsers.add_parser("report", help="Parse DMARC aggregate report")
    report_parser.add_argument("path", help="Path to XML report file or directory")
    report_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # Support legacy --check-domain and --parse-report flags
    parser.add_argument("--check-domain", help="Domain to check (legacy)")
    parser.add_argument("--parse-report", help="Report file to parse (legacy)")
    parser.add_argument("--parse-report-dir", help="Directory of reports (legacy)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    domain = getattr(args, "domain", None) or args.check_domain
    report_path = getattr(args, "path", None) or args.parse_report or args.parse_report_dir

    if domain:
        spf = check_spf(domain)
        dkim_records = check_dkim(domain, getattr(args, "selectors", None))
        dmarc = check_dmarc(domain)

        if args.json:
            result = {
                "domain": domain,
                "spf": asdict(spf),
                "dkim": [asdict(d) for d in dkim_records],
                "dmarc": asdict(dmarc),
            }
            print(json.dumps(result, indent=2))
        else:
            print(format_domain_check(domain, spf, dkim_records, dmarc))

    elif report_path:
        path = Path(report_path)
        if path.is_dir():
            for f in sorted(path.glob("*")):
                if f.suffix in (".xml", ".gz", ".zip"):
                    xml_content = load_report_file(str(f))
                    if xml_content:
                        summary = parse_dmarc_report(xml_content)
                        if args.json:
                            print(json.dumps(asdict(summary), indent=2, default=str))
                        else:
                            print(format_report_summary(summary))
                        print()
        else:
            xml_content = load_report_file(str(path))
            if xml_content:
                summary = parse_dmarc_report(xml_content)
                if args.json:
                    print(json.dumps(asdict(summary), indent=2, default=str))
                else:
                    print(format_report_summary(summary))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
