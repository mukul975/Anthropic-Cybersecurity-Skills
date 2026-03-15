#!/usr/bin/env python3
"""
Business Email Compromise (BEC) Detection Engine

Analyzes emails for BEC indicators including executive impersonation,
financial urgency, payment change requests, and communication anomalies.

Usage:
    python process.py detect --email-json email.json
    python process.py analyze-log --log-file email_log.json
    python process.py vip-list --add "John CEO" --email "john@company.com"
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from collections import defaultdict


@dataclass
class BECIndicator:
    """A BEC detection indicator."""
    category: str = ""
    description: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    bec_type: str = ""


@dataclass
class BECAnalysis:
    """Complete BEC analysis result."""
    from_address: str = ""
    from_display_name: str = ""
    to_address: str = ""
    subject: str = ""
    indicators: list = field(default_factory=list)
    bec_score: float = 0.0
    bec_type: str = "unknown"
    is_bec: bool = False
    recommended_action: str = ""


# Financial keywords
FINANCIAL_KEYWORDS = [
    r'\bwire\s+transfer\b', r'\bbank\s+transfer\b', r'\bpayment\b',
    r'\binvoice\b', r'\bpurchase\s+order\b', r'\baccount\s+number\b',
    r'\brouting\s+number\b', r'\biban\b', r'\bswift\b', r'\back\b',
    r'\bgift\s+card\b', r'\bbitcoin\b', r'\bcrypto\b', r'\bvenmo\b',
    r'\bzelle\b', r'\bpaypal\b', r'\bw-2\b', r'\btax\s+form\b',
]

# Urgency keywords
URGENCY_KEYWORDS = [
    r'\burgent\b', r'\bimmediately\b', r'\basap\b', r'\btoday\b',
    r'\bright\s+now\b', r'\btime\s+sensitive\b', r'\bdo\s+not\s+(share|tell|discuss)\b',
    r'\bconfidential\b', r'\bkeep\s+this\s+between\b', r'\bquietly\b',
    r'\bbefore\s+end\s+of\s+day\b', r'\bcritical\b', r'\boverdue\b',
]

# Authority/impersonation keywords
AUTHORITY_KEYWORDS = [
    r'\bi\s+need\s+you\s+to\b', r'\bplease\s+handle\b',
    r'\bi\'m\s+in\s+a\s+meeting\b', r'\bi\'m\s+traveling\b',
    r'\bdon\'t\s+call\s+me\b', r'\bemail\s+me\s+back\b',
    r'\bcan\s+you\s+take\s+care\s+of\b', r'\bapproved\s+by\b',
]


def detect_bec(headers: dict, body: str = "", vip_list: list = None,
               internal_domains: list = None) -> BECAnalysis:
    """Analyze email for BEC indicators."""
    analysis = BECAnalysis()
    analysis.from_address = headers.get("from", "")
    analysis.from_display_name = headers.get("from_display_name", "")
    analysis.to_address = headers.get("to", "")
    analysis.subject = headers.get("subject", "")

    from_domain = ""
    match = re.search(r'@([\w.-]+)', analysis.from_address)
    if match:
        from_domain = match.group(1).lower()

    if internal_domains is None:
        internal_domains = []

    score = 0.0
    full_text = f"{analysis.subject} {body}".lower()

    # Check 1: VIP display name impersonation
    if vip_list and analysis.from_display_name:
        name_lower = analysis.from_display_name.lower()
        for vip in vip_list:
            vip_name = vip.get("name", "").lower()
            vip_domain = vip.get("domain", "").lower()
            if vip_name and vip_name in name_lower:
                if from_domain and vip_domain and from_domain != vip_domain:
                    analysis.indicators.append(BECIndicator(
                        category="vip_impersonation",
                        description=f"Display name '{analysis.from_display_name}' matches VIP "
                                    f"'{vip.get('name')}' but email is from external domain '{from_domain}'",
                        severity="critical",
                        confidence=0.9,
                        bec_type="ceo_fraud"
                    ))
                    score += 35

    # Check 2: Financial keywords
    financial_matches = []
    for pattern in FINANCIAL_KEYWORDS:
        if re.search(pattern, full_text, re.IGNORECASE):
            financial_matches.append(pattern)

    if financial_matches:
        analysis.indicators.append(BECIndicator(
            category="financial_language",
            description=f"Found {len(financial_matches)} financial keyword(s)",
            severity="medium",
            confidence=min(len(financial_matches) * 0.2, 0.8),
            bec_type="payment_fraud"
        ))
        score += min(len(financial_matches) * 5, 20)

    # Check 3: Urgency keywords
    urgency_matches = []
    for pattern in URGENCY_KEYWORDS:
        if re.search(pattern, full_text, re.IGNORECASE):
            urgency_matches.append(pattern)

    if urgency_matches:
        analysis.indicators.append(BECIndicator(
            category="urgency_language",
            description=f"Found {len(urgency_matches)} urgency/secrecy keyword(s)",
            severity="medium",
            confidence=min(len(urgency_matches) * 0.2, 0.8),
            bec_type="social_engineering"
        ))
        score += min(len(urgency_matches) * 5, 15)

    # Check 4: Combined financial + urgency = higher risk
    if financial_matches and urgency_matches:
        analysis.indicators.append(BECIndicator(
            category="combined_financial_urgency",
            description="Financial request combined with urgency/secrecy language - strong BEC signal",
            severity="high",
            confidence=0.8,
            bec_type="ceo_fraud"
        ))
        score += 20

    # Check 5: Authority language
    authority_matches = []
    for pattern in AUTHORITY_KEYWORDS:
        if re.search(pattern, full_text, re.IGNORECASE):
            authority_matches.append(pattern)

    if authority_matches and (financial_matches or urgency_matches):
        analysis.indicators.append(BECIndicator(
            category="authority_language",
            description="Authority/directive language combined with financial or urgency content",
            severity="high",
            confidence=0.7,
            bec_type="ceo_fraud"
        ))
        score += 15

    # Check 6: Reply-to mismatch
    reply_to = headers.get("reply_to", "")
    if reply_to:
        reply_domain = ""
        match = re.search(r'@([\w.-]+)', reply_to)
        if match:
            reply_domain = match.group(1).lower()
        if reply_domain and from_domain and reply_domain != from_domain:
            analysis.indicators.append(BECIndicator(
                category="reply_to_mismatch",
                description=f"Reply-To ({reply_domain}) differs from From ({from_domain})",
                severity="high",
                confidence=0.85,
                bec_type="account_compromise"
            ))
            score += 20

    # Check 7: External sender to finance/HR (if role info available)
    to_role = headers.get("to_role", "").lower()
    if from_domain and internal_domains and from_domain not in internal_domains:
        if any(r in to_role for r in ["finance", "accounting", "payroll", "hr", "human resources"]):
            analysis.indicators.append(BECIndicator(
                category="external_to_finance",
                description=f"External sender to {to_role} staff",
                severity="medium",
                confidence=0.5,
                bec_type="vendor_fraud"
            ))
            score += 10

    # Calculate final verdict
    analysis.bec_score = min(score, 100)
    if analysis.bec_score >= 60:
        analysis.is_bec = True
        analysis.recommended_action = "BLOCK and alert SOC"
    elif analysis.bec_score >= 40:
        analysis.is_bec = True
        analysis.recommended_action = "QUARANTINE for manual review"
    elif analysis.bec_score >= 20:
        analysis.recommended_action = "TAG with warning banner"
    else:
        analysis.recommended_action = "DELIVER normally"

    # Determine most likely BEC type
    type_scores = defaultdict(float)
    for ind in analysis.indicators:
        type_scores[ind.bec_type] += ind.confidence * 10
    if type_scores:
        analysis.bec_type = max(type_scores, key=type_scores.get)

    return analysis


def format_bec_report(analysis: BECAnalysis) -> str:
    """Format BEC analysis as text report."""
    lines = []
    lines.append("=" * 60)
    lines.append("  BUSINESS EMAIL COMPROMISE DETECTION REPORT")
    lines.append("=" * 60)
    lines.append(f"  BEC Score: {analysis.bec_score:.0f}/100")
    lines.append(f"  Verdict: {'BEC DETECTED' if analysis.is_bec else 'NOT DETECTED'}")
    lines.append(f"  BEC Type: {analysis.bec_type}")
    lines.append(f"  Action: {analysis.recommended_action}")
    lines.append("")
    lines.append(f"  From: {analysis.from_display_name} <{analysis.from_address}>")
    lines.append(f"  To: {analysis.to_address}")
    lines.append(f"  Subject: {analysis.subject}")
    lines.append("")

    if analysis.indicators:
        lines.append(f"[INDICATORS] ({len(analysis.indicators)})")
        for i, ind in enumerate(analysis.indicators, 1):
            lines.append(f"  {i}. [{ind.severity.upper()}] {ind.description}")
            lines.append(f"     Category: {ind.category} | Confidence: {ind.confidence:.0%}")
    lines.append("=" * 60)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="BEC Detection Engine")
    subparsers = parser.add_subparsers(dest="command")

    detect_parser = subparsers.add_parser("detect", help="Detect BEC in email")
    detect_parser.add_argument("--email-json", help="Email JSON file")
    detect_parser.add_argument("--from", dest="from_addr")
    detect_parser.add_argument("--from-name", default="")
    detect_parser.add_argument("--to", dest="to_addr", default="")
    detect_parser.add_argument("--subject", default="")
    detect_parser.add_argument("--body", default="")
    detect_parser.add_argument("--vip-file", help="VIP list JSON file")
    detect_parser.add_argument("--internal-domains", nargs="+", default=[])

    log_parser = subparsers.add_parser("analyze-log", help="Analyze email log for BEC")
    log_parser.add_argument("--log-file", required=True)
    log_parser.add_argument("--vip-file")
    log_parser.add_argument("--internal-domains", nargs="+", default=[])

    parser.add_argument("--json", action="store_true")

    args = parser.parse_args()

    vip_list = []
    vip_file = getattr(args, "vip_file", None)
    if vip_file:
        with open(vip_file) as f:
            vip_list = json.load(f)

    if args.command == "detect":
        if args.email_json:
            with open(args.email_json) as f:
                email_data = json.load(f)
            headers = email_data.get("headers", email_data)
            body = email_data.get("body", "")
        else:
            headers = {
                "from": args.from_addr or "",
                "from_display_name": args.from_name,
                "to": args.to_addr,
                "subject": args.subject,
            }
            body = args.body

        analysis = detect_bec(headers, body, vip_list,
                              getattr(args, "internal_domains", []))
        if args.json:
            print(json.dumps(asdict(analysis), indent=2, default=str))
        else:
            print(format_bec_report(analysis))

    elif args.command == "analyze-log":
        with open(args.log_file) as f:
            log = json.load(f)

        bec_count = 0
        for entry in log:
            analysis = detect_bec(
                entry.get("headers", entry),
                entry.get("body", ""),
                vip_list,
                getattr(args, "internal_domains", [])
            )
            if analysis.is_bec:
                bec_count += 1
                if args.json:
                    print(json.dumps(asdict(analysis), indent=2, default=str))
                else:
                    print(format_bec_report(analysis))
                print()

        print(f"\nTotal analyzed: {len(log)}, BEC detected: {bec_count}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
