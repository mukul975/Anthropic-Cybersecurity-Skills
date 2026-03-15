#!/usr/bin/env python3
"""
Spearphishing Detection Engine for Email Gateway Logs

Analyzes email gateway logs to detect spearphishing patterns including
impersonation, lookalike domains, and behavioral anomalies. Generates
custom detection rules and threat reports.

Usage:
    python process.py analyze --log-file gateway_log.json
    python process.py detect --email-file email.eml
    python process.py rules --output detection_rules.yaml
"""

import argparse
import json
import re
import sys
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from collections import defaultdict

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class SpearphishingIndicator:
    """A detected spearphishing indicator."""
    indicator_type: str = ""
    description: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    raw_value: str = ""
    mitre_technique: str = ""


@dataclass
class DomainSimilarity:
    """Domain similarity analysis result."""
    original_domain: str = ""
    suspicious_domain: str = ""
    distance: int = 0
    technique: str = ""
    confidence: float = 0.0


@dataclass
class EmailAnalysis:
    """Complete spearphishing analysis for a single email."""
    message_id: str = ""
    from_address: str = ""
    from_display_name: str = ""
    from_domain: str = ""
    to_address: str = ""
    subject: str = ""
    date: str = ""
    indicators: list = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "low"
    domain_similarities: list = field(default_factory=list)
    is_spearphishing: bool = False


# VIP list for impersonation detection (configure per organization)
DEFAULT_VIP_NAMES = [
    "CEO", "CFO", "CTO", "CISO", "COO",
    "Chief Executive", "Chief Financial", "Chief Technology",
    "President", "Vice President", "Director",
]

# Common urgency keywords in spearphishing
URGENCY_KEYWORDS = [
    r'\burgent\b', r'\bimmediately\b', r'\basap\b', r'\btime.?sensitive\b',
    r'\bwire\s+transfer\b', r'\bbank\s+transfer\b', r'\bgift\s+card\b',
    r'\bconfidential\b', r'\bdo\s+not\s+share\b', r'\bsecret\b',
    r'\bpayment\b', r'\binvoice\b', r'\boverdue\b', r'\bfinal\s+notice\b',
    r'\baccount\s+suspen', r'\bverify\s+your\b', r'\bconfirm\s+your\b',
    r'\bunusual\s+activity\b', r'\bsecurity\s+alert\b',
]

# Legitimate domains for similarity comparison
COMMON_TARGETS = [
    "microsoft.com", "google.com", "apple.com", "amazon.com",
    "paypal.com", "netflix.com", "linkedin.com", "facebook.com",
    "dropbox.com", "docusign.com", "zoom.us", "slack.com",
    "office365.com", "outlook.com", "gmail.com",
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def detect_homograph(domain: str) -> list:
    """Detect IDN homograph attacks in domain names."""
    homograph_map = {
        'a': ['@', 'а', 'ɑ'],   # Cyrillic а, Latin alpha
        'e': ['е', 'ё', 'э'],   # Cyrillic variants
        'o': ['о', '0', 'ο'],   # Cyrillic о, zero, Greek omicron
        'p': ['р', 'ρ'],        # Cyrillic р, Greek rho
        'c': ['с', 'ç'],        # Cyrillic с
        'x': ['х', 'χ'],        # Cyrillic х, Greek chi
        'y': ['у', 'γ'],        # Cyrillic у
        'i': ['і', 'і', '1', 'l'],
    }
    findings = []
    for i, char in enumerate(domain):
        for latin, lookalikes in homograph_map.items():
            if char in lookalikes:
                findings.append({
                    "position": i,
                    "character": char,
                    "looks_like": latin,
                    "type": "homograph"
                })
    return findings


def check_domain_similarity(domain: str, known_domains: list = None) -> list:
    """Check if a domain is similar to known legitimate domains."""
    if known_domains is None:
        known_domains = COMMON_TARGETS

    similarities = []
    domain_base = domain.split(".")[0] if "." in domain else domain

    for known in known_domains:
        known_base = known.split(".")[0]
        dist = levenshtein_distance(domain_base.lower(), known_base.lower())

        if 0 < dist <= 2:
            technique = "typosquatting"
            if len(domain_base) != len(known_base):
                technique = "character_addition" if len(domain_base) > len(known_base) else "character_omission"
            elif dist == 1:
                for i, (a, b) in enumerate(zip(domain_base, known_base)):
                    if a != b:
                        if i > 0 and domain_base[i-1:i+1] == known_base[i:i-2:-1] if i > 0 else False:
                            technique = "transposition"
                        break

            confidence = max(0, 1.0 - dist * 0.3)
            similarities.append(DomainSimilarity(
                original_domain=known,
                suspicious_domain=domain,
                distance=dist,
                technique=technique,
                confidence=confidence
            ))

    # Check for homographs
    homographs = detect_homograph(domain)
    if homographs:
        similarities.append(DomainSimilarity(
            original_domain="(homograph detection)",
            suspicious_domain=domain,
            distance=0,
            technique="homograph",
            confidence=0.9
        ))

    return sorted(similarities, key=lambda x: x.distance)


def detect_urgency(text: str) -> list:
    """Detect urgency patterns in email text."""
    findings = []
    text_lower = text.lower()
    for pattern in URGENCY_KEYWORDS:
        matches = re.findall(pattern, text_lower, re.IGNORECASE)
        if matches:
            findings.append({
                "pattern": pattern,
                "matches": matches,
                "count": len(matches)
            })
    return findings


def detect_impersonation(display_name: str, vip_names: list = None) -> list:
    """Check if display name impersonates a VIP."""
    if vip_names is None:
        vip_names = DEFAULT_VIP_NAMES

    findings = []
    name_lower = display_name.lower()

    for vip in vip_names:
        if vip.lower() in name_lower:
            findings.append({
                "matched_vip": vip,
                "display_name": display_name,
                "confidence": 0.8
            })

    return findings


def analyze_email(headers: dict, body: str = "",
                  vip_names: list = None,
                  known_domains: list = None) -> EmailAnalysis:
    """Analyze a single email for spearphishing indicators."""
    analysis = EmailAnalysis()

    analysis.from_address = headers.get("from", "")
    analysis.from_display_name = headers.get("from_display_name", "")
    analysis.from_domain = headers.get("from_domain", "")
    analysis.to_address = headers.get("to", "")
    analysis.subject = headers.get("subject", "")
    analysis.date = headers.get("date", "")
    analysis.message_id = headers.get("message_id", "")

    # Extract domain from from_address if not provided
    if not analysis.from_domain and analysis.from_address:
        match = re.search(r'@([\w.-]+)', analysis.from_address)
        if match:
            analysis.from_domain = match.group(1).lower()

    # Extract display name if not provided
    if not analysis.from_display_name and analysis.from_address:
        match = re.match(r'"?([^"<]+)"?\s*<', analysis.from_address)
        if match:
            analysis.from_display_name = match.group(1).strip()

    score = 0.0

    # Check 1: Domain similarity
    if analysis.from_domain:
        similarities = check_domain_similarity(analysis.from_domain, known_domains)
        analysis.domain_similarities = similarities
        for sim in similarities:
            if sim.distance <= 1:
                analysis.indicators.append(SpearphishingIndicator(
                    indicator_type="lookalike_domain",
                    description=f"Domain '{sim.suspicious_domain}' is {sim.distance} edit(s) "
                                f"from '{sim.original_domain}' ({sim.technique})",
                    severity="critical" if sim.distance == 1 else "high",
                    confidence=sim.confidence,
                    raw_value=sim.suspicious_domain,
                    mitre_technique="T1566.002"
                ))
                score += 30 * sim.confidence
            elif sim.distance == 2:
                analysis.indicators.append(SpearphishingIndicator(
                    indicator_type="similar_domain",
                    description=f"Domain '{sim.suspicious_domain}' resembles "
                                f"'{sim.original_domain}' (distance={sim.distance})",
                    severity="medium",
                    confidence=sim.confidence,
                    raw_value=sim.suspicious_domain,
                    mitre_technique="T1566.002"
                ))
                score += 15 * sim.confidence

    # Check 2: VIP impersonation
    if analysis.from_display_name:
        impersonations = detect_impersonation(analysis.from_display_name, vip_names)
        for imp in impersonations:
            analysis.indicators.append(SpearphishingIndicator(
                indicator_type="vip_impersonation",
                description=f"Display name '{imp['display_name']}' matches VIP "
                            f"keyword '{imp['matched_vip']}'",
                severity="high",
                confidence=imp["confidence"],
                raw_value=analysis.from_display_name,
                mitre_technique="T1566.001"
            ))
            score += 25 * imp["confidence"]

    # Check 3: Urgency indicators in subject
    urgency_subject = detect_urgency(analysis.subject)
    if urgency_subject:
        analysis.indicators.append(SpearphishingIndicator(
            indicator_type="urgency_subject",
            description=f"Subject contains {len(urgency_subject)} urgency pattern(s)",
            severity="medium",
            confidence=min(len(urgency_subject) * 0.3, 0.9),
            raw_value=analysis.subject,
            mitre_technique="T1566"
        ))
        score += min(len(urgency_subject) * 5, 20)

    # Check 4: Urgency indicators in body
    if body:
        urgency_body = detect_urgency(body)
        if urgency_body:
            total_matches = sum(u["count"] for u in urgency_body)
            analysis.indicators.append(SpearphishingIndicator(
                indicator_type="urgency_body",
                description=f"Body contains {total_matches} urgency keyword(s) "
                            f"across {len(urgency_body)} pattern(s)",
                severity="medium",
                confidence=min(total_matches * 0.15, 0.9),
                raw_value=f"{total_matches} matches",
                mitre_technique="T1566"
            ))
            score += min(total_matches * 3, 15)

    # Check 5: Authentication failures
    auth_results = headers.get("authentication_results", "")
    if auth_results:
        if "spf=fail" in auth_results.lower() or "spf=softfail" in auth_results.lower():
            analysis.indicators.append(SpearphishingIndicator(
                indicator_type="spf_failure",
                description="SPF authentication failed",
                severity="high",
                confidence=0.7,
                raw_value=auth_results,
                mitre_technique="T1566"
            ))
            score += 20

        if "dkim=fail" in auth_results.lower():
            analysis.indicators.append(SpearphishingIndicator(
                indicator_type="dkim_failure",
                description="DKIM authentication failed",
                severity="high",
                confidence=0.7,
                raw_value=auth_results,
                mitre_technique="T1566"
            ))
            score += 20

        if "dmarc=fail" in auth_results.lower():
            analysis.indicators.append(SpearphishingIndicator(
                indicator_type="dmarc_failure",
                description="DMARC authentication failed",
                severity="critical",
                confidence=0.8,
                raw_value=auth_results,
                mitre_technique="T1566"
            ))
            score += 25

    # Check 6: Reply-to mismatch
    reply_to = headers.get("reply_to", "")
    if reply_to and analysis.from_address:
        reply_domain = ""
        match = re.search(r'@([\w.-]+)', reply_to)
        if match:
            reply_domain = match.group(1).lower()
        if reply_domain and reply_domain != analysis.from_domain:
            analysis.indicators.append(SpearphishingIndicator(
                indicator_type="reply_to_mismatch",
                description=f"Reply-To domain ({reply_domain}) differs from "
                            f"From domain ({analysis.from_domain})",
                severity="high",
                confidence=0.85,
                raw_value=f"From: {analysis.from_domain}, Reply-To: {reply_domain}",
                mitre_technique="T1566"
            ))
            score += 20

    # Calculate final risk
    analysis.risk_score = min(score, 100)
    if analysis.risk_score >= 70:
        analysis.risk_level = "critical"
        analysis.is_spearphishing = True
    elif analysis.risk_score >= 50:
        analysis.risk_level = "high"
        analysis.is_spearphishing = True
    elif analysis.risk_score >= 30:
        analysis.risk_level = "medium"
    elif analysis.risk_score >= 10:
        analysis.risk_level = "low"
    else:
        analysis.risk_level = "clean"

    return analysis


def generate_detection_rules(indicators_db: list) -> str:
    """Generate YAML detection rules from accumulated indicators."""
    rules = []

    # Group by indicator type
    by_type = defaultdict(list)
    for ind in indicators_db:
        by_type[ind["indicator_type"]].append(ind)

    rule_id = 1
    for ind_type, indicators in by_type.items():
        values = list(set(ind.get("raw_value", "") for ind in indicators if ind.get("raw_value")))
        if not values:
            continue

        rule = {
            "id": f"SPEAR-{rule_id:04d}",
            "name": f"Spearphishing {ind_type.replace('_', ' ').title()} Detection",
            "type": ind_type,
            "severity": indicators[0].get("severity", "medium"),
            "mitre": indicators[0].get("mitre_technique", "T1566"),
            "description": indicators[0].get("description", ""),
            "action": "quarantine" if indicators[0].get("severity") in ("high", "critical") else "tag",
            "values_count": len(values),
            "sample_values": values[:5]
        }
        rules.append(rule)
        rule_id += 1

    # Format as YAML-like output
    output_lines = ["# Auto-generated Spearphishing Detection Rules",
                    f"# Generated: {datetime.now(timezone.utc).isoformat()}",
                    f"# Total rules: {len(rules)}", ""]

    for rule in rules:
        output_lines.append(f"- id: {rule['id']}")
        output_lines.append(f"  name: \"{rule['name']}\"")
        output_lines.append(f"  type: {rule['type']}")
        output_lines.append(f"  severity: {rule['severity']}")
        output_lines.append(f"  mitre: {rule['mitre']}")
        output_lines.append(f"  action: {rule['action']}")
        output_lines.append(f"  indicators_count: {rule['values_count']}")
        output_lines.append(f"  sample_values:")
        for val in rule["sample_values"]:
            output_lines.append(f"    - \"{val}\"")
        output_lines.append("")

    return "\n".join(output_lines)


def format_analysis_report(analysis: EmailAnalysis) -> str:
    """Format analysis as text report."""
    lines = []
    lines.append("=" * 60)
    lines.append("  SPEARPHISHING DETECTION REPORT")
    lines.append("=" * 60)
    lines.append(f"  Risk Level: {analysis.risk_level.upper()} "
                 f"(Score: {analysis.risk_score:.0f}/100)")
    lines.append(f"  Verdict: {'SPEARPHISHING DETECTED' if analysis.is_spearphishing else 'NOT DETECTED'}")
    lines.append("")
    lines.append(f"  From: {analysis.from_display_name} <{analysis.from_address}>")
    lines.append(f"  To: {analysis.to_address}")
    lines.append(f"  Subject: {analysis.subject}")
    lines.append(f"  Date: {analysis.date}")
    lines.append("")

    if analysis.indicators:
        lines.append(f"[INDICATORS] ({len(analysis.indicators)} found)")
        for i, ind in enumerate(analysis.indicators, 1):
            lines.append(f"  {i}. [{ind.severity.upper()}] {ind.description}")
            lines.append(f"     Type: {ind.indicator_type} | "
                         f"MITRE: {ind.mitre_technique} | "
                         f"Confidence: {ind.confidence:.0%}")
    else:
        lines.append("[INDICATORS] None found")

    if analysis.domain_similarities:
        lines.append(f"\n[DOMAIN ANALYSIS]")
        for sim in analysis.domain_similarities:
            lines.append(f"  {sim.suspicious_domain} ~ {sim.original_domain} "
                         f"(distance={sim.distance}, technique={sim.technique})")

    lines.append("=" * 60)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Spearphishing Detection Engine")
    subparsers = parser.add_subparsers(dest="command")

    analyze_parser = subparsers.add_parser("analyze", help="Analyze gateway log file")
    analyze_parser.add_argument("--log-file", required=True, help="JSON log file")
    analyze_parser.add_argument("--output", "-o", help="Output file")

    detect_parser = subparsers.add_parser("detect", help="Detect spearphishing in single email")
    detect_parser.add_argument("--from", dest="from_addr", required=True)
    detect_parser.add_argument("--from-name", default="")
    detect_parser.add_argument("--to", dest="to_addr", default="")
    detect_parser.add_argument("--subject", default="")
    detect_parser.add_argument("--body", default="")
    detect_parser.add_argument("--auth-results", default="")

    domain_parser = subparsers.add_parser("check-domain", help="Check domain similarity")
    domain_parser.add_argument("domain", help="Domain to check")

    rules_parser = subparsers.add_parser("rules", help="Generate detection rules from log")
    rules_parser.add_argument("--log-file", required=True)
    rules_parser.add_argument("--output", "-o", help="Output rules file")

    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    if args.command == "analyze":
        with open(args.log_file, "r") as f:
            log_entries = json.load(f)

        results = []
        for entry in log_entries:
            headers = entry.get("headers", entry)
            body = entry.get("body", "")
            analysis = analyze_email(headers, body)
            results.append(analysis)

        spearphishing_count = sum(1 for r in results if r.is_spearphishing)
        print(f"Analyzed {len(results)} emails, detected {spearphishing_count} spearphishing attempts")
        print()

        for analysis in results:
            if analysis.is_spearphishing:
                if args.json:
                    print(json.dumps(asdict(analysis), indent=2, default=str))
                else:
                    print(format_analysis_report(analysis))
                print()

    elif args.command == "detect":
        headers = {
            "from": args.from_addr,
            "from_display_name": args.from_name,
            "to": args.to_addr,
            "subject": args.subject,
            "authentication_results": args.auth_results,
        }
        analysis = analyze_email(headers, args.body)
        if args.json:
            print(json.dumps(asdict(analysis), indent=2, default=str))
        else:
            print(format_analysis_report(analysis))

    elif args.command == "check-domain":
        similarities = check_domain_similarity(args.domain)
        if similarities:
            print(f"Domain '{args.domain}' is similar to:")
            for sim in similarities:
                print(f"  - {sim.original_domain} (distance={sim.distance}, "
                      f"technique={sim.technique}, confidence={sim.confidence:.0%})")
        else:
            print(f"Domain '{args.domain}' has no known similarities")

    elif args.command == "rules":
        with open(args.log_file, "r") as f:
            log_entries = json.load(f)

        all_indicators = []
        for entry in log_entries:
            analysis = analyze_email(entry.get("headers", entry), entry.get("body", ""))
            for ind in analysis.indicators:
                all_indicators.append(asdict(ind))

        rules = generate_detection_rules(all_indicators)
        if args.output:
            with open(args.output, "w") as f:
                f.write(rules)
            print(f"Rules written to {args.output}")
        else:
            print(rules)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
