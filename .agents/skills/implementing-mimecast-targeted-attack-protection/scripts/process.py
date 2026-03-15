#!/usr/bin/env python3
"""
Mimecast TTP Policy Configuration Auditor

Audits Mimecast Targeted Threat Protection policy configuration
and generates compliance reports. Can also analyze Mimecast
TTP log exports for threat detection metrics.

Usage:
    python process.py audit-config --config-file mimecast_config.json
    python process.py analyze-logs --log-file ttp_logs.json
    python process.py vip-check --vip-file vip_list.json --email-json email.json
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from collections import defaultdict, Counter
from datetime import datetime


@dataclass
class PolicyAudit:
    """TTP policy configuration audit result."""
    url_protect_enabled: bool = False
    url_rewriting: bool = False
    url_predelivery_hold: bool = False
    attachment_protect_enabled: bool = False
    attachment_sandbox_mode: str = ""
    impersonation_protect_enabled: bool = False
    impersonation_vip_count: int = 0
    internal_email_protect: bool = False
    findings: list = field(default_factory=list)
    score: int = 0
    max_score: int = 100


@dataclass
class TTPMetrics:
    """TTP detection metrics from log analysis."""
    total_emails: int = 0
    url_threats_blocked: int = 0
    attachment_threats_blocked: int = 0
    impersonation_detected: int = 0
    internal_threats: int = 0
    top_threat_types: dict = field(default_factory=dict)
    top_targeted_users: list = field(default_factory=list)
    daily_stats: dict = field(default_factory=dict)


@dataclass
class ImpersonationCheck:
    """VIP impersonation check result."""
    from_display_name: str = ""
    from_email: str = ""
    matched_vip: str = ""
    indicators: list = field(default_factory=list)
    hit_count: int = 0
    is_impersonation: bool = False
    action: str = ""


REQUIRED_POLICIES = {
    "url_protect": {
        "enabled": True,
        "rewriting": True,
        "predelivery_hold": True,
        "weight": 25
    },
    "attachment_protect": {
        "enabled": True,
        "sandbox_mode": "dynamic",
        "weight": 25
    },
    "impersonation_protect": {
        "enabled": True,
        "min_vips": 5,
        "weight": 25
    },
    "internal_email_protect": {
        "enabled": True,
        "weight": 25
    }
}


def audit_config(config: dict) -> PolicyAudit:
    """Audit Mimecast TTP configuration against best practices."""
    audit = PolicyAudit()

    # Check URL Protect
    url_config = config.get("url_protect", {})
    audit.url_protect_enabled = url_config.get("enabled", False)
    audit.url_rewriting = url_config.get("rewriting", False)
    audit.url_predelivery_hold = url_config.get("predelivery_hold", False)

    if audit.url_protect_enabled:
        audit.score += 10
        if audit.url_rewriting:
            audit.score += 8
        else:
            audit.findings.append("URL rewriting not enabled - URLs not protected at click time")
        if audit.url_predelivery_hold:
            audit.score += 7
        else:
            audit.findings.append(
                "URL Pre-Delivery Hold not enabled - "
                "Mimecast recommends Hold setting (default since Nov 2025)"
            )
    else:
        audit.findings.append("CRITICAL: URL Protect not enabled")

    # Check Attachment Protect
    att_config = config.get("attachment_protect", {})
    audit.attachment_protect_enabled = att_config.get("enabled", False)
    audit.attachment_sandbox_mode = att_config.get("sandbox_mode", "none")

    if audit.attachment_protect_enabled:
        audit.score += 10
        if audit.attachment_sandbox_mode == "dynamic":
            audit.score += 15
        elif audit.attachment_sandbox_mode == "safe_file":
            audit.score += 10
            audit.findings.append(
                "Attachment Protect in Safe File mode - consider Dynamic for full sandbox"
            )
        else:
            audit.findings.append("Attachment sandbox mode not configured")
    else:
        audit.findings.append("CRITICAL: Attachment Protect not enabled")

    # Check Impersonation Protect
    imp_config = config.get("impersonation_protect", {})
    audit.impersonation_protect_enabled = imp_config.get("enabled", False)
    audit.impersonation_vip_count = len(imp_config.get("vip_list", []))

    if audit.impersonation_protect_enabled:
        audit.score += 10
        if audit.impersonation_vip_count >= 5:
            audit.score += 15
        elif audit.impersonation_vip_count > 0:
            audit.score += 8
            audit.findings.append(
                f"Only {audit.impersonation_vip_count} VIPs configured - "
                "recommend adding all executives and finance leadership"
            )
        else:
            audit.findings.append("No VIPs configured for Impersonation Protect")
    else:
        audit.findings.append("CRITICAL: Impersonation Protect not enabled")

    # Check Internal Email Protect
    int_config = config.get("internal_email_protect", {})
    audit.internal_email_protect = int_config.get("enabled", False)

    if audit.internal_email_protect:
        audit.score += 25
    else:
        audit.findings.append(
            "Internal Email Protect not enabled - "
            "lateral phishing from compromised accounts undetected"
        )

    return audit


def analyze_ttp_logs(logs: list) -> TTPMetrics:
    """Analyze Mimecast TTP logs for threat metrics."""
    metrics = TTPMetrics()
    threat_types = Counter()
    targeted_users = Counter()
    daily = defaultdict(lambda: {"total": 0, "threats": 0})

    for entry in logs:
        metrics.total_emails += 1
        date_str = entry.get("date", "unknown")
        daily[date_str]["total"] += 1

        category = entry.get("category", "").lower()
        if category in ("url_threat", "url_blocked"):
            metrics.url_threats_blocked += 1
            daily[date_str]["threats"] += 1
            threat_types["URL Threat"] += 1
        elif category in ("attachment_threat", "attachment_blocked"):
            metrics.attachment_threats_blocked += 1
            daily[date_str]["threats"] += 1
            threat_types["Attachment Threat"] += 1
        elif category in ("impersonation", "impersonation_detected"):
            metrics.impersonation_detected += 1
            daily[date_str]["threats"] += 1
            threat_types["Impersonation"] += 1
        elif category in ("internal_threat",):
            metrics.internal_threats += 1
            daily[date_str]["threats"] += 1
            threat_types["Internal Threat"] += 1

        recipient = entry.get("recipient", "")
        if recipient and category != "clean":
            targeted_users[recipient] += 1

    metrics.top_threat_types = dict(threat_types.most_common(10))
    metrics.top_targeted_users = [
        {"user": user, "threat_count": count}
        for user, count in targeted_users.most_common(10)
    ]
    metrics.daily_stats = dict(daily)

    return metrics


def check_impersonation(email_data: dict, vip_list: list) -> ImpersonationCheck:
    """Check if an email impersonates a VIP."""
    check = ImpersonationCheck()
    check.from_display_name = email_data.get("from_display_name", "")
    check.from_email = email_data.get("from", "")

    from_domain = ""
    match = re.search(r'@([\w.-]+)', check.from_email)
    if match:
        from_domain = match.group(1).lower()

    name_lower = check.from_display_name.lower()

    for vip in vip_list:
        vip_name = vip.get("name", "").lower()
        vip_domain = vip.get("domain", "").lower()

        # Check display name match
        if vip_name and vip_name in name_lower:
            check.indicators.append(f"Display name matches VIP: {vip.get('name')}")
            check.hit_count += 1
            check.matched_vip = vip.get("name", "")

            # Check domain mismatch
            if from_domain and vip_domain and from_domain != vip_domain:
                check.indicators.append(
                    f"Email domain ({from_domain}) differs from VIP domain ({vip_domain})"
                )
                check.hit_count += 1

        # Check domain similarity (lookalike)
        if vip_domain and from_domain:
            if _domain_similarity(from_domain, vip_domain) > 0.8 and from_domain != vip_domain:
                check.indicators.append(
                    f"Domain '{from_domain}' is visually similar to '{vip_domain}'"
                )
                check.hit_count += 1

    # Check reply-to mismatch
    reply_to = email_data.get("reply_to", "")
    if reply_to and reply_to != check.from_email:
        check.indicators.append("Reply-To differs from From address")
        check.hit_count += 1

    # Determine action
    if check.hit_count >= 3:
        check.is_impersonation = True
        check.action = "QUARANTINE (Hit 3 - Default policy)"
    elif check.hit_count >= 1 and check.matched_vip:
        check.is_impersonation = True
        check.action = "QUARANTINE (Hit 1 - VIP policy)"
    else:
        check.action = "DELIVER"

    return check


def _domain_similarity(d1: str, d2: str) -> float:
    """Calculate visual similarity between two domain names."""
    if d1 == d2:
        return 1.0
    longer = max(len(d1), len(d2))
    if longer == 0:
        return 0.0
    matches = sum(1 for a, b in zip(d1, d2) if a == b)
    return matches / longer


def main():
    parser = argparse.ArgumentParser(description="Mimecast TTP Auditor")
    subparsers = parser.add_subparsers(dest="command")

    audit_parser = subparsers.add_parser("audit-config", help="Audit TTP configuration")
    audit_parser.add_argument("--config-file", required=True)

    log_parser = subparsers.add_parser("analyze-logs", help="Analyze TTP logs")
    log_parser.add_argument("--log-file", required=True)

    vip_parser = subparsers.add_parser("vip-check", help="Check for VIP impersonation")
    vip_parser.add_argument("--vip-file", required=True)
    vip_parser.add_argument("--email-json", required=True)

    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.command == "audit-config":
        with open(args.config_file) as f:
            config = json.load(f)
        result = audit_config(config)
        if args.json:
            print(json.dumps(asdict(result), indent=2))
        else:
            print(f"TTP Configuration Score: {result.score}/{result.max_score}")
            print(f"URL Protect: {'Enabled' if result.url_protect_enabled else 'DISABLED'}")
            print(f"Attachment Protect: {'Enabled' if result.attachment_protect_enabled else 'DISABLED'}")
            print(f"Impersonation Protect: {'Enabled' if result.impersonation_protect_enabled else 'DISABLED'}")
            print(f"Internal Email Protect: {'Enabled' if result.internal_email_protect else 'DISABLED'}")
            if result.findings:
                print(f"\nFindings ({len(result.findings)}):")
                for i, f_item in enumerate(result.findings, 1):
                    print(f"  {i}. {f_item}")

    elif args.command == "analyze-logs":
        with open(args.log_file) as f:
            logs = json.load(f)
        result = analyze_ttp_logs(logs)
        if args.json:
            print(json.dumps(asdict(result), indent=2))
        else:
            print(f"Total emails: {result.total_emails}")
            print(f"URL threats: {result.url_threats_blocked}")
            print(f"Attachment threats: {result.attachment_threats_blocked}")
            print(f"Impersonation: {result.impersonation_detected}")
            print(f"Internal threats: {result.internal_threats}")

    elif args.command == "vip-check":
        with open(args.vip_file) as f:
            vip_list = json.load(f)
        with open(args.email_json) as f:
            email_data = json.load(f)
        result = check_impersonation(email_data, vip_list)
        if args.json:
            print(json.dumps(asdict(result), indent=2))
        else:
            print(f"From: {result.from_display_name} <{result.from_email}>")
            print(f"Matched VIP: {result.matched_vip or 'None'}")
            print(f"Hit Count: {result.hit_count}")
            print(f"Impersonation: {'YES' if result.is_impersonation else 'No'}")
            print(f"Action: {result.action}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
