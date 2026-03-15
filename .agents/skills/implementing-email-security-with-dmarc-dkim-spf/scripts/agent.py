#!/usr/bin/env python3
"""Email Security Audit Agent - Validates SPF, DKIM, and DMARC DNS records for domains."""

import json
import re
import logging
import argparse
from datetime import datetime

import dns.resolver

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2",
    "mail", "dkim", "s1", "s2", "mandrill", "everlytickey1",
    "smtpapi", "pic", "protonmail", "protonmail2", "protonmail3",
]


def query_txt_records(domain, prefix=""):
    """Query TXT DNS records for a domain."""
    fqdn = f"{prefix}.{domain}" if prefix else domain
    try:
        answers = dns.resolver.resolve(fqdn, "TXT")
        records = []
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            records.append(txt)
        return records
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def check_spf(domain):
    """Check and validate SPF record."""
    records = query_txt_records(domain)
    spf_records = [r for r in records if r.startswith("v=spf1")]

    if not spf_records:
        return {"status": "missing", "severity": "critical", "issues": ["No SPF record found"], "record": None}

    if len(spf_records) > 1:
        issues = ["Multiple SPF records found (RFC violation, causes permerror)"]
    else:
        issues = []

    spf = spf_records[0]
    mechanisms = spf.split()
    include_count = sum(1 for m in mechanisms if m.startswith("include:"))
    has_all = any(m in ("~all", "-all", "+all", "?all") for m in mechanisms)

    if "+all" in mechanisms:
        issues.append("SPF uses +all (allows any sender - completely open)")
        severity = "critical"
    elif "?all" in mechanisms:
        issues.append("SPF uses ?all (neutral - no protection)")
        severity = "high"
    elif "~all" in mechanisms:
        issues.append("SPF uses ~all (softfail - mail accepted but marked)")
        severity = "medium"
    elif "-all" in mechanisms:
        severity = "low"
    elif not has_all:
        issues.append("SPF record missing -all qualifier")
        severity = "high"
    else:
        severity = "low"

    if include_count > 10:
        issues.append(f"SPF has {include_count} includes (>10 DNS lookups causes permerror)")
        severity = "high"

    lookup_mechanisms = sum(1 for m in mechanisms if any(m.startswith(p) for p in ("include:", "a:", "mx:", "ptr:", "exists:", "redirect=")))
    if lookup_mechanisms > 10:
        issues.append(f"SPF exceeds 10 DNS lookup limit ({lookup_mechanisms} lookups)")

    return {
        "status": "found",
        "record": spf,
        "mechanism_count": len(mechanisms),
        "include_count": include_count,
        "dns_lookups": lookup_mechanisms,
        "qualifier": next((m for m in mechanisms if m.endswith("all")), "none"),
        "severity": severity,
        "issues": issues,
    }


def check_dkim(domain, selectors=None):
    """Check DKIM records for common selectors."""
    if selectors is None:
        selectors = DKIM_SELECTORS

    found_selectors = []
    for selector in selectors:
        records = query_txt_records(domain, prefix=f"{selector}._domainkey")
        dkim_records = [r for r in records if "v=DKIM1" in r or "k=rsa" in r or "p=" in r]
        if dkim_records:
            record = dkim_records[0]
            key_match = re.search(r"p=([A-Za-z0-9+/=]+)", record)
            key_length = len(key_match.group(1)) * 6 // 8 if key_match else 0
            issues = []
            if key_length and key_length < 128:
                issues.append(f"DKIM key too short ({key_length} bytes, minimum 1024 bits recommended)")
            if "p=" in record and not key_match:
                issues.append("DKIM public key appears empty (revoked)")
            found_selectors.append({
                "selector": selector,
                "record": record[:200],
                "key_size_bytes": key_length,
                "issues": issues,
            })

    if not found_selectors:
        return {
            "status": "not_found",
            "severity": "high",
            "issues": ["No DKIM records found for any common selector"],
            "selectors_checked": len(selectors),
            "selectors_found": [],
        }

    return {
        "status": "found",
        "severity": "low",
        "selectors_checked": len(selectors),
        "selectors_found": found_selectors,
        "issues": [i for s in found_selectors for i in s["issues"]],
    }


def check_dmarc(domain):
    """Check and validate DMARC record."""
    records = query_txt_records(domain, prefix="_dmarc")
    dmarc_records = [r for r in records if r.startswith("v=DMARC1")]

    if not dmarc_records:
        return {"status": "missing", "severity": "critical", "issues": ["No DMARC record found"], "record": None}

    dmarc = dmarc_records[0]
    tags = {}
    for part in dmarc.split(";"):
        part = part.strip()
        if "=" in part:
            key, val = part.split("=", 1)
            tags[key.strip()] = val.strip()

    issues = []
    policy = tags.get("p", "none")
    subdomain_policy = tags.get("sp", policy)
    pct = int(tags.get("pct", "100"))
    rua = tags.get("rua", "")
    ruf = tags.get("ruf", "")
    adkim = tags.get("adkim", "r")
    aspf = tags.get("aspf", "r")

    if policy == "none":
        issues.append("DMARC policy is 'none' - no enforcement (monitoring only)")
        severity = "high"
    elif policy == "quarantine":
        severity = "medium" if pct < 100 else "low"
        if pct < 100:
            issues.append(f"DMARC only applied to {pct}% of messages")
    elif policy == "reject":
        severity = "low"
        if pct < 100:
            issues.append(f"DMARC reject only applied to {pct}% of messages")
            severity = "medium"
    else:
        severity = "high"
        issues.append(f"Unknown DMARC policy: {policy}")

    if not rua:
        issues.append("No aggregate report URI (rua) configured")
    if not ruf:
        issues.append("No forensic report URI (ruf) configured")
    if adkim == "r":
        issues.append("DKIM alignment is relaxed (adkim=r)")
    if aspf == "r":
        issues.append("SPF alignment is relaxed (aspf=r)")

    return {
        "status": "found",
        "record": dmarc,
        "policy": policy,
        "subdomain_policy": subdomain_policy,
        "percentage": pct,
        "aggregate_report": rua,
        "forensic_report": ruf,
        "dkim_alignment": adkim,
        "spf_alignment": aspf,
        "severity": severity,
        "issues": issues,
    }


def compute_risk_score(spf, dkim, dmarc):
    """Compute overall email security risk score."""
    severity_scores = {"critical": 40, "high": 25, "medium": 10, "low": 0}
    score = 0
    score += severity_scores.get(spf["severity"], 0)
    score += severity_scores.get(dkim["severity"], 0)
    score += severity_scores.get(dmarc["severity"], 0)

    if spf["status"] == "missing":
        score += 20
    if dmarc.get("policy") == "none":
        score += 15

    if score >= 60:
        risk = "CRITICAL"
    elif score >= 35:
        risk = "HIGH"
    elif score >= 15:
        risk = "MEDIUM"
    else:
        risk = "LOW"
    return {"score": score, "risk_level": risk}


def generate_report(domain, spf, dkim, dmarc, risk):
    """Generate email security audit report."""
    all_issues = spf.get("issues", []) + dkim.get("issues", []) + dmarc.get("issues", [])
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "domain": domain,
        "risk_assessment": risk,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "total_issues": len(all_issues),
        "all_issues": all_issues,
    }
    print(f"EMAIL SECURITY [{domain}]: Risk={risk['risk_level']} Score={risk['score']} Issues={len(all_issues)}")
    return report


def main():
    parser = argparse.ArgumentParser(description="Email Security Audit Agent (SPF/DKIM/DMARC)")
    parser.add_argument("--domain", required=True, help="Domain to audit")
    parser.add_argument("--dkim-selectors", nargs="*", help="Custom DKIM selectors to check")
    parser.add_argument("--output", default="email_security_report.json")
    args = parser.parse_args()

    spf = check_spf(args.domain)
    logger.info("SPF: %s (severity: %s)", spf["status"], spf["severity"])

    dkim = check_dkim(args.domain, args.dkim_selectors)
    logger.info("DKIM: %s (%d selectors found)", dkim["status"], len(dkim.get("selectors_found", [])))

    dmarc = check_dmarc(args.domain)
    logger.info("DMARC: %s (severity: %s)", dmarc["status"], dmarc["severity"])

    risk = compute_risk_score(spf, dkim, dmarc)
    report = generate_report(args.domain, spf, dkim, dmarc, risk)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
