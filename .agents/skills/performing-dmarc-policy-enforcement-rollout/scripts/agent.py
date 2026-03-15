#!/usr/bin/env python3
"""Agent for performing DMARC policy enforcement rollout with DNS record analysis."""

import json
import argparse
from datetime import datetime

try:
    import dns.resolver
except ImportError:
    dns = None


def check_dmarc(domain):
    """Query and parse DMARC record for a domain."""
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                return parse_dmarc_tags(txt, domain)
        return {"domain": domain, "dmarc_found": False}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception) as e:
        return {"domain": domain, "dmarc_found": False, "error": str(e)}


def parse_dmarc_tags(record, domain):
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip()] = v.strip()
    policy = tags.get("p", "none")
    findings = []
    if policy == "none":
        findings.append({"severity": "HIGH", "finding": "DMARC policy is 'none' — no enforcement"})
    elif policy == "quarantine":
        findings.append({"severity": "MEDIUM", "finding": "DMARC policy is 'quarantine' — partial enforcement"})
    if "rua" not in tags:
        findings.append({"severity": "MEDIUM", "finding": "No aggregate report URI (rua) configured"})
    pct = int(tags.get("pct", "100"))
    if pct < 100:
        findings.append({"severity": "INFO", "finding": f"Policy applied to {pct}% of messages"})
    sp = tags.get("sp", policy)
    if sp == "none" and policy != "none":
        findings.append({"severity": "MEDIUM", "finding": "Subdomain policy (sp) is 'none'"})
    return {
        "domain": domain, "dmarc_found": True, "record": record,
        "policy": policy, "subdomain_policy": sp, "percentage": pct,
        "rua": tags.get("rua"), "ruf": tags.get("ruf"),
        "adkim": tags.get("adkim", "r"), "aspf": tags.get("aspf", "r"),
        "findings": findings,
        "enforcement_level": "full" if policy == "reject" and pct == 100 else "partial" if policy != "none" else "none",
    }


def check_spf(domain):
    """Query and analyze SPF record."""
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                mechanisms = txt.split()
                qualifier = mechanisms[-1] if mechanisms else "~all"
                return {"domain": domain, "spf_found": True, "record": txt,
                        "mechanisms": mechanisms, "qualifier": qualifier,
                        "strict": qualifier == "-all"}
        return {"domain": domain, "spf_found": False}
    except Exception as e:
        return {"domain": domain, "spf_found": False, "error": str(e)}


def check_dkim(domain, selector="default"):
    """Query DKIM public key record."""
    try:
        fqdn = f"{selector}._domainkey.{domain}"
        answers = dns.resolver.resolve(fqdn, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if "p=" in txt:
                return {"domain": domain, "selector": selector, "dkim_found": True, "record": txt[:200]}
        return {"domain": domain, "selector": selector, "dkim_found": False}
    except Exception as e:
        return {"domain": domain, "selector": selector, "dkim_found": False, "error": str(e)}


def audit_domains(domains, selectors=None):
    """Audit multiple domains for DMARC/SPF/DKIM readiness."""
    selectors = selectors or ["default", "google", "selector1", "selector2", "k1"]
    results = []
    for domain in domains:
        domain = domain.strip()
        if not domain:
            continue
        dmarc = check_dmarc(domain)
        spf = check_spf(domain)
        dkim_results = []
        for sel in selectors:
            dkim = check_dkim(domain, sel)
            if dkim.get("dkim_found"):
                dkim_results.append(dkim)
        score = 0
        if dmarc.get("policy") == "reject":
            score += 40
        elif dmarc.get("policy") == "quarantine":
            score += 20
        if spf.get("strict"):
            score += 30
        elif spf.get("spf_found"):
            score += 15
        if dkim_results:
            score += 30
        results.append({
            "domain": domain, "dmarc": dmarc, "spf": spf,
            "dkim": dkim_results, "security_score": score,
        })
    return {"timestamp": datetime.utcnow().isoformat(), "domains": results}


def main():
    if not dns:
        print(json.dumps({"error": "dnspython not installed"}))
        return
    parser = argparse.ArgumentParser(description="DMARC Policy Enforcement Rollout Agent")
    sub = parser.add_subparsers(dest="command")
    d = sub.add_parser("check", help="Check single domain")
    d.add_argument("--domain", required=True)
    a = sub.add_parser("audit", help="Audit multiple domains")
    a.add_argument("--domains", nargs="+", required=True)
    a.add_argument("--selectors", nargs="*", default=None)
    args = parser.parse_args()
    if args.command == "check":
        result = {"dmarc": check_dmarc(args.domain), "spf": check_spf(args.domain)}
    elif args.command == "audit":
        result = audit_domains(args.domains, args.selectors)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
