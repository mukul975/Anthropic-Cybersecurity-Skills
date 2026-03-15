#!/usr/bin/env python3
"""Email Account Compromise Detection agent - analyzes inbox rules, sign-in logs, and OAuth grants to detect O365/Google Workspace account compromise"""

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

SUSPICIOUS_UA_PATTERNS = [
    "python-requests", "python-urllib", "curl", "wget", "powershell",
    "go-http-client", "httpie", "postman", "insomnia",
]

FINANCIAL_KEYWORDS = [
    "invoice", "payment", "wire", "transfer", "bank", "account",
    "payroll", "salary", "remittance", "ach", "swift",
]


def load_data(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371.0
    rlat1, rlat2 = math.radians(lat1), math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(rlat1) * math.cos(rlat2) * math.sin(dlon / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def analyze_inbox_rules(rules):
    """Detect malicious inbox rules: external forwarding, deletion rules, keyword-based filters."""
    findings = []
    for rule in rules:
        user = rule.get("user", rule.get("mailbox", ""))
        rule_name = rule.get("displayName", rule.get("name", ""))
        actions = rule.get("actions", {})
        forward_to = actions.get("forwardTo", []) or actions.get("forward_to", [])
        redirect_to = actions.get("redirectTo", []) or actions.get("redirect_to", [])
        delete_msg = actions.get("delete", False) or actions.get("moveToDeletedItems", False)
        move_to = actions.get("moveToFolder", "") or ""
        conditions = rule.get("conditions", {})
        subject_contains = conditions.get("subjectContains", []) or []
        body_contains = conditions.get("bodyContains", []) or []
        for dest in forward_to + redirect_to:
            addr = dest.get("emailAddress", {}).get("address", dest) if isinstance(dest, dict) else str(dest)
            domain = addr.split("@")[-1] if "@" in str(addr) else ""
            user_domain = user.split("@")[-1] if "@" in user else ""
            if domain and domain != user_domain:
                findings.append({
                    "type": "external_forwarding_rule",
                    "severity": "critical",
                    "resource": user,
                    "detail": f"Rule '{rule_name}' forwards to external address: {addr}",
                })
        if delete_msg:
            findings.append({
                "type": "deletion_rule",
                "severity": "high",
                "resource": user,
                "detail": f"Rule '{rule_name}' auto-deletes messages",
            })
        keyword_hits = [kw for kw in FINANCIAL_KEYWORDS
                        if any(kw in s.lower() for s in subject_contains + body_contains)]
        if keyword_hits:
            findings.append({
                "type": "financial_keyword_filter",
                "severity": "high",
                "resource": user,
                "detail": f"Rule '{rule_name}' targets financial keywords: {', '.join(keyword_hits)}",
            })
    return findings


def analyze_sign_ins(sign_ins):
    """Detect impossible travel, suspicious user agents, and risky sign-in patterns."""
    findings = []
    user_logins = defaultdict(list)
    for si in sign_ins:
        user = si.get("userPrincipalName", si.get("user", ""))
        ua = si.get("userAgent", si.get("user_agent", ""))
        ip = si.get("ipAddress", si.get("ip", ""))
        ts = si.get("createdDateTime", si.get("timestamp", ""))
        lat = si.get("location", {}).get("geoCoordinates", {}).get("latitude", 0)
        lon = si.get("location", {}).get("geoCoordinates", {}).get("longitude", 0)
        country = si.get("location", {}).get("countryOrRegion", "")
        risk = si.get("riskLevelAggregated", si.get("risk_level", "none"))
        for pattern in SUSPICIOUS_UA_PATTERNS:
            if pattern.lower() in (ua or "").lower():
                findings.append({
                    "type": "suspicious_user_agent",
                    "severity": "high",
                    "resource": user,
                    "detail": f"Sign-in from suspicious UA '{ua[:60]}' at IP {ip}",
                })
                break
        if risk in ("high", "medium"):
            findings.append({
                "type": "risky_sign_in",
                "severity": "high" if risk == "high" else "medium",
                "resource": user,
                "detail": f"Azure AD risk level '{risk}' from {country or ip}",
            })
        if lat and lon and ts:
            user_logins[user].append({"ts": ts, "lat": lat, "lon": lon, "ip": ip})
    for user, logins in user_logins.items():
        try:
            logins.sort(key=lambda x: x["ts"])
        except TypeError:
            continue
        for i in range(1, len(logins)):
            try:
                t1 = datetime.fromisoformat(logins[i - 1]["ts"].replace("Z", "+00:00"))
                t2 = datetime.fromisoformat(logins[i]["ts"].replace("Z", "+00:00"))
                hours = abs((t2 - t1).total_seconds()) / 3600.0
                if hours < 0.01:
                    continue
                dist = haversine_km(logins[i - 1]["lat"], logins[i - 1]["lon"], logins[i]["lat"], logins[i]["lon"])
                speed = dist / hours
                if speed > 900:
                    findings.append({
                        "type": "impossible_travel",
                        "severity": "critical",
                        "resource": user,
                        "detail": f"Impossible travel: {dist:.0f} km in {hours:.1f}h ({speed:.0f} km/h) between IPs {logins[i-1]['ip']} and {logins[i]['ip']}",
                    })
            except (ValueError, TypeError):
                continue
    return findings


def analyze_oauth_grants(grants):
    """Detect suspicious OAuth application consent grants."""
    findings = []
    for grant in grants:
        user = grant.get("user", grant.get("principalDisplayName", ""))
        app = grant.get("appDisplayName", grant.get("app_name", ""))
        scopes = grant.get("scope", grant.get("scopes", ""))
        consent_type = grant.get("consentType", "")
        risky_scopes = ["Mail.ReadWrite", "Mail.Send", "MailboxSettings.ReadWrite", "Files.ReadWrite.All"]
        granted_risky = [s for s in risky_scopes if s.lower() in (scopes or "").lower()]
        if granted_risky:
            findings.append({
                "type": "risky_oauth_grant",
                "severity": "high",
                "resource": user,
                "detail": f"App '{app}' granted risky scopes: {', '.join(granted_risky)}",
            })
        if consent_type == "AllPrincipals":
            findings.append({
                "type": "admin_consent_grant",
                "severity": "critical",
                "resource": user,
                "detail": f"App '{app}' has admin consent (AllPrincipals) with scopes: {scopes[:80]}",
            })
    return findings


def analyze(data):
    findings = []
    if isinstance(data, list):
        findings.extend(analyze_inbox_rules(data))
        return findings
    findings.extend(analyze_inbox_rules(data.get("inbox_rules", data.get("rules", []))))
    findings.extend(analyze_sign_ins(data.get("sign_ins", data.get("logins", []))))
    findings.extend(analyze_oauth_grants(data.get("oauth_grants", data.get("app_consents", []))))
    return findings


def generate_report(input_path):
    data = load_data(input_path)
    findings = analyze(data)
    sev = Counter(f["severity"] for f in findings)
    compromised = set(f["resource"] for f in findings if f["severity"] in ("critical", "high"))
    return {
        "report": "email_account_compromise_detection",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "severity_summary": dict(sev),
        "potentially_compromised_accounts": sorted(compromised),
        "findings": findings,
    }


def main():
    ap = argparse.ArgumentParser(description="Email Account Compromise Detection Agent")
    ap.add_argument("--input", required=True, help="Input JSON with inbox rules/sign-in/OAuth data")
    ap.add_argument("--output", help="Output JSON report path")
    args = ap.parse_args()
    report = generate_report(args.input)
    out = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(out)


if __name__ == "__main__":
    main()
