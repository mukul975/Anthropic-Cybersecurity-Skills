#!/usr/bin/env python3
"""Email forwarding rules attack detection agent.

Detects malicious inbox rules created by adversaries for persistent
email access (T1114.003) by querying Microsoft Graph API and analyzing
audit logs for suspicious rule creation patterns.
"""

import argparse
import json
import re
import sys
from datetime import datetime

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

SUSPICIOUS_RULE_PATTERNS = {
    "forward_external": {"severity": "HIGH", "desc": "Rule forwards to external domain"},
    "delete_after_forward": {"severity": "CRITICAL", "desc": "Rule deletes after forwarding"},
    "move_to_rss": {"severity": "HIGH", "desc": "Rule moves to RSS Feeds folder"},
    "move_to_junk": {"severity": "MEDIUM", "desc": "Rule moves to Junk folder"},
    "keyword_financial": {"severity": "HIGH", "desc": "Rule targets financial keywords"},
    "mark_as_read": {"severity": "MEDIUM", "desc": "Rule marks messages as read"},
}

FINANCIAL_KEYWORDS = ["invoice", "payment", "wire", "transfer", "bank",
                       "ach", "routing", "remittance", "purchase order"]


def get_mailbox_rules(token, user_id="me"):
    url = f"https://graph.microsoft.com/v1.0/users/{user_id}/mailFolders/inbox/messageRules"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.json().get("value", [])
        return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except requests.RequestException as e:
        return {"error": str(e)}


def analyze_rules(rules, org_domain=""):
    findings = []
    for rule in rules:
        if isinstance(rules, dict) and "error" in rules:
            return [rules]
        rule_name = rule.get("displayName", "")
        actions = rule.get("actions", {})
        conditions = rule.get("conditions", {})
        is_enabled = rule.get("isEnabled", True)

        forward_to = actions.get("forwardTo", [])
        redirect_to = actions.get("redirectTo", [])
        delete = actions.get("delete", False)
        move_folder = actions.get("moveToFolder", "")
        mark_read = actions.get("markAsRead", False)

        all_forwards = forward_to + redirect_to
        for fwd in all_forwards:
            addr = fwd.get("emailAddress", {}).get("address", "")
            if org_domain and addr and not addr.lower().endswith(f"@{org_domain.lower()}"):
                severity = "CRITICAL" if delete else "HIGH"
                findings.append({
                    "rule_name": rule_name,
                    "type": "external_forwarding",
                    "forward_to": addr,
                    "delete_after": delete,
                    "is_enabled": is_enabled,
                    "severity": severity,
                    "mitre": "T1114.003",
                })

        subject_contains = conditions.get("subjectContains", [])
        body_contains = conditions.get("bodyContains", [])
        all_keywords = [k.lower() for k in subject_contains + body_contains]
        matched_financial = [k for k in all_keywords if k in FINANCIAL_KEYWORDS]
        if matched_financial and all_forwards:
            findings.append({
                "rule_name": rule_name,
                "type": "financial_keyword_forwarding",
                "keywords": matched_financial,
                "forward_to": [f.get("emailAddress", {}).get("address", "") for f in all_forwards],
                "severity": "CRITICAL",
                "mitre": "T1114.003",
            })

        if mark_read and all_forwards:
            findings.append({
                "rule_name": rule_name,
                "type": "silent_forwarding",
                "mark_as_read": True,
                "severity": "HIGH",
                "description": "Rule forwards and marks as read to hide activity",
            })

    return findings


def parse_audit_log_for_rules(filepath):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if "New-InboxRule" in line or "Set-InboxRule" in line:
                forward = re.search(r'ForwardTo["\s:]+([^\s"]+@[^\s"]+)', line, re.IGNORECASE)
                user = re.search(r'UserId["\s:]+([^\s"]+)', line, re.IGNORECASE)
                findings.append({
                    "type": "rule_creation_audit",
                    "command": "New-InboxRule" if "New-InboxRule" in line else "Set-InboxRule",
                    "user": user.group(1) if user else "",
                    "forward_to": forward.group(1) if forward else "",
                    "severity": "HIGH",
                    "raw": line.strip()[:300],
                })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Email Forwarding Rules Attack Detector")
    parser.add_argument("--token", help="Microsoft Graph API bearer token")
    parser.add_argument("--user-id", default="me", help="User ID or UPN")
    parser.add_argument("--org-domain", default="", help="Organization email domain")
    parser.add_argument("--audit-log", help="Exchange audit log file to parse")
    args = parser.parse_args()

    results = {"timestamp": datetime.utcnow().isoformat() + "Z", "findings": []}

    if args.token:
        rules = get_mailbox_rules(args.token, args.user_id)
        if isinstance(rules, dict) and "error" in rules:
            results["error"] = rules["error"]
        else:
            results["total_rules"] = len(rules)
            findings = analyze_rules(rules, args.org_domain)
            results["findings"].extend(findings)

    if args.audit_log:
        audit_findings = parse_audit_log_for_rules(args.audit_log)
        results["findings"].extend(audit_findings)

    results["total_findings"] = len(results["findings"])
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
