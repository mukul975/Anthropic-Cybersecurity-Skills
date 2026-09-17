#!/usr/bin/env python3
"""Proofpoint email security gateway audit agent.

Audits Proofpoint TAP (Targeted Attack Protection) via the SIEM API
to retrieve blocked threats, clicked URLs, delivered messages, and
campaign attribution data for email security monitoring.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone, timedelta

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    print("[!] 'requests' required: pip install requests", file=sys.stderr)
    sys.exit(1)

PROOFPOINT_BASE = "https://tap-api-v2.proofpoint.com"


def get_pp_config():
    """Return Proofpoint TAP API credentials."""
    principal = os.environ.get("PROOFPOINT_PRINCIPAL", "")
    secret = os.environ.get("PROOFPOINT_SECRET", "")
    if not principal or not secret:
        print("[!] Set PROOFPOINT_PRINCIPAL and PROOFPOINT_SECRET env vars", file=sys.stderr)
        sys.exit(1)
    return principal, secret


def pp_api(endpoint, principal, secret, params=None):
    """Make authenticated Proofpoint TAP API call."""
    url = f"{PROOFPOINT_BASE}{endpoint}"
    resp = requests.get(url, auth=HTTPBasicAuth(principal, secret),
                        params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def get_blocked_clicks(principal, secret, hours=24):
    """Get URLs that were blocked when clicked."""
    print(f"[*] Fetching blocked clicks (last {hours}h)...")
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = pp_api("/v2/siem/clicks/blocked", principal, secret,
                  params={"sinceTime": since, "format": "json"})
    clicks = data.get("clicksBlocked", [])
    print(f"[+] {len(clicks)} blocked clicks")
    return clicks


def get_blocked_messages(principal, secret, hours=24):
    """Get messages that were blocked."""
    print(f"[*] Fetching blocked messages (last {hours}h)...")
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = pp_api("/v2/siem/messages/blocked", principal, secret,
                  params={"sinceTime": since, "format": "json"})
    messages = data.get("messagesBlocked", [])
    print(f"[+] {len(messages)} blocked messages")
    return messages


def get_delivered_threats(principal, secret, hours=24):
    """Get threats that were delivered (missed by filters)."""
    print(f"[*] Fetching delivered threats (last {hours}h)...")
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = pp_api("/v2/siem/messages/delivered", principal, secret,
                  params={"sinceTime": since, "format": "json"})
    messages = data.get("messagesDelivered", [])
    threats = [m for m in messages if m.get("threatsInfoMap")]
    print(f"[+] {len(messages)} delivered, {len(threats)} with threats")
    return threats


def get_permitted_clicks(principal, secret, hours=24):
    """Get URLs that were permitted when clicked (potential misses)."""
    print(f"[*] Fetching permitted clicks (last {hours}h)...")
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = pp_api("/v2/siem/clicks/permitted", principal, secret,
                  params={"sinceTime": since, "format": "json"})
    clicks = data.get("clicksPermitted", [])
    print(f"[+] {len(clicks)} permitted clicks")
    return clicks


def analyze_threats(blocked_msgs, delivered_threats, blocked_clicks, permitted_clicks):
    """Analyze threat data for security insights."""
    findings = []

    # Delivered threats are highest priority
    for msg in delivered_threats:
        for threat_info in msg.get("threatsInfoMap", []):
            findings.append({
                "type": "delivered_threat",
                "severity": "CRITICAL",
                "threat_type": threat_info.get("threatType", ""),
                "classification": threat_info.get("classification", ""),
                "threat_url": threat_info.get("threat", "")[:100],
                "recipient": msg.get("recipient", [""])[0] if msg.get("recipient") else "",
                "sender": msg.get("sender", ""),
                "subject": msg.get("subject", "")[:80],
                "timestamp": msg.get("messageTime", ""),
            })

    # Summarize blocked activity
    threat_types = {}
    for msg in blocked_msgs:
        for t in msg.get("threatsInfoMap", []):
            tt = t.get("threatType", "unknown")
            threat_types[tt] = threat_types.get(tt, 0) + 1

    if threat_types:
        findings.append({
            "type": "blocked_summary",
            "severity": "INFO",
            "detail": f"Blocked threats by type: {json.dumps(threat_types)}",
            "total_blocked": len(blocked_msgs),
        })

    # Permitted clicks on potentially malicious URLs
    for click in permitted_clicks:
        if click.get("threatStatus") == "active":
            findings.append({
                "type": "permitted_malicious_click",
                "severity": "HIGH",
                "url": click.get("url", "")[:100],
                "user": click.get("recipient", [""])[0] if click.get("recipient") else "",
                "click_time": click.get("clickTime", ""),
            })

    return findings


def format_summary(findings, blocked_msgs, delivered, blocked_clicks, permitted_clicks):
    """Print email security summary."""
    print(f"\n{'='*60}")
    print("  Proofpoint Email Security Report")
    print(f"{'='*60}")
    print(f"  Blocked Messages  : {len(blocked_msgs)}")
    print(f"  Delivered Threats  : {len(delivered)}")
    print(f"  Blocked Clicks     : {len(blocked_clicks)}")
    print(f"  Permitted Clicks   : {len(permitted_clicks)}")
    print(f"  Security Findings  : {len(findings)}")

    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    if critical:
        print(f"\n  CRITICAL - Threats That Bypassed Filters ({len(critical)}):")
        for f in critical[:10]:
            print(f"    {f.get('threat_type', 'N/A'):15s} | "
                  f"To: {f.get('recipient', 'N/A'):30s} | "
                  f"{f.get('subject', '')[:40]}")

    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    return severity_counts


def main():
    parser = argparse.ArgumentParser(description="Proofpoint email security audit agent")
    parser.add_argument("--principal", help="TAP API principal (or PROOFPOINT_PRINCIPAL env)")
    parser.add_argument("--secret", help="TAP API secret (or PROOFPOINT_SECRET env)")
    parser.add_argument("--hours", type=int, default=24, help="Hours to look back (default: 24)")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.principal:
        os.environ["PROOFPOINT_PRINCIPAL"] = args.principal
    if args.secret:
        os.environ["PROOFPOINT_SECRET"] = args.secret

    principal, secret = get_pp_config()

    blocked_msgs = get_blocked_messages(principal, secret, args.hours)
    delivered = get_delivered_threats(principal, secret, args.hours)
    blocked_clicks = get_blocked_clicks(principal, secret, args.hours)
    permitted_clicks = get_permitted_clicks(principal, secret, args.hours)

    findings = analyze_threats(blocked_msgs, delivered, blocked_clicks, permitted_clicks)
    severity_counts = format_summary(findings, blocked_msgs, delivered, blocked_clicks, permitted_clicks)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "Proofpoint TAP",
        "period_hours": args.hours,
        "blocked_messages": len(blocked_msgs),
        "delivered_threats": len(delivered),
        "findings": findings,
        "severity_counts": severity_counts,
        "risk_level": (
            "CRITICAL" if severity_counts.get("CRITICAL", 0) > 0
            else "HIGH" if severity_counts.get("HIGH", 0) > 0
            else "LOW"
        ),
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
