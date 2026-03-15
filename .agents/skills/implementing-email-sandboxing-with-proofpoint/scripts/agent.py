#!/usr/bin/env python3
"""Agent for implementing and monitoring Proofpoint email sandboxing."""

import json
import argparse
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


def get_tap_threats(base_url, principal, secret, time_range="PT1H"):
    """Query Proofpoint TAP SIEM API for threats."""
    url = f"{base_url}/v2/siem/all"
    resp = requests.get(url, auth=(principal, secret),
                        params={"sinceSeconds": 3600, "format": "json"}, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    return {
        "messages_delivered": len(data.get("messagesDelivered", [])),
        "messages_blocked": len(data.get("messagesBlocked", [])),
        "clicks_permitted": len(data.get("clicksPermitted", [])),
        "clicks_blocked": len(data.get("clicksBlocked", [])),
        "threats": data.get("messagesBlocked", [])[:50],
    }


def analyze_sandbox_results(results_path):
    """Analyze Proofpoint sandbox detonation results."""
    with open(results_path) as f:
        results = json.load(f)
    findings = []
    for result in results if isinstance(results, list) else results.get("results", []):
        verdict = result.get("verdict", result.get("classification", ""))
        score = result.get("score", result.get("threat_score", 0))
        if verdict.lower() in ("malicious", "phish", "spam") or int(score) > 70:
            findings.append({
                "message_id": result.get("message_id", ""),
                "sender": result.get("sender", result.get("from", "")),
                "subject": result.get("subject", ""),
                "verdict": verdict,
                "score": score,
                "threats_found": result.get("threats", []),
                "attachment": result.get("attachment_name", ""),
                "url_detonated": result.get("url", ""),
                "severity": "CRITICAL" if int(score) > 90 else "HIGH",
            })
    return findings


def calculate_email_metrics(log_path):
    """Calculate email security metrics from logs."""
    total = 0
    blocked = 0
    delivered = 0
    by_category = {}
    with open(log_path) as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1
            action = entry.get("action", entry.get("policy_action", "")).lower()
            if action in ("block", "quarantine", "reject"):
                blocked += 1
            else:
                delivered += 1
            cat = entry.get("category", entry.get("threat_type", "clean"))
            by_category[cat] = by_category.get(cat, 0) + 1
    return {
        "total_messages": total, "blocked": blocked, "delivered": delivered,
        "block_rate": round(blocked / total * 100, 1) if total else 0,
        "by_category": by_category,
    }


def generate_url_defense_config():
    """Generate Proofpoint URL Defense configuration."""
    return {
        "url_defense": {
            "enabled": True,
            "rewrite_all_urls": True,
            "real_time_scanning": True,
            "sandbox_detonation": True,
            "click_time_protection": True,
        },
        "attachment_defense": {
            "enabled": True,
            "sandbox_analysis": True,
            "supported_types": ["exe", "dll", "doc", "docx", "xls", "xlsx",
                               "pdf", "zip", "rar", "iso", "lnk"],
            "action_on_malicious": "quarantine",
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Proofpoint Email Sandboxing Agent")
    parser.add_argument("--tap-url", default="https://tap-api-v2.proofpoint.com")
    parser.add_argument("--principal", help="TAP API principal")
    parser.add_argument("--secret", help="TAP API secret")
    parser.add_argument("--results", help="Sandbox results JSON")
    parser.add_argument("--log", help="Email log (JSON lines)")
    parser.add_argument("--output", default="proofpoint_sandbox_report.json")
    parser.add_argument("--action", choices=["tap", "analyze", "metrics", "config", "full"],
                        default="full")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.action in ("tap", "full") and args.principal and args.secret:
        data = get_tap_threats(args.tap_url, args.principal, args.secret)
        report["findings"]["tap_threats"] = data
        print(f"[+] Blocked: {data['messages_blocked']}, Delivered: {data['messages_delivered']}")

    if args.action in ("analyze", "full") and args.results:
        findings = analyze_sandbox_results(args.results)
        report["findings"]["sandbox_findings"] = findings
        print(f"[+] Malicious sandbox results: {len(findings)}")

    if args.action in ("metrics", "full") and args.log:
        metrics = calculate_email_metrics(args.log)
        report["findings"]["email_metrics"] = metrics
        print(f"[+] Block rate: {metrics['block_rate']}%")

    if args.action in ("config", "full"):
        config = generate_url_defense_config()
        report["findings"]["config"] = config
        print("[+] URL/Attachment Defense config generated")

    with open(args.output, "w") as fout:
        json.dump(report, fout, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
