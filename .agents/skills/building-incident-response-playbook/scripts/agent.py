#!/usr/bin/env python3
"""Agent for building and managing incident response playbooks."""

import os
import json
import argparse
from datetime import datetime

import requests


PLAYBOOK_TYPES = {
    "ransomware": {
        "name": "Ransomware Incident Response",
        "trigger": "EDR alert for file encryption activity or ransom note detection",
        "severity_default": "P1",
        "phases": {
            "detection": [
                "EDR alerts on mass file encryption (CrowdStrike, SentinelOne)",
                "Canary file modification alerts from deception tools",
                "User reports of inaccessible files or ransom note",
            ],
            "containment": [
                "Isolate affected hosts via EDR network containment",
                "Block C2 IPs/domains at firewall and DNS sinkhole",
                "Disable compromised accounts in Active Directory",
                "Segment affected network VLANs at switch level",
            ],
            "eradication": [
                "Identify ransomware variant and initial access vector",
                "Remove persistence mechanisms (scheduled tasks, services, registry)",
                "Scan enterprise for IOCs using EDR threat hunt",
                "Patch exploited vulnerability if applicable",
            ],
            "recovery": [
                "Restore from verified clean backups (test integrity first)",
                "Rebuild compromised systems from gold images",
                "Re-enable accounts with forced password reset and MFA",
                "Monitor restored systems for 72 hours post-recovery",
            ],
        },
    },
    "phishing": {
        "name": "Phishing Incident Response",
        "trigger": "User report via abuse mailbox or phishing button",
        "severity_default": "P2",
        "phases": {
            "detection": [
                "User report to abuse@company.com or phish report button",
                "Email gateway alert on suspicious attachment/link",
                "SIEM correlation of multiple reports for same sender",
            ],
            "containment": [
                "Quarantine phishing email from all mailboxes (O365 purge or Exchange)",
                "Block sender domain and reply-to address in email gateway",
                "If credentials entered: force password reset and revoke sessions",
                "Block malicious URL at web proxy",
            ],
            "eradication": [
                "Extract and submit IOCs (URLs, hashes, sender) to TI platform",
                "Search email logs for all recipients of the phishing email",
                "Verify no malware payload executed on endpoints",
                "Update email filtering rules to catch similar campaigns",
            ],
            "recovery": [
                "Notify affected users with guidance on what to watch for",
                "Restore any quarantined legitimate emails (false positives)",
                "Schedule targeted phishing awareness training for clickers",
            ],
        },
    },
    "data_breach": {
        "name": "Data Breach / Exfiltration Response",
        "trigger": "DLP alert, anomalous data transfer, or external notification",
        "severity_default": "P1",
        "phases": {
            "detection": [
                "DLP policy violation alert on sensitive data movement",
                "Network anomaly detection for large outbound transfers",
                "Cloud access broker alert for unauthorized file sharing",
            ],
            "containment": [
                "Block exfiltration channel (IP, domain, cloud service)",
                "Revoke access for compromised account",
                "Preserve affected system for forensic imaging",
                "Engage legal counsel for breach notification assessment",
            ],
            "eradication": [
                "Determine scope: what data, how much, which systems",
                "Identify root cause and attack vector",
                "Remove attacker access and persistence",
                "Audit all access to affected data stores",
            ],
            "recovery": [
                "Implement additional DLP controls on affected data",
                "Reset credentials for all accounts with access to breached data",
                "Execute breach notification plan if PII/PHI involved",
                "Engage external forensics firm if required by cyber insurance",
            ],
        },
    },
}


def generate_playbook(playbook_type):
    """Generate a structured IR playbook for the given incident type."""
    template = PLAYBOOK_TYPES.get(playbook_type)
    if not template:
        return {"error": f"Unknown playbook type: {playbook_type}"}
    playbook = {
        "metadata": {
            "name": template["name"],
            "version": "1.0",
            "created": datetime.utcnow().isoformat(),
            "owner": "SOC Manager",
            "default_severity": template["severity_default"],
            "trigger": template["trigger"],
            "framework": "NIST SP 800-61r3",
        },
        "raci": {
            "detection": {"R": "SOC L1", "A": "SOC L2", "C": "IR Lead", "I": ""},
            "containment": {"R": "SOC L2", "A": "IR Lead", "C": "CISO", "I": "Legal"},
            "eradication": {"R": "IR Lead", "A": "CISO", "C": "IT Ops", "I": "Mgmt"},
            "recovery": {"R": "IT Ops", "A": "IR Lead", "C": "Business Owner", "I": "CISO"},
            "post_incident": {"R": "IR Lead", "A": "CISO", "C": "All", "I": "Exec"},
        },
        "phases": template["phases"],
        "escalation": {
            "P1": "Immediate: IR Lead + CISO + Legal within 15 minutes",
            "P2": "IR Lead notified within 30 minutes",
            "P3": "Queued for investigation within 4 hours",
        },
        "communication": {
            "internal_cadence": "Every 2 hours during active incident",
            "executive_update": "Within 1 hour of P1 declaration",
            "regulatory": "Within 72 hours if personal data involved (GDPR)",
        },
    }
    return playbook


def check_thehive_cases(thehive_url, api_key):
    """List open incident cases from TheHive."""
    headers = {"Authorization": f"Bearer {api_key}"}
    resp = requests.post(f"{thehive_url}/api/v1/query", headers=headers, json={
        "query": [
            {"_name": "listCase"},
            {"_name": "filter", "_field": "status", "_value": "Open"},
            {"_name": "sort", "_fields": [{"startDate": "desc"}]},
            {"_name": "page", "from": 0, "to": 50},
        ]
    })
    resp.raise_for_status()
    cases = []
    for c in resp.json():
        cases.append({
            "number": c.get("number"),
            "title": c.get("title"),
            "severity": c.get("severity"),
            "status": c.get("status"),
            "start_date": c.get("startDate"),
            "owner": c.get("owner"),
        })
    return cases


def calculate_ir_metrics(thehive_url, api_key, days=30):
    """Calculate incident response metrics from TheHive cases."""
    headers = {"Authorization": f"Bearer {api_key}"}
    resp = requests.post(f"{thehive_url}/api/v1/query", headers=headers, json={
        "query": [
            {"_name": "listCase"},
            {"_name": "filter", "_field": "status", "_value": "Resolved"},
            {"_name": "page", "from": 0, "to": 500},
        ]
    })
    resp.raise_for_status()
    cases = resp.json()
    total_resolve_ms = 0
    count = 0
    for c in cases:
        if c.get("endDate") and c.get("startDate"):
            resolve_ms = c["endDate"] - c["startDate"]
            total_resolve_ms += resolve_ms
            count += 1
    avg_mttr_hours = (total_resolve_ms / count / 3600000) if count else 0
    return {"resolved_cases": count, "avg_mttr_hours": round(avg_mttr_hours, 1)}


def main():
    parser = argparse.ArgumentParser(description="Incident Response Playbook Agent")
    parser.add_argument("--playbook-type", choices=list(PLAYBOOK_TYPES.keys()))
    parser.add_argument("--thehive-url", default=os.getenv("THEHIVE_URL"))
    parser.add_argument("--thehive-key", default=os.getenv("THEHIVE_API_KEY"))
    parser.add_argument("--output", default="ir_playbook_output.json")
    parser.add_argument("--action", choices=[
        "generate", "list_cases", "metrics", "all_playbooks"
    ], default="generate")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat()}

    if args.action == "generate" and args.playbook_type:
        playbook = generate_playbook(args.playbook_type)
        report["playbook"] = playbook
        print(f"[+] Generated playbook: {playbook['metadata']['name']}")

    if args.action == "all_playbooks":
        report["playbooks"] = {}
        for ptype in PLAYBOOK_TYPES:
            report["playbooks"][ptype] = generate_playbook(ptype)
            print(f"[+] Generated: {PLAYBOOK_TYPES[ptype]['name']}")

    if args.action == "list_cases" and args.thehive_url:
        cases = check_thehive_cases(args.thehive_url, args.thehive_key)
        report["open_cases"] = cases
        print(f"[+] Open cases: {len(cases)}")

    if args.action == "metrics" and args.thehive_url:
        metrics = calculate_ir_metrics(args.thehive_url, args.thehive_key)
        report["metrics"] = metrics
        print(f"[+] Avg MTTR: {metrics['avg_mttr_hours']}h across {metrics['resolved_cases']} cases")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Output saved to {args.output}")


if __name__ == "__main__":
    main()
