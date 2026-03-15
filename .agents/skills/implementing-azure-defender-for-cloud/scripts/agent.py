#!/usr/bin/env python3
"""Azure Defender for Cloud security posture agent using azure-mgmt-security."""

import json
import sys
import argparse
from datetime import datetime

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.security import SecurityCenter
    from azure.mgmt.resource import SubscriptionClient
except ImportError:
    print("Install: pip install azure-identity azure-mgmt-security azure-mgmt-resource")
    sys.exit(1)


def get_security_client(subscription_id):
    """Create Azure Security Center client."""
    credential = DefaultAzureCredential()
    return SecurityCenter(credential, subscription_id)


def list_subscriptions():
    """List available Azure subscriptions."""
    credential = DefaultAzureCredential()
    sub_client = SubscriptionClient(credential)
    return [{"id": s.subscription_id, "name": s.display_name, "state": s.state}
            for s in sub_client.subscriptions.list()]


def get_secure_score(client):
    """Retrieve the current secure score."""
    scores = []
    for score in client.secure_scores.list():
        scores.append({
            "name": score.display_name,
            "current": score.current.score,
            "max": score.max_score,
            "percentage": round(score.current.score / max(score.max_score, 1) * 100, 1),
            "weight": score.weight,
        })
    return scores


def get_security_assessments(client, subscription_id):
    """List all unhealthy security assessments (recommendations)."""
    scope = f"/subscriptions/{subscription_id}"
    assessments = []
    for a in client.assessments.list(scope=scope):
        status = a.status
        if status and status.code and status.code.lower() == "unhealthy":
            assessments.append({
                "name": a.display_name,
                "status": status.code,
                "severity": a.metadata.severity if a.metadata else "Unknown",
                "category": a.metadata.category if a.metadata else "Unknown",
                "description": a.metadata.description if a.metadata else "",
            })
    return assessments


def get_pricing_tiers(client):
    """Check which Defender plans are enabled."""
    plans = []
    for p in client.pricings.list().value:
        plans.append({
            "name": p.name,
            "tier": p.pricing_tier,
            "sub_plan": getattr(p, "sub_plan", None),
        })
    return plans


def get_security_alerts(client):
    """Retrieve active security alerts."""
    alerts = []
    for alert in client.alerts.list():
        if alert.status == "Active":
            alerts.append({
                "name": alert.alert_display_name,
                "severity": alert.severity,
                "status": alert.status,
                "time": str(alert.time_generated_utc),
                "description": alert.description[:200] if alert.description else "",
                "tactics": list(alert.intent) if alert.intent else [],
            })
    return sorted(alerts, key=lambda x: {"High": 0, "Medium": 1, "Low": 2}.get(x["severity"], 3))


def get_regulatory_compliance(client):
    """Check regulatory compliance standard status."""
    standards = []
    try:
        for std in client.regulatory_compliance_standards.list():
            standards.append({
                "name": std.name,
                "state": std.state,
                "passed": std.passed_controls,
                "failed": std.failed_controls,
                "skipped": std.skipped_controls,
            })
    except Exception as e:
        standards.append({"error": str(e)})
    return standards


def get_jit_policies(client, resource_group=None):
    """List Just-In-Time VM access policies."""
    policies = []
    try:
        if resource_group:
            jit_list = client.jit_network_access_policies.list_by_resource_group(resource_group)
        else:
            jit_list = client.jit_network_access_policies.list()
        for p in jit_list:
            policies.append({
                "name": p.name,
                "vm_count": len(p.virtual_machines) if p.virtual_machines else 0,
                "provisioning_state": p.provisioning_state,
            })
    except Exception as e:
        policies.append({"error": str(e)})
    return policies


def run_defender_audit(subscription_id):
    """Run a full Defender for Cloud audit."""
    client = get_security_client(subscription_id)

    print(f"\n{'='*60}")
    print(f"  MICROSOFT DEFENDER FOR CLOUD AUDIT")
    print(f"  Subscription: {subscription_id}")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    plans = get_pricing_tiers(client)
    print(f"--- DEFENDER PLANS ---")
    for p in plans:
        tier_icon = "[ON]" if p["tier"] == "Standard" else "[OFF]"
        print(f"  {tier_icon} {p['name']}: {p['tier']}"
              f"{' (' + p['sub_plan'] + ')' if p['sub_plan'] else ''}")

    scores = get_secure_score(client)
    print(f"\n--- SECURE SCORE ---")
    for s in scores:
        bar = "#" * int(s["percentage"] / 2)
        print(f"  {s['name']}: {s['current']}/{s['max']} ({s['percentage']}%) {bar}")

    assessments = get_security_assessments(client, subscription_id)
    sev_counts = {}
    for a in assessments:
        sev_counts[a["severity"]] = sev_counts.get(a["severity"], 0) + 1
    print(f"\n--- UNHEALTHY RECOMMENDATIONS ({len(assessments)}) ---")
    for sev in ["High", "Medium", "Low"]:
        print(f"  {sev}: {sev_counts.get(sev, 0)}")
    for a in assessments[:5]:
        print(f"  [{a['severity']}] {a['name']}")

    alerts = get_security_alerts(client)
    print(f"\n--- ACTIVE ALERTS ({len(alerts)}) ---")
    for a in alerts[:5]:
        print(f"  [{a['severity']}] {a['name']} ({a['time']})")

    compliance = get_regulatory_compliance(client)
    print(f"\n--- REGULATORY COMPLIANCE ---")
    for c in compliance:
        if "error" not in c:
            print(f"  {c['name']}: {c['state']} (P:{c['passed']} F:{c['failed']} S:{c['skipped']})")

    print(f"\n{'='*60}\n")
    return {"plans": plans, "scores": scores, "assessments_count": len(assessments),
            "alerts_count": len(alerts), "compliance": compliance}


def main():
    parser = argparse.ArgumentParser(description="Azure Defender for Cloud Agent")
    parser.add_argument("--subscription", required=True, help="Azure subscription ID")
    parser.add_argument("--audit", action="store_true", help="Run full audit")
    parser.add_argument("--output", help="Save report to JSON")
    args = parser.parse_args()

    if args.audit:
        report = run_defender_audit(args.subscription)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"[+] Report saved to {args.output}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
