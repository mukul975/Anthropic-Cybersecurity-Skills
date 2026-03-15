#!/usr/bin/env python3
"""Agent for monitoring and managing Microsoft Defender for Cloud security posture."""

import subprocess
import json
import sys
import argparse
from datetime import datetime


def run_az_command(args_list):
    """Execute an Azure CLI command and return parsed JSON output."""
    cmd = ["az"] + args_list + ["--output", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            print(f"  [-] Error: {result.stderr.strip()}")
            return None
        return json.loads(result.stdout) if result.stdout.strip() else None
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        print(f"  [-] Command failed: {e}")
        return None


def get_defender_plans():
    """List all Defender for Cloud pricing plans and their status."""
    print("[*] Checking Defender for Cloud plan status...")
    plans = run_az_command(["security", "pricing", "list"])
    if not plans:
        return []
    enabled = []
    for plan in plans:
        tier = plan.get("pricingTier", "Free")
        name = plan.get("name", "Unknown")
        sub_plan = plan.get("subPlan", "")
        status = "ENABLED" if tier == "Standard" else "FREE"
        indicator = "[+]" if tier == "Standard" else "[-]"
        sub_info = f" ({sub_plan})" if sub_plan else ""
        print(f"  {indicator} {name}: {status}{sub_info}")
        if tier == "Standard":
            enabled.append({"name": name, "tier": tier, "subPlan": sub_plan})
    print(f"[*] {len(enabled)} plans enabled out of {len(plans)} total")
    return enabled


def get_secure_score():
    """Retrieve the current Secure Score across subscriptions."""
    print("\n[*] Fetching Secure Score...")
    scores = run_az_command(["security", "secure-score", "list"])
    if not scores:
        return {}
    for score in scores:
        current = score.get("current", 0)
        maximum = score.get("max", 0)
        pct = round((current / maximum * 100), 1) if maximum > 0 else 0
        print(f"  Score: {current}/{maximum} ({pct}%)")
    return scores


def get_security_assessments(severity_filter=None):
    """List security assessments and their health status."""
    print("\n[*] Fetching security assessments...")
    assessments = run_az_command(["security", "assessment", "list"])
    if not assessments:
        return []
    unhealthy = []
    for a in assessments:
        props = a.get("properties", {})
        status = props.get("status", {}).get("code", "")
        if status == "Unhealthy":
            sev = props.get("metadata", {}).get("severity", "Unknown")
            display = props.get("displayName", "Unknown")
            if severity_filter and sev.lower() != severity_filter.lower():
                continue
            unhealthy.append({"name": display, "severity": sev, "status": status})
            print(f"  [{sev.upper()}] {display}")
    print(f"[*] {len(unhealthy)} unhealthy assessments found")
    return unhealthy


def get_security_alerts(days=7):
    """Retrieve recent security alerts from Defender for Cloud."""
    print(f"\n[*] Fetching security alerts (last {days} days)...")
    alerts = run_az_command(["security", "alert", "list"])
    if not alerts:
        return []
    severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    active_alerts = []
    for alert in alerts:
        props = alert.get("properties", {})
        status = props.get("status", "")
        if status in ("Active", "InProgress"):
            sev = props.get("severity", "Unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            active_alerts.append({
                "name": props.get("alertDisplayName", "Unknown"),
                "severity": sev,
                "status": status,
                "timestamp": props.get("timeGeneratedUtc", ""),
            })
    for sev, count in severity_counts.items():
        if count > 0:
            print(f"  [{sev}] {count} alerts")
    return active_alerts


def check_security_contacts():
    """Verify security contact configuration for alert notifications."""
    print("\n[*] Checking security contact configuration...")
    contacts = run_az_command(["security", "contact", "list"])
    if not contacts:
        print("  [!] No security contacts configured")
        return False
    for contact in contacts:
        email = contact.get("email", "Not set")
        alerts = contact.get("alertNotifications", "off")
        print(f"  Email: {email} | Alert notifications: {alerts}")
    return True


def check_auto_provisioning():
    """Check auto-provisioning settings for security agents."""
    print("\n[*] Checking auto-provisioning settings...")
    settings = run_az_command(["security", "auto-provisioning-setting", "list"])
    if not settings:
        return []
    for s in settings:
        name = s.get("name", "Unknown")
        auto_prov = s.get("autoProvision", "Off")
        indicator = "[+]" if auto_prov == "On" else "[-]"
        print(f"  {indicator} {name}: {auto_prov}")
    return settings


def generate_posture_report(output_path):
    """Generate a comprehensive security posture report."""
    print("[*] Generating security posture report...")
    report = {
        "report_date": datetime.now().isoformat(),
        "defender_plans": get_defender_plans(),
        "secure_score": get_secure_score(),
        "unhealthy_assessments": get_security_assessments(),
        "active_alerts": get_security_alerts(),
        "contacts_configured": check_security_contacts(),
        "auto_provisioning": check_auto_provisioning(),
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[*] Report saved to {output_path}")
    return report


def main():
    parser = argparse.ArgumentParser(description="Microsoft Defender for Cloud Security Agent")
    parser.add_argument("action", choices=["plans", "score", "assessments", "alerts",
                                           "contacts", "auto-provision", "full-report"])
    parser.add_argument("--severity", choices=["high", "medium", "low"], help="Filter by severity")
    parser.add_argument("--days", type=int, default=7, help="Alert lookback in days")
    parser.add_argument("-o", "--output", default="defender_report.json")
    args = parser.parse_args()

    if args.action == "plans":
        get_defender_plans()
    elif args.action == "score":
        get_secure_score()
    elif args.action == "assessments":
        get_security_assessments(args.severity)
    elif args.action == "alerts":
        get_security_alerts(args.days)
    elif args.action == "contacts":
        check_security_contacts()
    elif args.action == "auto-provision":
        check_auto_provisioning()
    elif args.action == "full-report":
        generate_posture_report(args.output)


if __name__ == "__main__":
    main()
