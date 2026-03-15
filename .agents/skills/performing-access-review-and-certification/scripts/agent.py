#!/usr/bin/env python3
"""Agent for conducting access review and certification using identity governance APIs."""

import requests
import json
import argparse
import csv
from datetime import datetime, timezone, timedelta


def load_access_data(csv_path):
    """Load access entitlement data from CSV export."""
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        data = list(reader)
    print(f"[*] Loaded {len(data)} entitlement records from {csv_path}")
    return data


def identify_orphaned_accounts(records):
    """Find accounts with no manager or terminated status."""
    findings = []
    for r in records:
        if not r.get("manager") or r.get("status", "").lower() == "terminated":
            findings.append({"user": r.get("username"), "status": r.get("status"),
                             "manager": r.get("manager", "NONE"), "severity": "HIGH",
                             "issue": "Orphaned/terminated account with active access"})
    print(f"\n[*] Orphaned/terminated accounts: {len(findings)}")
    for f in findings[:10]:
        print(f"  [!] {f['user']} (status={f['status']}, manager={f['manager']})")
    return findings


def check_sod_violations(records, sod_rules):
    """Check for separation of duties violations."""
    user_entitlements = {}
    for r in records:
        user = r.get("username", "")
        ent = r.get("entitlement", "")
        user_entitlements.setdefault(user, set()).add(ent)
    findings = []
    for user, ents in user_entitlements.items():
        for rule in sod_rules:
            if rule["role_a"] in ents and rule["role_b"] in ents:
                findings.append({"user": user, "conflict": f"{rule['role_a']} + {rule['role_b']}",
                                 "severity": "CRITICAL", "rule": rule.get("name", "")})
    print(f"\n[*] SoD violations: {len(findings)}")
    for f in findings[:10]:
        print(f"  [!] {f['user']}: {f['conflict']}")
    return findings


def identify_excessive_access(records, threshold=10):
    """Find users with entitlement counts above threshold."""
    user_counts = {}
    for r in records:
        user = r.get("username", "")
        user_counts[user] = user_counts.get(user, 0) + 1
    excessive = [{"user": u, "count": c, "severity": "MEDIUM"}
                 for u, c in user_counts.items() if c > threshold]
    excessive.sort(key=lambda x: -x["count"])
    print(f"\n[*] Users with >{threshold} entitlements: {len(excessive)}")
    for e in excessive[:10]:
        print(f"  [!] {e['user']}: {e['count']} entitlements")
    return excessive


def check_last_used(records, stale_days=90):
    """Find entitlements not used within the stale period."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=stale_days)
    stale = []
    for r in records:
        last_used = r.get("last_used", "")
        if last_used:
            try:
                lu_dt = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                if lu_dt < cutoff:
                    stale.append({"user": r.get("username"), "entitlement": r.get("entitlement"),
                                  "last_used": last_used, "severity": "MEDIUM"})
            except ValueError:
                pass
    print(f"\n[*] Stale entitlements (>{stale_days} days unused): {len(stale)}")
    return stale


def generate_report(orphaned, sod, excessive, stale, output_path):
    """Generate access review report."""
    report = {"review_date": datetime.now(timezone.utc).isoformat(),
              "summary": {"orphaned_accounts": len(orphaned), "sod_violations": len(sod),
                          "excessive_access": len(excessive), "stale_entitlements": len(stale)},
              "orphaned": orphaned, "sod_violations": sod,
              "excessive_access": excessive[:50], "stale_entitlements": stale[:50]}
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    total = len(orphaned) + len(sod) + len(excessive) + len(stale)
    print(f"\n[*] Report saved to {output_path} | Total findings: {total}")


def main():
    parser = argparse.ArgumentParser(description="Access Review and Certification Agent")
    parser.add_argument("action", choices=["orphaned", "sod", "excessive", "stale", "full-review"])
    parser.add_argument("--data", required=True, help="CSV file with access entitlements")
    parser.add_argument("--sod-rules", help="JSON file with SoD rules")
    parser.add_argument("--threshold", type=int, default=10, help="Excessive access threshold")
    parser.add_argument("--stale-days", type=int, default=90)
    parser.add_argument("-o", "--output", default="access_review.json")
    args = parser.parse_args()

    records = load_access_data(args.data)
    sod_rules = []
    if args.sod_rules:
        with open(args.sod_rules) as f:
            sod_rules = json.load(f)

    if args.action == "orphaned":
        identify_orphaned_accounts(records)
    elif args.action == "sod":
        check_sod_violations(records, sod_rules)
    elif args.action == "excessive":
        identify_excessive_access(records, args.threshold)
    elif args.action == "stale":
        check_last_used(records, args.stale_days)
    elif args.action == "full-review":
        o = identify_orphaned_accounts(records)
        s = check_sod_violations(records, sod_rules)
        e = identify_excessive_access(records, args.threshold)
        st = check_last_used(records, args.stale_days)
        generate_report(o, s, e, st, args.output)


if __name__ == "__main__":
    main()
