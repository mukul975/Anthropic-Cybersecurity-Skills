#!/usr/bin/env python3
"""Privileged Account Access Review agent — audits privileged accounts for
compliance with least-privilege and periodic recertification requirements."""

import argparse
import csv
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path


def load_accounts(csv_path: str) -> list[dict]:
    """Load privileged account inventory from CSV."""
    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return list(reader)


def check_stale_accounts(accounts: list[dict], max_days: int = 90) -> list[dict]:
    """Flag accounts not used within max_days."""
    findings = []
    cutoff = datetime.utcnow() - timedelta(days=max_days)
    for acct in accounts:
        last_used = acct.get("last_used", "")
        if not last_used:
            findings.append({"account": acct.get("username", ""), "issue": "no_last_used_date",
                             "severity": "high", "detail": "Account has no recorded last-used date"})
            continue
        try:
            used_dt = datetime.strptime(last_used, "%Y-%m-%d")
            if used_dt < cutoff:
                findings.append({"account": acct.get("username", ""),
                                 "issue": "stale_account", "severity": "high",
                                 "detail": f"Last used {last_used}, exceeds {max_days}-day threshold"})
        except ValueError:
            findings.append({"account": acct.get("username", ""), "issue": "invalid_date",
                             "severity": "medium", "detail": f"Cannot parse last_used: {last_used}"})
    return findings


def check_shared_accounts(accounts: list[dict]) -> list[dict]:
    """Detect shared/generic privileged accounts."""
    shared_patterns = ["admin", "root", "service", "svc_", "shared", "generic", "temp"]
    findings = []
    for acct in accounts:
        uname = acct.get("username", "").lower()
        owner = acct.get("owner", "").strip()
        for pat in shared_patterns:
            if pat in uname and not owner:
                findings.append({"account": acct.get("username", ""),
                                 "issue": "shared_account_no_owner", "severity": "critical",
                                 "detail": f"Appears shared (matches '{pat}') with no assigned owner"})
                break
    return findings


def check_excessive_privileges(accounts: list[dict]) -> list[dict]:
    """Flag accounts with overly broad privilege sets."""
    high_risk_roles = {"domain admin", "enterprise admin", "schema admin",
                       "global admin", "super admin", "root"}
    findings = []
    for acct in accounts:
        roles = {r.strip().lower() for r in acct.get("roles", "").split(";")}
        overlap = roles & high_risk_roles
        if overlap:
            findings.append({"account": acct.get("username", ""),
                             "issue": "excessive_privilege", "severity": "critical",
                             "detail": f"Holds high-risk roles: {', '.join(sorted(overlap))}"})
    return findings


def check_recertification(accounts: list[dict], cert_interval_days: int = 180) -> list[dict]:
    """Flag accounts overdue for recertification."""
    cutoff = datetime.utcnow() - timedelta(days=cert_interval_days)
    findings = []
    for acct in accounts:
        cert_date = acct.get("last_certified", "")
        if not cert_date:
            findings.append({"account": acct.get("username", ""),
                             "issue": "never_certified", "severity": "critical",
                             "detail": "Account has never been certified"})
            continue
        try:
            cert_dt = datetime.strptime(cert_date, "%Y-%m-%d")
            if cert_dt < cutoff:
                findings.append({"account": acct.get("username", ""),
                                 "issue": "overdue_recertification", "severity": "high",
                                 "detail": f"Last certified {cert_date}, exceeds {cert_interval_days}-day cycle"})
        except ValueError:
            pass
    return findings


def generate_report(accounts: list[dict], stale_days: int, cert_days: int) -> dict:
    """Run all checks and produce a consolidated JSON report."""
    findings = []
    findings.extend(check_stale_accounts(accounts, stale_days))
    findings.extend(check_shared_accounts(accounts))
    findings.extend(check_excessive_privileges(accounts))
    findings.extend(check_recertification(accounts, cert_days))

    severity_counts = {}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    return {
        "report": "privileged_account_access_review",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_accounts": len(accounts),
        "total_findings": len(findings),
        "severity_summary": severity_counts,
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="Privileged Account Access Review Agent")
    parser.add_argument("--input", required=True, help="CSV file with privileged account inventory")
    parser.add_argument("--stale-days", type=int, default=90, help="Max days of inactivity (default: 90)")
    parser.add_argument("--cert-days", type=int, default=180, help="Recertification interval in days (default: 180)")
    parser.add_argument("--output", help="Output JSON file path")
    args = parser.parse_args()

    accounts = load_accounts(args.input)
    report = generate_report(accounts, args.stale_days, args.cert_days)

    output = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
