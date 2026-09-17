#!/usr/bin/env python3
"""Ransomware backup strategy audit agent.

Audits backup infrastructure for ransomware resilience by checking
3-2-1 backup rule compliance, air-gapped/immutable backup presence,
backup encryption status, recovery point objectives (RPO), and
backup integrity verification schedules.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone


def check_veeam_backups(server_url, token):
    """Check Veeam backup status via REST API."""
    try:
        import requests
    except ImportError:
        return [{"check": "Veeam API", "status": "SKIP", "severity": "INFO",
                 "detail": "requests library not installed"}]

    findings = []
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    # Check backup jobs
    try:
        resp = requests.get(f"{server_url}/api/v1/jobs", headers=headers, timeout=30)
        resp.raise_for_status()
        jobs = resp.json().get("data", [])
        for job in jobs:
            job_name = job.get("name", "Unknown")
            last_result = job.get("lastResult", "None")
            schedule_enabled = job.get("scheduleEnabled", False)
            if last_result == "Failed":
                findings.append({
                    "check": f"Backup job: {job_name}",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "detail": "Last backup failed",
                })
            elif not schedule_enabled:
                findings.append({
                    "check": f"Backup job: {job_name}",
                    "status": "WARN",
                    "severity": "HIGH",
                    "detail": "Schedule disabled",
                })
            else:
                findings.append({
                    "check": f"Backup job: {job_name}",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": f"Last result: {last_result}",
                })
    except Exception as e:
        findings.append({"check": "Veeam job check", "status": "ERROR",
                         "severity": "HIGH", "detail": str(e)})
    return findings


def check_restic_repository(repo_path, password_file=None):
    """Audit a Restic backup repository for integrity and freshness."""
    findings = []
    restic_bin = None
    for name in ["restic", "restic.exe"]:
        for d in os.environ.get("PATH", "").split(os.pathsep):
            if os.path.isfile(os.path.join(d, name)):
                restic_bin = os.path.join(d, name)
                break
    if not restic_bin:
        findings.append({"check": "Restic binary", "status": "SKIP",
                         "severity": "INFO", "detail": "restic not found"})
        return findings

    env = dict(os.environ)
    env["RESTIC_REPOSITORY"] = repo_path
    if password_file:
        env["RESTIC_PASSWORD_FILE"] = password_file

    # Check snapshots
    try:
        result = subprocess.run(
            [restic_bin, "snapshots", "--json"],
            capture_output=True, text=True, timeout=120, env=env,
        )
        if result.returncode == 0:
            snapshots = json.loads(result.stdout)
            if not snapshots:
                findings.append({"check": "Snapshots exist", "status": "FAIL",
                                 "severity": "CRITICAL", "detail": "No snapshots found"})
            else:
                latest = max(snapshots, key=lambda s: s.get("time", ""))
                latest_time = latest.get("time", "")[:19]
                findings.append({"check": "Latest snapshot", "status": "PASS",
                                 "severity": "INFO",
                                 "detail": f"{latest_time} ({len(snapshots)} total)"})
                try:
                    latest_dt = datetime.fromisoformat(latest_time.replace("Z", "+00:00"))
                    age_hours = (datetime.now(timezone.utc) - latest_dt).total_seconds() / 3600
                    if age_hours > 48:
                        findings.append({"check": "Backup freshness", "status": "FAIL",
                                        "severity": "HIGH",
                                        "detail": f"Latest backup is {age_hours:.0f}h old (>48h)"})
                    elif age_hours > 24:
                        findings.append({"check": "Backup freshness", "status": "WARN",
                                        "severity": "MEDIUM",
                                        "detail": f"Latest backup is {age_hours:.0f}h old (>24h)"})
                except (ValueError, TypeError):
                    pass
        else:
            findings.append({"check": "Repository access", "status": "FAIL",
                             "severity": "CRITICAL", "detail": result.stderr[:200]})
    except subprocess.TimeoutExpired:
        findings.append({"check": "Repository access", "status": "FAIL",
                         "severity": "HIGH", "detail": "Command timed out"})

    # Check repository integrity
    try:
        result = subprocess.run(
            [restic_bin, "check", "--read-data-subset=1%"],
            capture_output=True, text=True, timeout=300, env=env,
        )
        if result.returncode == 0:
            findings.append({"check": "Repository integrity", "status": "PASS",
                             "severity": "INFO", "detail": "Integrity check passed"})
        else:
            findings.append({"check": "Repository integrity", "status": "FAIL",
                             "severity": "CRITICAL", "detail": "Integrity check failed"})
    except subprocess.TimeoutExpired:
        findings.append({"check": "Repository integrity", "status": "WARN",
                         "severity": "MEDIUM", "detail": "Integrity check timed out"})

    return findings


def audit_321_rule(backup_config):
    """Audit compliance with the 3-2-1 backup rule."""
    findings = []
    copies = backup_config.get("copies", 0)
    media_types = backup_config.get("media_types", [])
    offsite_locations = backup_config.get("offsite_locations", [])
    immutable = backup_config.get("immutable_backup", False)
    air_gapped = backup_config.get("air_gapped", False)

    # 3 copies
    if copies >= 3:
        findings.append({"check": "3-2-1: At least 3 copies", "status": "PASS",
                         "severity": "INFO", "detail": f"{copies} copies"})
    else:
        findings.append({"check": "3-2-1: At least 3 copies", "status": "FAIL",
                         "severity": "CRITICAL",
                         "detail": f"Only {copies} copies (need 3)"})

    # 2 different media types
    if len(media_types) >= 2:
        findings.append({"check": "3-2-1: 2 different media types", "status": "PASS",
                         "severity": "INFO", "detail": ", ".join(media_types)})
    else:
        findings.append({"check": "3-2-1: 2 different media types", "status": "FAIL",
                         "severity": "HIGH",
                         "detail": f"Only {len(media_types)} type(s): {', '.join(media_types)}"})

    # 1 offsite copy
    if offsite_locations:
        findings.append({"check": "3-2-1: 1 offsite copy", "status": "PASS",
                         "severity": "INFO", "detail": ", ".join(offsite_locations)})
    else:
        findings.append({"check": "3-2-1: 1 offsite copy", "status": "FAIL",
                         "severity": "CRITICAL", "detail": "No offsite backup"})

    # Immutable backup (ransomware protection)
    if immutable:
        findings.append({"check": "Immutable backup", "status": "PASS",
                         "severity": "INFO", "detail": "WORM/immutable storage enabled"})
    else:
        findings.append({"check": "Immutable backup", "status": "FAIL",
                         "severity": "CRITICAL",
                         "detail": "No immutable backup - vulnerable to ransomware encryption"})

    # Air-gapped backup
    if air_gapped:
        findings.append({"check": "Air-gapped backup", "status": "PASS",
                         "severity": "INFO", "detail": "Offline/air-gapped copy exists"})
    else:
        findings.append({"check": "Air-gapped backup", "status": "WARN",
                         "severity": "HIGH",
                         "detail": "No air-gapped backup - consider tape or offline storage"})

    # Encryption
    if backup_config.get("encrypted", False):
        findings.append({"check": "Backup encryption", "status": "PASS",
                         "severity": "INFO"})
    else:
        findings.append({"check": "Backup encryption", "status": "FAIL",
                         "severity": "HIGH", "detail": "Backups are not encrypted"})

    return findings


def format_summary(all_findings):
    """Print audit summary."""
    print(f"\n{'='*60}")
    print("  Ransomware Backup Strategy Audit")
    print(f"{'='*60}")

    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    pass_count = sum(1 for f in all_findings if f.get("status") == "PASS")
    fail_count = sum(1 for f in all_findings if f.get("status") == "FAIL")
    warn_count = sum(1 for f in all_findings if f.get("status") == "WARN")

    print(f"  Checks   : {len(all_findings)}")
    print(f"  Passed   : {pass_count}")
    print(f"  Failed   : {fail_count}")
    print(f"  Warnings : {warn_count}")

    print("\n  By Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            print(f"    {sev:10s}: {count}")

    print("\n  Detailed Results:")
    for f in all_findings:
        status_icon = "OK" if f["status"] == "PASS" else "!!" if f["status"] == "FAIL" else "~~"
        detail = f.get("detail", "")
        print(f"    [{status_icon}] [{f['severity']:8s}] {f['check']}"
              + (f": {detail}" if detail else ""))

    return severity_counts


def main():
    parser = argparse.ArgumentParser(
        description="Ransomware backup strategy audit agent"
    )
    parser.add_argument("--config", help="Backup configuration JSON file")
    parser.add_argument("--restic-repo", help="Restic repository path to audit")
    parser.add_argument("--restic-password-file", help="Restic password file")
    parser.add_argument("--veeam-url", help="Veeam server URL")
    parser.add_argument("--veeam-token", help="Veeam API token")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    all_findings = []

    if args.config:
        with open(args.config, "r") as f:
            backup_config = json.load(f)
        all_findings.extend(audit_321_rule(backup_config))

    if args.restic_repo:
        all_findings.extend(check_restic_repository(args.restic_repo, args.restic_password_file))

    if args.veeam_url and args.veeam_token:
        all_findings.extend(check_veeam_backups(args.veeam_url, args.veeam_token))

    if not all_findings:
        print("[!] No audit sources specified. Use --config, --restic-repo, or --veeam-url.",
              file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    severity_counts = format_summary(all_findings)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "Ransomware Backup Audit",
        "findings": all_findings,
        "severity_counts": severity_counts,
        "risk_level": (
            "CRITICAL" if severity_counts.get("CRITICAL", 0) > 0
            else "HIGH" if severity_counts.get("HIGH", 0) > 0
            else "MEDIUM" if severity_counts.get("MEDIUM", 0) > 0
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
