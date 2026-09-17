#!/usr/bin/env python3
"""ScoutSuite AWS account enumeration and security audit agent.

Wraps the ScoutSuite CLI to perform comprehensive AWS security audits,
parses the generated JSON results, and produces a structured findings
report covering IAM, S3, EC2, RDS, Lambda, and other AWS services.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone


def find_scoutsuite_binary():
    """Locate the scout CLI binary."""
    custom_path = os.environ.get("SCOUTSUITE_PATH")
    if custom_path and os.path.isfile(custom_path):
        return custom_path
    for name in ["scout", "scout.exe"]:
        for directory in os.environ.get("PATH", "").split(os.pathsep):
            full_path = os.path.join(directory, name)
            if os.path.isfile(full_path):
                return full_path
    return None


def run_scoutsuite(scout_bin, profile=None, services=None, regions=None,
                   result_dir=None, max_workers=None, no_browser=True):
    """Execute ScoutSuite AWS scan."""
    if scout_bin:
        cmd = [scout_bin, "aws"]
    else:
        cmd = [sys.executable, "-m", "ScoutSuite", "aws"]

    if profile:
        cmd.extend(["--profile", profile])
    if services:
        cmd.extend(["--services"] + services)
    if regions:
        cmd.extend(["--regions"] + regions)
    if result_dir:
        cmd.extend(["--report-dir", result_dir])
    if max_workers:
        cmd.extend(["--max-workers", str(max_workers)])
    if no_browser:
        cmd.append("--no-browser")

    print(f"[*] Running: {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=1800,
    )
    if result.returncode != 0:
        print(f"[!] ScoutSuite exited with code {result.returncode}", file=sys.stderr)
        if result.stderr:
            print(f"    stderr: {result.stderr[:500]}", file=sys.stderr)
    return result.returncode, result.stdout, result.stderr


def find_latest_results(result_dir=None):
    """Find the most recent ScoutSuite results JSON file."""
    import glob as _glob
    if result_dir:
        search_dirs = [result_dir]
    else:
        search_dirs = [
            os.path.expanduser("~/.local/share/scoutsuite-report"),
            "scoutsuite-report",
            os.path.join(os.getcwd(), "scoutsuite-report"),
        ]
    for base_dir in search_dirs:
        pattern = os.path.join(base_dir, "scoutsuite-results", "scoutsuite_results_*.js")
        matches = _glob.glob(pattern)
        if not matches:
            pattern = os.path.join(base_dir, "**", "scoutsuite_results_*.js")
            matches = _glob.glob(pattern, recursive=True)
        if matches:
            return max(matches, key=os.path.getmtime)
    return None


def parse_results(results_file):
    """Parse ScoutSuite results JavaScript file into Python dict."""
    print(f"[*] Parsing results from {results_file}")
    with open(results_file, "r", encoding="utf-8") as f:
        content = f.read()
    json_start = content.find("{")
    if json_start == -1:
        print("[!] Could not find JSON data in results file", file=sys.stderr)
        return None
    json_data = content[json_start:].rstrip().rstrip(";")
    return json.loads(json_data)


def extract_findings(results):
    """Extract security findings from ScoutSuite results."""
    findings = []
    services = results.get("services", {})
    severity_map = {"danger": "CRITICAL", "warning": "HIGH", "info": "INFO"}

    for service_name, service_data in services.items():
        rules = service_data.get("findings", {})
        for rule_id, rule_data in rules.items():
            flagged = rule_data.get("flagged_items", 0)
            if flagged == 0:
                continue
            level = rule_data.get("level", "warning")
            findings.append({
                "service": service_name,
                "rule_id": rule_id,
                "description": rule_data.get("description", ""),
                "severity": severity_map.get(level, "MEDIUM"),
                "level": level,
                "flagged_items": flagged,
                "checked_items": rule_data.get("checked_items", 0),
                "rationale": rule_data.get("rationale", ""),
                "remediation": rule_data.get("remediation", ""),
                "references": rule_data.get("references", []),
                "compliance": rule_data.get("compliance", []),
            })

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
    findings.sort(key=lambda f: (severity_order.get(f["severity"], 9), -f["flagged_items"]))
    return findings


def extract_account_info(results):
    """Extract AWS account metadata from results."""
    last_run = results.get("last_run", {})
    return {
        "account_id": results.get("account_id", "unknown"),
        "partition": results.get("partition", "aws"),
        "run_time": last_run.get("time", ""),
        "version": last_run.get("version", ""),
        "ruleset": last_run.get("ruleset_name", "default"),
        "services_scanned": list(results.get("services", {}).keys()),
    }


def format_summary(account_info, findings):
    """Print a human-readable summary."""
    print(f"\n{'='*60}")
    print("  ScoutSuite AWS Security Audit Report")
    print(f"{'='*60}")
    print(f"  Account     : {account_info['account_id']}")
    print(f"  Partition   : {account_info['partition']}")
    print(f"  Scan Time   : {account_info['run_time']}")
    print(f"  Services    : {', '.join(account_info['services_scanned'])}")
    print(f"  Failing Rules: {len(findings)}")

    severity_counts = {}
    for f in findings:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\n  Severity Breakdown:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            print(f"    {sev:10s}: {count}")

    by_service = {}
    for f in findings:
        by_service.setdefault(f["service"], []).append(f)

    print("\n  Findings by Service:")
    for svc, items in sorted(by_service.items(), key=lambda x: -len(x[1])):
        danger = sum(1 for i in items if i["severity"] == "CRITICAL")
        warn = sum(1 for i in items if i["severity"] == "HIGH")
        print(f"    {svc:20s}: {len(items)} findings ({danger} critical, {warn} high)")

    print("\n  Top Critical/High Findings:")
    for f in findings[:15]:
        if f["severity"] in ("CRITICAL", "HIGH"):
            print(f"    [{f['severity']:8s}] {f['service']:12s} | "
                  f"{f['description'][:60]} ({f['flagged_items']} items)")

    return severity_counts


def main():
    parser = argparse.ArgumentParser(
        description="ScoutSuite AWS security audit agent"
    )
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--services", nargs="+",
                        help="Specific services to audit (e.g., iam s3 ec2 rds)")
    parser.add_argument("--regions", nargs="+",
                        help="Specific regions to audit")
    parser.add_argument("--result-dir", help="Directory for ScoutSuite report output")
    parser.add_argument("--results-file",
                        help="Parse existing results file instead of running scan")
    parser.add_argument("--max-workers", type=int, default=10,
                        help="Max concurrent API workers (default: 10)")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.results_file:
        results_file = args.results_file
    else:
        scout_bin = find_scoutsuite_binary()
        returncode, stdout, stderr = run_scoutsuite(
            scout_bin, args.profile, args.services, args.regions,
            args.result_dir, args.max_workers
        )
        if returncode != 0:
            print("[!] ScoutSuite scan failed", file=sys.stderr)
            sys.exit(1)
        results_file = find_latest_results(args.result_dir)

    if not results_file or not os.path.isfile(results_file):
        print("[!] Could not find ScoutSuite results file", file=sys.stderr)
        sys.exit(1)

    results = parse_results(results_file)
    if not results:
        sys.exit(1)

    account_info = extract_account_info(results)
    findings = extract_findings(results)
    severity_counts = format_summary(account_info, findings)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "ScoutSuite",
        "account": account_info,
        "severity_counts": severity_counts,
        "total_findings": len(findings),
        "findings": findings,
        "risk_level": (
            "CRITICAL" if severity_counts.get("CRITICAL", 0) > 0
            else "HIGH" if severity_counts.get("HIGH", 0) > 0
            else "MEDIUM" if len(findings) > 0
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
