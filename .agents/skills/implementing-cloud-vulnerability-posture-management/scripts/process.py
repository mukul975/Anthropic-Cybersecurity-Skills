#!/usr/bin/env python3
"""Cloud Vulnerability Posture Management Tool.

Orchestrates multi-cloud security posture assessments using Prowler,
aggregates findings, and generates compliance reports.
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import boto3
except ImportError:
    boto3 = None


def run_prowler_aws(profile=None, region=None, compliance=None, output_dir="./prowler_output"):
    """Execute Prowler scan against AWS account."""
    cmd = ["prowler", "aws", "--output-formats", "json-ocsf,csv", "--output-directory", output_dir]
    if profile:
        cmd.extend(["--profile", profile])
    if region:
        cmd.extend(["--region", region])
    if compliance:
        cmd.extend(["--compliance", compliance])
    print(f"[*] Running Prowler AWS scan...")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
    if result.returncode == 0:
        print("[+] Prowler AWS scan completed successfully")
    else:
        print(f"[-] Prowler AWS scan failed: {result.stderr[:500]}")
    return result.returncode == 0


def run_prowler_azure(subscription_id=None, output_dir="./prowler_output"):
    """Execute Prowler scan against Azure subscription."""
    cmd = ["prowler", "azure", "--output-formats", "json-ocsf,csv", "--output-directory", output_dir]
    if subscription_id:
        cmd.extend(["--subscription-ids", subscription_id])
    print(f"[*] Running Prowler Azure scan...")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
    if result.returncode == 0:
        print("[+] Prowler Azure scan completed successfully")
    else:
        print(f"[-] Prowler Azure scan failed: {result.stderr[:500]}")
    return result.returncode == 0


def get_aws_security_hub_findings(region="us-east-1", severity="CRITICAL"):
    """Fetch findings from AWS Security Hub."""
    if not boto3:
        print("[-] boto3 not installed")
        return []
    client = boto3.client("securityhub", region_name=region)
    findings = []
    paginator = client.get_paginator("get_findings")
    for page in paginator.paginate(
        Filters={
            "SeverityLabel": [{"Value": severity, "Comparison": "EQUALS"}],
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        },
        MaxResults=100,
    ):
        findings.extend(page.get("Findings", []))
    print(f"[+] Retrieved {len(findings)} {severity} findings from Security Hub")
    return findings


def parse_prowler_output(output_dir):
    """Parse Prowler JSON-OCSF output files."""
    findings = []
    output_path = Path(output_dir)
    for json_file in output_path.rglob("*.ocsf.json"):
        with open(json_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                    findings.append({
                        "provider": finding.get("cloud", {}).get("provider", "unknown"),
                        "account": finding.get("cloud", {}).get("account", {}).get("uid", ""),
                        "region": finding.get("cloud", {}).get("region", ""),
                        "service": finding.get("resources", [{}])[0].get("type", "") if finding.get("resources") else "",
                        "check_id": finding.get("metadata", {}).get("uid", ""),
                        "title": finding.get("finding_info", {}).get("title", ""),
                        "severity": finding.get("severity", "unknown"),
                        "status": finding.get("status", ""),
                        "description": finding.get("finding_info", {}).get("desc", ""),
                        "remediation": finding.get("remediation", {}).get("desc", ""),
                        "resource_uid": finding.get("resources", [{}])[0].get("uid", "") if finding.get("resources") else "",
                    })
                except (json.JSONDecodeError, KeyError, IndexError):
                    continue
    return findings


def generate_posture_report(findings, output_path):
    """Generate cloud security posture report."""
    severity_map = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    failed = [f for f in findings if f.get("status", "").lower() in ("fail", "failed")]
    passed = [f for f in findings if f.get("status", "").lower() in ("pass", "passed")]

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_checks": len(findings),
        "passed": len(passed),
        "failed": len(failed),
        "pass_rate": round(len(passed) / max(len(findings), 1) * 100, 1),
        "failed_by_severity": {},
        "failed_by_provider": {},
        "failed_by_service": {},
        "top_findings": [],
    }

    for f in failed:
        sev = str(f.get("severity", "unknown")).lower()
        provider = f.get("provider", "unknown")
        service = f.get("service", "unknown")
        report["failed_by_severity"][sev] = report["failed_by_severity"].get(sev, 0) + 1
        report["failed_by_provider"][provider] = report["failed_by_provider"].get(provider, 0) + 1
        report["failed_by_service"][service] = report["failed_by_service"].get(service, 0) + 1

    critical_high = [f for f in failed if str(f.get("severity", "")).lower() in ("critical", "high")]
    critical_high.sort(key=lambda x: severity_map.get(str(x.get("severity", "")).lower(), 5))
    report["top_findings"] = critical_high[:20]

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    print(f"\n[+] Cloud Posture Report: {output_path}")
    print(f"    Total checks: {report['total_checks']}")
    print(f"    Passed: {report['passed']} | Failed: {report['failed']}")
    print(f"    Pass rate: {report['pass_rate']}%")
    print(f"    Failed by severity: {json.dumps(report['failed_by_severity'])}")
    return report


def main():
    parser = argparse.ArgumentParser(description="Cloud Vulnerability Posture Management")
    parser.add_argument("--scan-aws", action="store_true", help="Run Prowler AWS scan")
    parser.add_argument("--scan-azure", action="store_true", help="Run Prowler Azure scan")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--region", help="AWS region")
    parser.add_argument("--subscription", help="Azure subscription ID")
    parser.add_argument("--compliance", help="Compliance framework (e.g., cis_1.5_aws)")
    parser.add_argument("--parse", help="Parse Prowler output directory")
    parser.add_argument("--security-hub", action="store_true", help="Fetch from AWS Security Hub")
    parser.add_argument("--output", default="cloud_posture_report.json")
    parser.add_argument("--output-dir", default="./prowler_output")
    args = parser.parse_args()

    if args.scan_aws:
        run_prowler_aws(args.profile, args.region, args.compliance, args.output_dir)
    if args.scan_azure:
        run_prowler_azure(args.subscription, args.output_dir)
    if args.parse:
        findings = parse_prowler_output(args.parse)
        print(f"[*] Parsed {len(findings)} findings")
        generate_posture_report(findings, args.output)
    if args.security_hub:
        findings = get_aws_security_hub_findings(args.region or "us-east-1")
        print(f"[*] Retrieved {len(findings)} Security Hub findings")
    if not any([args.scan_aws, args.scan_azure, args.parse, args.security_hub]):
        parser.print_help()


if __name__ == "__main__":
    main()
