#!/usr/bin/env python3
"""
Cloud Infrastructure Penetration Test — Automation Process

Automates AWS/Azure/GCP enumeration and security assessment.

Usage:
    python process.py --provider aws --profile testuser --output ./results
"""

import subprocess
import json
import argparse
import datetime
from pathlib import Path


def run_command(cmd: list[str], timeout: int = 300) -> tuple[str, str, int]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return "", str(e), -1


def aws_enumerate(profile: str, output_dir: Path) -> dict:
    """Enumerate AWS resources."""
    print("[*] Enumerating AWS resources...")
    results = {}

    checks = {
        "identity": ["aws", "sts", "get-caller-identity", "--profile", profile],
        "s3_buckets": ["aws", "s3api", "list-buckets", "--profile", profile],
        "ec2_instances": ["aws", "ec2", "describe-instances", "--profile", profile],
        "lambda_functions": ["aws", "lambda", "list-functions", "--profile", profile],
        "iam_users": ["aws", "iam", "list-users", "--profile", profile],
        "rds_instances": ["aws", "rds", "describe-db-instances", "--profile", profile],
    }

    for name, cmd in checks.items():
        stdout, stderr, rc = run_command(cmd)
        if rc == 0:
            try:
                results[name] = json.loads(stdout)
            except json.JSONDecodeError:
                results[name] = {"raw": stdout}
        else:
            results[name] = {"error": stderr[:200]}

    with open(output_dir / "aws_enum.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    return results


def check_public_s3(buckets: list[str], profile: str) -> list[dict]:
    """Check S3 buckets for public access."""
    findings = []
    for bucket in buckets:
        stdout, stderr, rc = run_command(
            ["aws", "s3api", "get-bucket-acl", "--bucket", bucket, "--profile", profile]
        )
        if rc == 0:
            acl = json.loads(stdout)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI", "").endswith("AllUsers") or \
                   grantee.get("URI", "").endswith("AuthenticatedUsers"):
                    findings.append({
                        "bucket": bucket,
                        "grantee": grantee.get("URI"),
                        "permission": grant.get("Permission"),
                        "severity": "Critical"
                    })
    return findings


def generate_report(provider: str, enum_results: dict, findings: list[dict],
                     output_dir: Path) -> str:
    """Generate cloud pentest report."""
    report_file = output_dir / f"{provider}_pentest_report.md"
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    with open(report_file, "w") as f:
        f.write(f"# {provider.upper()} Cloud Penetration Test Report\n\n")
        f.write(f"**Generated:** {timestamp}\n\n---\n\n")

        f.write("## Resource Inventory\n\n")
        for resource, data in enum_results.items():
            f.write(f"### {resource}\n")
            if isinstance(data, dict) and "error" in data:
                f.write(f"Access denied: {data['error'][:100]}\n\n")
            else:
                f.write(f"```json\n{json.dumps(data, indent=2, default=str)[:500]}\n```\n\n")

        if findings:
            f.write("## Security Findings\n\n")
            for finding in findings:
                f.write(f"### [{finding['severity']}] {finding.get('bucket', finding.get('resource', 'Unknown'))}\n")
                f.write(f"- Issue: {finding.get('grantee', finding.get('issue', ''))}\n")
                f.write(f"- Permission: {finding.get('permission', '')}\n\n")

        f.write("## Recommendations\n\n")
        f.write("1. Enable S3 Block Public Access at account level\n")
        f.write("2. Implement least-privilege IAM policies\n")
        f.write("3. Enforce IMDSv2 on all EC2 instances\n")
        f.write("4. Enable CloudTrail logging in all regions\n")
        f.write("5. Use AWS Organizations SCPs for guardrails\n")

    print(f"[+] Report: {report_file}")
    return str(report_file)


def main():
    parser = argparse.ArgumentParser(description="Cloud Pentest Automation")
    parser.add_argument("--provider", choices=["aws", "azure", "gcp"], default="aws")
    parser.add_argument("--profile", default="default")
    parser.add_argument("--output", default="./results")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.provider == "aws":
        results = aws_enumerate(args.profile, output_dir)
        buckets = [b["Name"] for b in results.get("s3_buckets", {}).get("Buckets", [])]
        findings = check_public_s3(buckets[:20], args.profile)
        generate_report("aws", results, findings, output_dir)

    print(f"\n[+] Cloud pentest automation complete for {args.provider}")


if __name__ == "__main__":
    main()
