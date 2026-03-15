#!/usr/bin/env python3
"""Agent for auditing Terraform infrastructure for security misconfigurations."""

import os
import json
import argparse
import subprocess
from datetime import datetime
from pathlib import Path


def run_checkov(terraform_dir, output_format="json"):
    """Run Checkov static analysis on Terraform code."""
    cmd = ["checkov", "-d", terraform_dir, "--framework", "terraform", "--output", output_format, "--compact"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if output_format == "json":
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"raw_output": result.stdout, "error": result.stderr}
    return result.stdout


def run_checkov_on_plan(plan_json_path):
    """Run Checkov on a Terraform plan JSON file for accurate analysis."""
    cmd = ["checkov", "-f", plan_json_path, "--framework", "terraform_plan", "--output", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"raw_output": result.stdout}


def run_tfsec(terraform_dir, min_severity="HIGH"):
    """Run tfsec Terraform security scanner."""
    cmd = ["tfsec", terraform_dir, "--format", "json", "--minimum-severity", min_severity]
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"raw_output": result.stdout}


def parse_checkov_results(checkov_output):
    """Parse Checkov output and extract failed checks with details."""
    findings = []
    if isinstance(checkov_output, list):
        checks = checkov_output
    elif isinstance(checkov_output, dict):
        checks = checkov_output.get("results", {}).get("failed_checks", [])
    else:
        return findings
    for check in checks:
        if isinstance(check, dict):
            findings.append({
                "check_id": check.get("check_id", ""),
                "check_name": check.get("check_result", {}).get("check", {}).get("name", check.get("name", "")),
                "resource": check.get("resource", ""),
                "file": check.get("file_path", ""),
                "line": check.get("file_line_range", []),
                "severity": check.get("severity", "UNKNOWN"),
                "guideline": check.get("guideline", ""),
            })
    return findings


def parse_tfsec_results(tfsec_output):
    """Parse tfsec output and extract findings."""
    findings = []
    results = tfsec_output.get("results", [])
    if results is None:
        return findings
    for r in results:
        findings.append({
            "rule_id": r.get("rule_id", ""),
            "description": r.get("description", ""),
            "severity": r.get("severity", ""),
            "resource": r.get("resource", ""),
            "location": f"{r.get('location', {}).get('filename', '')}:{r.get('location', {}).get('start_line', '')}",
            "resolution": r.get("resolution", ""),
        })
    return findings


def scan_tf_plan_for_issues(plan_json_path):
    """Directly scan a Terraform plan JSON for common security issues."""
    with open(plan_json_path) as f:
        plan = json.load(f)
    issues = []
    for change in plan.get("resource_changes", []):
        after = change.get("change", {}).get("after", {})
        resource_type = change.get("type", "")
        address = change.get("address", "")
        if resource_type == "aws_s3_bucket":
            if not after.get("server_side_encryption_configuration"):
                issues.append({"resource": address, "issue": "S3 bucket without encryption", "severity": "HIGH"})
        if resource_type == "aws_security_group_rule":
            for cidr in after.get("cidr_blocks", []):
                if cidr == "0.0.0.0/0" and after.get("from_port", 0) <= 22 <= after.get("to_port", 0):
                    issues.append({"resource": address, "issue": "SSH open to 0.0.0.0/0", "severity": "CRITICAL"})
        if resource_type == "aws_iam_policy":
            policy_doc = after.get("policy", "{}")
            if isinstance(policy_doc, str):
                try:
                    doc = json.loads(policy_doc)
                    for stmt in doc.get("Statement", []):
                        if stmt.get("Action") == "*" and stmt.get("Effect") == "Allow":
                            issues.append({"resource": address, "issue": "IAM wildcard actions", "severity": "CRITICAL"})
                except json.JSONDecodeError:
                    pass
    return issues


def generate_report(checkov_findings, tfsec_findings, plan_issues):
    """Generate combined audit report."""
    all_findings = []
    for f in checkov_findings:
        f["source"] = "checkov"
        all_findings.append(f)
    for f in tfsec_findings:
        f["source"] = "tfsec"
        all_findings.append(f)
    for f in plan_issues:
        f["source"] = "plan_scan"
        all_findings.append(f)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "LOW"), 4))
    return {
        "audit_date": datetime.utcnow().isoformat(),
        "total_findings": len(all_findings),
        "critical": sum(1 for f in all_findings if f.get("severity") == "CRITICAL"),
        "high": sum(1 for f in all_findings if f.get("severity") == "HIGH"),
        "findings": all_findings,
    }


def main():
    parser = argparse.ArgumentParser(description="Terraform Security Audit Agent")
    parser.add_argument("--terraform-dir", help="Directory with Terraform code")
    parser.add_argument("--plan-json", help="Terraform plan JSON file")
    parser.add_argument("--output", default="terraform_audit.json")
    parser.add_argument("--tool", choices=["checkov", "tfsec", "both", "plan_only"], default="both")
    args = parser.parse_args()

    checkov_findings = []
    tfsec_findings = []
    plan_issues = []

    if args.terraform_dir:
        if args.tool in ("checkov", "both"):
            print("[+] Running Checkov...")
            raw = run_checkov(args.terraform_dir)
            checkov_findings = parse_checkov_results(raw)
            print(f"    Found {len(checkov_findings)} issues")
        if args.tool in ("tfsec", "both"):
            print("[+] Running tfsec...")
            raw = run_tfsec(args.terraform_dir)
            tfsec_findings = parse_tfsec_results(raw)
            print(f"    Found {len(tfsec_findings)} issues")

    if args.plan_json:
        print("[+] Scanning Terraform plan...")
        plan_issues = scan_tf_plan_for_issues(args.plan_json)
        print(f"    Found {len(plan_issues)} issues")

    report = generate_report(checkov_findings, tfsec_findings, plan_issues)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] {report['critical']} critical, {report['high']} high out of {report['total_findings']} total")
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
