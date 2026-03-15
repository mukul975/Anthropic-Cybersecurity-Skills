#!/usr/bin/env python3
"""Agent for scanning Infrastructure as Code templates for security misconfigurations."""

import json
import argparse
import subprocess
from datetime import datetime
from collections import Counter
from pathlib import Path


def run_checkov(target_path, framework=None):
    """Run Checkov IaC security scanner."""
    cmd = ["checkov", "-d", target_path, "--output", "json", "--quiet"]
    if framework:
        cmd.extend(["--framework", framework])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    try:
        return json.loads(result.stdout) if result.stdout.strip() else {"error": result.stderr}
    except json.JSONDecodeError:
        return {"raw": result.stdout[:2000], "error": result.stderr}


def run_tfsec(target_path):
    """Run tfsec Terraform security scanner."""
    cmd = ["tfsec", target_path, "--format", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    try:
        return json.loads(result.stdout) if result.stdout.strip() else {"error": result.stderr}
    except json.JSONDecodeError:
        return {"raw": result.stdout[:2000]}


def analyze_checkov_results(results):
    """Analyze Checkov scan results and categorize findings."""
    if isinstance(results, list):
        all_checks = results
    elif isinstance(results, dict):
        all_checks = results.get("results", {}).get("failed_checks", [])
    else:
        return {"error": "Invalid results format"}

    by_severity = Counter()
    by_resource_type = Counter()
    by_check = Counter()
    findings = []

    for check in all_checks:
        severity = check.get("severity", check.get("check_result", {}).get("severity", "MEDIUM"))
        by_severity[severity] += 1
        resource = check.get("resource", "unknown")
        by_resource_type[resource.split(".")[0]] += 1
        by_check[check.get("check_id", "unknown")] += 1
        if severity in ("CRITICAL", "HIGH"):
            findings.append({
                "check_id": check.get("check_id", ""),
                "check_name": check.get("check", check.get("name", "")),
                "resource": resource,
                "file": check.get("file_path", check.get("repo_file_path", "")),
                "line": check.get("file_line_range", []),
                "severity": severity,
                "guideline": check.get("guideline", ""),
            })

    return {
        "total_failures": len(all_checks),
        "by_severity": dict(by_severity),
        "by_resource_type": dict(by_resource_type.most_common(10)),
        "top_checks": dict(by_check.most_common(10)),
        "critical_findings": findings[:30],
    }


def scan_terraform_files(dir_path):
    """Scan Terraform files for common security misconfigurations."""
    findings = []
    tf_files = list(Path(dir_path).rglob("*.tf"))

    risky_patterns = {
        '"0.0.0.0/0"': {"issue": "Open CIDR block", "severity": "HIGH"},
        "cidr_blocks = [": {"issue": "Check CIDR block restrictions", "severity": "MEDIUM"},
        "publicly_accessible": {"issue": "Public accessibility setting", "severity": "HIGH"},
        "encrypted = false": {"issue": "Encryption disabled", "severity": "CRITICAL"},
        "enable_logging = false": {"issue": "Logging disabled", "severity": "HIGH"},
        "versioning {": {"issue": "Check versioning enabled", "severity": "MEDIUM"},
        'protocol = "-1"': {"issue": "All protocols allowed", "severity": "HIGH"},
        "from_port = 0": {"issue": "All ports open", "severity": "HIGH"},
    }

    for tf_file in tf_files:
        try:
            content = tf_file.read_text(encoding="utf-8", errors="ignore")
            for pattern, info in risky_patterns.items():
                if pattern in content:
                    lines = [i + 1 for i, line in enumerate(content.split("\n"))
                             if pattern in line]
                    for line in lines[:5]:
                        findings.append({
                            "file": str(tf_file),
                            "line": line,
                            "pattern": pattern,
                            "issue": info["issue"],
                            "severity": info["severity"],
                        })
        except (OSError, PermissionError):
            continue

    return findings


def generate_ci_config(scanner="checkov", framework="terraform"):
    """Generate CI/CD pipeline config for IaC scanning."""
    configs = {
        "github_actions": f"""name: IaC Security Scan
on: [push, pull_request]
jobs:
  iac-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run {scanner}
        uses: bridgecrewio/checkov-action@master
        with:
          directory: .
          framework: {framework}
          soft_fail: false
          output_format: sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
""",
        "gitlab_ci": f"""iac-scan:
  image: bridgecrew/checkov:latest
  script:
    - checkov -d . --framework {framework} --output junitxml > checkov.xml
  artifacts:
    reports:
      junit: checkov.xml
""",
    }
    return configs


def main():
    parser = argparse.ArgumentParser(description="IaC Security Scanning Agent")
    parser.add_argument("--scan-dir", help="Directory to scan")
    parser.add_argument("--framework", choices=["terraform", "cloudformation",
                                                  "kubernetes", "helm", "all"])
    parser.add_argument("--scanner", choices=["checkov", "tfsec", "builtin"], default="builtin")
    parser.add_argument("--gen-ci", action="store_true", help="Generate CI config")
    parser.add_argument("--output", default="iac_security_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}

    if args.scan_dir:
        if args.scanner == "checkov":
            raw = run_checkov(args.scan_dir, args.framework)
            analysis = analyze_checkov_results(raw)
            report["results"]["checkov"] = analysis
            print(f"[+] Checkov: {analysis.get('total_failures', 0)} failures")
        elif args.scanner == "tfsec":
            raw = run_tfsec(args.scan_dir)
            report["results"]["tfsec"] = raw
            print("[+] tfsec scan complete")
        else:
            findings = scan_terraform_files(args.scan_dir)
            report["results"]["builtin_scan"] = findings
            print(f"[+] Built-in scan: {len(findings)} findings")

    if args.gen_ci:
        configs = generate_ci_config(args.scanner or "checkov", args.framework or "terraform")
        report["results"]["ci_configs"] = configs
        print("[+] CI configs generated")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
