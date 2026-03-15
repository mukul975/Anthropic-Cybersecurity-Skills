#!/usr/bin/env python3
"""
Gitleaks Secret Scanning Pipeline Script

Runs Gitleaks scans, manages baselines, evaluates findings,
and generates remediation reports.

Usage:
    python process.py --repo-path /path/to/repo --scan-type detect
    python process.py --repo-path . --scan-type protect --staged
    python process.py --repo-path . --baseline .gitleaks-baseline.json --output report.json
"""

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class SecretFinding:
    rule_id: str
    description: str
    file: str
    line: int
    commit: str
    author: str
    date: str
    secret: str
    entropy: float
    match: str
    tags: list = field(default_factory=list)
    is_new: bool = True


@dataclass
class ScanResult:
    findings: list = field(default_factory=list)
    new_findings: list = field(default_factory=list)
    baseline_findings: list = field(default_factory=list)
    commits_scanned: int = 0
    scan_duration: float = 0.0
    error: str = ""


def run_gitleaks(repo_path: str, scan_type: str = "detect",
                 baseline_path: Optional[str] = None,
                 commit_range: Optional[str] = None,
                 staged: bool = False,
                 config_path: Optional[str] = None) -> dict:
    """Execute Gitleaks and return JSON results."""
    cmd = ["gitleaks", scan_type, "--source", repo_path,
           "--report-format", "json", "--report-path", "/dev/stdout"]

    if baseline_path and os.path.exists(baseline_path):
        cmd.extend(["--baseline-path", baseline_path])

    if commit_range:
        cmd.extend(["--log-opts", commit_range])

    if staged:
        cmd.append("--staged")

    if config_path:
        cmd.extend(["--config", config_path])

    cmd.append("--verbose")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        findings = []
        if proc.stdout.strip():
            try:
                findings = json.loads(proc.stdout)
            except json.JSONDecodeError:
                pass

        return {
            "findings": findings if isinstance(findings, list) else [],
            "exit_code": proc.returncode,
            "stderr": proc.stderr
        }

    except subprocess.TimeoutExpired:
        return {"findings": [], "exit_code": -1, "stderr": "Scan timed out after 300s"}
    except FileNotFoundError:
        return {"findings": [], "exit_code": -1,
                "stderr": "gitleaks not found. Install from https://github.com/gitleaks/gitleaks"}


def parse_findings(raw_findings: list) -> list:
    """Parse raw Gitleaks JSON findings into SecretFinding objects."""
    findings = []
    for f in raw_findings:
        redacted_secret = redact_secret(f.get("Secret", ""))
        findings.append(SecretFinding(
            rule_id=f.get("RuleID", "unknown"),
            description=f.get("Description", ""),
            file=f.get("File", ""),
            line=f.get("StartLine", 0),
            commit=f.get("Commit", "")[:8],
            author=f.get("Author", ""),
            date=f.get("Date", ""),
            secret=redacted_secret,
            entropy=f.get("Entropy", 0.0),
            match=f.get("Match", "")[:100],
            tags=f.get("Tags", [])
        ))
    return findings


def redact_secret(secret: str) -> str:
    """Redact a secret, showing only first 4 and last 4 characters."""
    if len(secret) <= 12:
        return "*" * len(secret)
    return secret[:4] + "..." + secret[-4:]


def load_baseline(baseline_path: str) -> set:
    """Load baseline fingerprints for comparison."""
    if not os.path.exists(baseline_path):
        return set()

    with open(baseline_path, "r") as f:
        try:
            baseline = json.load(f)
        except json.JSONDecodeError:
            return set()

    fingerprints = set()
    for entry in baseline:
        fp = f"{entry.get('RuleID', '')}:{entry.get('File', '')}:{entry.get('Commit', '')}"
        fingerprints.add(fp)

    return fingerprints


def classify_findings(findings: list, baseline_fingerprints: set) -> tuple:
    """Separate findings into new and baseline (pre-existing)."""
    new_findings = []
    baseline_findings = []

    for f in findings:
        fp = f"{f.rule_id}:{f.file}:{f.commit}"
        if fp in baseline_fingerprints:
            f.is_new = False
            baseline_findings.append(f)
        else:
            f.is_new = True
            new_findings.append(f)

    return new_findings, baseline_findings


def generate_report(scan_result: ScanResult, repo_path: str) -> dict:
    """Generate a structured scan report."""
    rule_summary = {}
    for f in scan_result.findings:
        rule_summary[f.rule_id] = rule_summary.get(f.rule_id, 0) + 1

    author_summary = {}
    for f in scan_result.new_findings:
        author_summary[f.author] = author_summary.get(f.author, 0) + 1

    return {
        "report_metadata": {
            "repository": repo_path,
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": scan_result.scan_duration,
            "commits_scanned": scan_result.commits_scanned
        },
        "summary": {
            "total_findings": len(scan_result.findings),
            "new_findings": len(scan_result.new_findings),
            "baseline_findings": len(scan_result.baseline_findings),
            "unique_rules_triggered": len(rule_summary),
            "rules_breakdown": rule_summary,
            "authors_with_new_findings": author_summary
        },
        "quality_gate": {
            "passed": len(scan_result.new_findings) == 0,
            "blocking_count": len(scan_result.new_findings)
        },
        "new_findings": [
            {
                "rule_id": f.rule_id,
                "description": f.description,
                "file": f.file,
                "line": f.line,
                "commit": f.commit,
                "author": f.author,
                "date": f.date,
                "secret_preview": f.secret,
                "entropy": f.entropy
            }
            for f in scan_result.new_findings
        ],
        "remediation_steps": [
            f"1. Rotate the {f.rule_id} credential found in {f.file}"
            for f in scan_result.new_findings
        ]
    }


def main():
    parser = argparse.ArgumentParser(description="Gitleaks Secret Scanning Pipeline")
    parser.add_argument("--repo-path", required=True, help="Path to git repository")
    parser.add_argument("--scan-type", default="detect", choices=["detect", "protect"],
                        help="Scan type: detect (history) or protect (staged/pre-commit)")
    parser.add_argument("--baseline", default=None, help="Path to baseline JSON file")
    parser.add_argument("--commit-range", default=None,
                        help="Git log range (e.g., HEAD~10..HEAD)")
    parser.add_argument("--staged", action="store_true",
                        help="Scan only staged changes (for pre-commit)")
    parser.add_argument("--config", default=None, help="Path to .gitleaks.toml config")
    parser.add_argument("--output", default="gitleaks-report.json", help="Output report path")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="Exit non-zero on new findings")
    parser.add_argument("--create-baseline", action="store_true",
                        help="Generate baseline from current findings")
    args = parser.parse_args()

    repo_path = os.path.abspath(args.repo_path)
    start_time = datetime.now(timezone.utc)

    print(f"[*] Running Gitleaks {args.scan_type} on {repo_path}")

    raw_result = run_gitleaks(
        repo_path,
        scan_type=args.scan_type,
        baseline_path=args.baseline,
        commit_range=args.commit_range,
        staged=args.staged,
        config_path=args.config
    )

    if raw_result["exit_code"] == -1:
        print(f"[ERROR] {raw_result['stderr']}")
        sys.exit(2)

    scan_result = ScanResult()
    scan_result.findings = parse_findings(raw_result["findings"])
    scan_result.scan_duration = (datetime.now(timezone.utc) - start_time).total_seconds()

    if args.baseline:
        baseline_fps = load_baseline(args.baseline)
        scan_result.new_findings, scan_result.baseline_findings = classify_findings(
            scan_result.findings, baseline_fps
        )
    else:
        scan_result.new_findings = scan_result.findings
        scan_result.baseline_findings = []

    if args.create_baseline:
        baseline_path = os.path.join(repo_path, ".gitleaks-baseline.json")
        with open(baseline_path, "w") as f:
            json.dump(raw_result["findings"], f, indent=2)
        print(f"[*] Baseline created: {baseline_path}")
        print(f"    Contains {len(raw_result['findings'])} findings")
        return

    report = generate_report(scan_result, repo_path)

    output_path = os.path.abspath(args.output)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Report: {output_path}")

    print(f"\n[*] Total: {len(scan_result.findings)} | "
          f"New: {len(scan_result.new_findings)} | "
          f"Baseline: {len(scan_result.baseline_findings)}")

    if scan_result.new_findings:
        print("\n[!] New secrets detected:")
        for f in scan_result.new_findings:
            print(f"  [{f.rule_id}] {f.file}:{f.line} (commit: {f.commit}, author: {f.author})")
            print(f"    Secret: {f.secret}")

    if report["quality_gate"]["passed"]:
        print("\n[PASS] No new secrets detected.")
    else:
        print(f"\n[FAIL] {len(scan_result.new_findings)} new secrets found. Rotate immediately.")

    if args.fail_on_findings and not report["quality_gate"]["passed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
