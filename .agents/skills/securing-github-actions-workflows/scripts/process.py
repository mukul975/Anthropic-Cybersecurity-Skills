#!/usr/bin/env python3
"""
GitHub Actions Workflow Security Audit Script

Analyzes workflow files for security issues including unpinned actions,
excessive permissions, script injection risks, and insecure patterns.

Usage:
    python process.py --workflows-dir .github/workflows/ --output audit-report.json
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml


@dataclass
class SecurityFinding:
    file: str
    line: int
    check: str
    severity: str
    message: str
    remediation: str


SHA_PATTERN = re.compile(r"@[0-9a-f]{40}")
TAG_PATTERN = re.compile(r"@v?\d+(\.\d+)*$")
INJECTION_PATTERN = re.compile(r"\$\{\{\s*github\.event\.(issue|pull_request|comment|review)\.\w+")
DANGEROUS_CONTEXTS = [
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.head_ref",
]


def load_workflow(filepath: str) -> dict:
    """Load a GitHub Actions workflow YAML file."""
    try:
        with open(filepath, "r") as f:
            return yaml.safe_load(f) or {}
    except (yaml.YAMLError, FileNotFoundError):
        return {}


def check_action_pinning(workflow: dict, filepath: str) -> list:
    """Check if actions are pinned to SHA digests."""
    findings = []
    filename = os.path.basename(filepath)

    for job_name, job in workflow.get("jobs", {}).items():
        for i, step in enumerate(job.get("steps", [])):
            uses = step.get("uses", "")
            if not uses or uses.startswith("./"):
                continue
            if not SHA_PATTERN.search(uses):
                findings.append(SecurityFinding(
                    file=filename, line=0,
                    check="ACTION_PINNING",
                    severity="HIGH",
                    message=f"Job '{job_name}' step {i}: '{uses}' not pinned to SHA digest",
                    remediation=f"Pin to SHA: {uses.split('@')[0]}@<commit-sha>"
                ))
    return findings


def check_permissions(workflow: dict, filepath: str) -> list:
    """Check for overly permissive GITHUB_TOKEN permissions."""
    findings = []
    filename = os.path.basename(filepath)

    top_perms = workflow.get("permissions")
    if top_perms is None:
        findings.append(SecurityFinding(
            file=filename, line=0,
            check="PERMISSIONS",
            severity="MEDIUM",
            message="No top-level permissions defined. Inherits default (may be write-all).",
            remediation="Add 'permissions: {}' at workflow level and grant per-job."
        ))
    elif top_perms == "write-all" or (isinstance(top_perms, dict) and
                                       all(v == "write" for v in top_perms.values())):
        findings.append(SecurityFinding(
            file=filename, line=0,
            check="PERMISSIONS",
            severity="HIGH",
            message="Workflow has write-all permissions.",
            remediation="Restrict to minimum required permissions per job."
        ))
    return findings


def check_script_injection(workflow: dict, filepath: str) -> list:
    """Check for script injection via user-controlled inputs."""
    findings = []
    filename = os.path.basename(filepath)

    for job_name, job in workflow.get("jobs", {}).items():
        for i, step in enumerate(job.get("steps", [])):
            run_cmd = step.get("run", "")
            if not run_cmd:
                continue
            for ctx in DANGEROUS_CONTEXTS:
                if f"${{{{ {ctx}" in run_cmd or f"${{{{{ctx}" in run_cmd:
                    findings.append(SecurityFinding(
                        file=filename, line=0,
                        check="SCRIPT_INJECTION",
                        severity="CRITICAL",
                        message=f"Job '{job_name}' step {i}: '{ctx}' interpolated in run step",
                        remediation="Use env variable: env: VAR: ${{ " + ctx + " }} then ${VAR}"
                    ))
    return findings


def check_pr_target(workflow: dict, filepath: str) -> list:
    """Check for dangerous pull_request_target usage."""
    findings = []
    filename = os.path.basename(filepath)

    triggers = workflow.get("on", {})
    if isinstance(triggers, dict) and "pull_request_target" in triggers:
        for job_name, job in workflow.get("jobs", {}).items():
            for step in job.get("steps", []):
                uses = step.get("uses", "")
                if "checkout" in uses:
                    with_ref = step.get("with", {}).get("ref", "")
                    if "pull_request" in with_ref or "head" in with_ref:
                        findings.append(SecurityFinding(
                            file=filename, line=0,
                            check="PR_TARGET_CHECKOUT",
                            severity="CRITICAL",
                            message=f"Job '{job_name}': pull_request_target with PR code checkout",
                            remediation="Never checkout PR code in pull_request_target workflows."
                        ))
    return findings


def main():
    parser = argparse.ArgumentParser(description="GitHub Actions Security Audit")
    parser.add_argument("--workflows-dir", required=True)
    parser.add_argument("--output", default="actions-security-report.json")
    parser.add_argument("--fail-on-findings", action="store_true")
    args = parser.parse_args()

    workflows_dir = os.path.abspath(args.workflows_dir)
    all_findings = []

    workflow_files = list(Path(workflows_dir).glob("*.yml")) + list(Path(workflows_dir).glob("*.yaml"))
    print(f"[*] Auditing {len(workflow_files)} workflow files in {workflows_dir}")

    for wf_path in workflow_files:
        workflow = load_workflow(str(wf_path))
        if not workflow:
            continue

        all_findings.extend(check_action_pinning(workflow, str(wf_path)))
        all_findings.extend(check_permissions(workflow, str(wf_path)))
        all_findings.extend(check_script_injection(workflow, str(wf_path)))
        all_findings.extend(check_pr_target(workflow, str(wf_path)))

    severity_counts = {}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    report = {
        "metadata": {
            "directory": workflows_dir,
            "date": datetime.now(timezone.utc).isoformat(),
            "workflows_scanned": len(workflow_files)
        },
        "summary": {
            "total_findings": len(all_findings),
            "severity_counts": severity_counts
        },
        "findings": [
            {"file": f.file, "check": f.check, "severity": f.severity,
             "message": f.message, "remediation": f.remediation}
            for f in sorted(all_findings,
                            key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.severity, 4))
        ]
    }

    output_path = os.path.abspath(args.output)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Report: {output_path}")

    for f in all_findings:
        print(f"  [{f.severity}] {f.file}: {f.message}")

    passed = len(all_findings) == 0
    print(f"\n[{'PASS' if passed else 'FAIL'}] {len(all_findings)} security findings")

    if args.fail_on_findings and not passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
