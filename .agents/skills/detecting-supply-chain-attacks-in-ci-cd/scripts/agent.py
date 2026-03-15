#!/usr/bin/env python3
"""Agent for detecting supply chain attacks in CI/CD pipelines."""

import os
import re
import json
import argparse
from pathlib import Path
from datetime import datetime

import yaml
import requests


def scan_workflow_file(workflow_path):
    """Scan a single GitHub Actions workflow file for supply chain risks."""
    with open(workflow_path) as f:
        workflow = yaml.safe_load(f)
    if not workflow or not isinstance(workflow, dict):
        return []
    findings = []
    permissions = workflow.get("permissions", {})
    if permissions == "write-all" or (isinstance(permissions, dict) and
                                      permissions.get("contents") == "write"):
        findings.append({
            "file": str(workflow_path),
            "issue": "Overly permissive workflow permissions",
            "severity": "HIGH",
            "detail": f"permissions: {permissions}",
        })
    for job_name, job in workflow.get("jobs", {}).items():
        for i, step in enumerate(job.get("steps", [])):
            uses = step.get("uses", "")
            if uses:
                findings.extend(check_action_pinning(str(workflow_path), job_name, uses))
            run_cmd = step.get("run", "")
            if run_cmd:
                findings.extend(check_script_injection(str(workflow_path), job_name, run_cmd))
            env_vars = step.get("env", {})
            for key, val in (env_vars or {}).items():
                if isinstance(val, str) and "${{" in val and "secrets." in val:
                    if "run" in step:
                        findings.append({
                            "file": str(workflow_path),
                            "job": job_name,
                            "issue": "Secret passed to environment variable in run step",
                            "severity": "MEDIUM",
                            "detail": f"{key}={val[:60]}",
                        })
    return findings


def check_action_pinning(filepath, job_name, uses):
    """Check if a GitHub Action is pinned to a commit SHA."""
    findings = []
    if "@" not in uses:
        return findings
    ref = uses.split("@")[1]
    if re.match(r'^[0-9a-f]{40}$', ref):
        return findings
    if ref in ("main", "master", "latest"):
        findings.append({
            "file": filepath,
            "job": job_name,
            "issue": f"Action pinned to mutable branch: {uses}",
            "severity": "CRITICAL",
        })
    elif re.match(r'^v\d+', ref):
        findings.append({
            "file": filepath,
            "job": job_name,
            "issue": f"Action pinned to mutable tag: {uses}",
            "severity": "MEDIUM",
            "recommendation": "Pin to full commit SHA instead of tag",
        })
    return findings


def check_script_injection(filepath, job_name, run_cmd):
    """Check for script injection via GitHub context expressions."""
    findings = []
    injection_patterns = [
        r"\$\{\{\s*github\.event\.issue\.title",
        r"\$\{\{\s*github\.event\.issue\.body",
        r"\$\{\{\s*github\.event\.pull_request\.title",
        r"\$\{\{\s*github\.event\.pull_request\.body",
        r"\$\{\{\s*github\.event\.comment\.body",
        r"\$\{\{\s*github\.event\.review\.body",
        r"\$\{\{\s*github\.head_ref",
    ]
    for pattern in injection_patterns:
        if re.search(pattern, run_cmd):
            findings.append({
                "file": filepath,
                "job": job_name,
                "issue": f"Script injection via untrusted input",
                "severity": "CRITICAL",
                "pattern": pattern,
                "detail": run_cmd[:100],
            })
    return findings


def scan_directory(directory):
    """Scan all workflow files in a directory."""
    all_findings = []
    workflow_dir = Path(directory) / ".github" / "workflows"
    if not workflow_dir.exists():
        workflow_dir = Path(directory)
    for wf in workflow_dir.glob("*.yml"):
        all_findings.extend(scan_workflow_file(str(wf)))
    for wf in workflow_dir.glob("*.yaml"):
        all_findings.extend(scan_workflow_file(str(wf)))
    return all_findings


def check_dependency_confusion(package_name, registry="npm"):
    """Check if a private package name exists on public registries."""
    urls = {
        "npm": f"https://registry.npmjs.org/{package_name}",
        "pypi": f"https://pypi.org/pypi/{package_name}/json",
    }
    url = urls.get(registry)
    if not url:
        return {"exists_publicly": False}
    try:
        resp = requests.get(url, timeout=10)
        return {
            "package": package_name,
            "registry": registry,
            "exists_publicly": resp.status_code == 200,
            "severity": "HIGH" if resp.status_code == 200 else "INFO",
        }
    except requests.RequestException:
        return {"package": package_name, "exists_publicly": False}


def scan_dockerfile(dockerfile_path):
    """Scan Dockerfile for supply chain risks."""
    findings = []
    with open(dockerfile_path) as f:
        lines = f.readlines()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("FROM") and ":latest" in stripped:
            findings.append({
                "file": str(dockerfile_path),
                "line": i,
                "issue": "Using :latest tag in FROM",
                "severity": "MEDIUM",
                "detail": stripped,
            })
        if "curl" in stripped and "| sh" in stripped or "| bash" in stripped:
            findings.append({
                "file": str(dockerfile_path),
                "line": i,
                "issue": "Piping curl output to shell",
                "severity": "HIGH",
                "detail": stripped[:100],
            })
    return findings


def main():
    parser = argparse.ArgumentParser(description="CI/CD Supply Chain Attack Detection Agent")
    parser.add_argument("--directory", default=".", help="Repository root to scan")
    parser.add_argument("--check-packages", nargs="*", help="Package names to check for confusion")
    parser.add_argument("--output", default="supply_chain_report.json")
    parser.add_argument("--action", choices=[
        "workflows", "dockerfiles", "packages", "full_scan"
    ], default="full_scan")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.action in ("workflows", "full_scan"):
        wf_findings = scan_directory(args.directory)
        report["findings"]["workflow_risks"] = wf_findings
        print(f"[+] Workflow risks found: {len(wf_findings)}")

    if args.action in ("dockerfiles", "full_scan"):
        df_findings = []
        for df in Path(args.directory).rglob("Dockerfile*"):
            df_findings.extend(scan_dockerfile(str(df)))
        report["findings"]["dockerfile_risks"] = df_findings
        print(f"[+] Dockerfile risks found: {len(df_findings)}")

    if args.action in ("packages", "full_scan") and args.check_packages:
        pkg_results = []
        for pkg in args.check_packages:
            pkg_results.append(check_dependency_confusion(pkg))
        report["findings"]["dependency_confusion"] = pkg_results
        public = [p for p in pkg_results if p.get("exists_publicly")]
        print(f"[+] Dependency confusion risks: {len(public)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
