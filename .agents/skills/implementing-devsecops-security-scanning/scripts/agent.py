#!/usr/bin/env python3
"""DevSecOps security scanning pipeline agent.

Orchestrates Semgrep (SAST), Trivy (container/SCA), and Gitleaks (secrets)
scans via subprocess, aggregates findings, and enforces severity gates.
"""

import argparse
import json
import os
import subprocess
import sys
import datetime


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def run_semgrep(target_dir, config="auto"):
    """Run Semgrep SAST scan and return findings."""
    cmd = ["semgrep", "scan", "--config", config, "--json", "--quiet", target_dir]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        findings = []
        for r in data.get("results", []):
            findings.append({
                "tool": "semgrep",
                "rule_id": r.get("check_id", ""),
                "severity": r.get("extra", {}).get("severity", "WARNING").upper(),
                "message": r.get("extra", {}).get("message", ""),
                "file": r.get("path", ""),
                "line": r.get("start", {}).get("line", 0),
            })
        return findings
    except FileNotFoundError:
        return [{"tool": "semgrep", "error": "semgrep not installed"}]
    except subprocess.TimeoutExpired:
        return [{"tool": "semgrep", "error": "scan timed out"}]
    except json.JSONDecodeError:
        return [{"tool": "semgrep", "error": "invalid JSON output"}]


def run_trivy(image_or_path, scan_type="image"):
    """Run Trivy vulnerability scan on image or filesystem."""
    cmd = ["trivy", scan_type, "--format", "json", "--quiet", image_or_path]
    if scan_type == "fs":
        cmd = ["trivy", "fs", "--format", "json", "--quiet", "--scanners", "vuln,secret", image_or_path]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        findings = []
        for res in data.get("Results", []):
            for vuln in res.get("Vulnerabilities", []):
                findings.append({
                    "tool": "trivy",
                    "rule_id": vuln.get("VulnerabilityID", ""),
                    "severity": vuln.get("Severity", "UNKNOWN").upper(),
                    "message": vuln.get("Title", ""),
                    "file": res.get("Target", ""),
                    "line": 0,
                    "fixed_version": vuln.get("FixedVersion", ""),
                })
        return findings
    except FileNotFoundError:
        return [{"tool": "trivy", "error": "trivy not installed"}]
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        return [{"tool": "trivy", "error": str(e)}]


def run_gitleaks(repo_path):
    """Run Gitleaks secret detection scan."""
    cmd = ["gitleaks", "detect", "--source", repo_path, "--report-format", "json",
           "--report-path", "/dev/stdout", "--no-banner"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        data = json.loads(result.stdout) if result.stdout.strip().startswith("[") else []
        findings = []
        for leak in data:
            findings.append({
                "tool": "gitleaks",
                "rule_id": leak.get("RuleID", ""),
                "severity": "HIGH",
                "message": leak.get("Description", ""),
                "file": leak.get("File", ""),
                "line": leak.get("StartLine", 0),
            })
        return findings
    except FileNotFoundError:
        return [{"tool": "gitleaks", "error": "gitleaks not installed"}]
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        return [{"tool": "gitleaks", "error": str(e)}]


def enforce_gate(findings, fail_on="HIGH"):
    """Enforce security gate based on severity threshold."""
    threshold = SEVERITY_ORDER.get(fail_on.upper(), 3)
    blockers = [
        f for f in findings
        if not f.get("error") and SEVERITY_ORDER.get(f.get("severity", ""), 0) >= threshold
    ]
    return {
        "gate_threshold": fail_on,
        "blocking_findings": len(blockers),
        "passed": len(blockers) == 0,
    }


def aggregate_report(all_findings):
    """Aggregate findings from all scanners."""
    by_severity = {}
    by_tool = {}
    for f in all_findings:
        if f.get("error"):
            continue
        sev = f.get("severity", "UNKNOWN")
        tool = f.get("tool", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_tool[tool] = by_tool.get(tool, 0) + 1
    return {
        "total_findings": sum(1 for f in all_findings if not f.get("error")),
        "by_severity": by_severity,
        "by_tool": by_tool,
    }


def main():
    parser = argparse.ArgumentParser(description="DevSecOps security scanning pipeline")
    parser.add_argument("target", nargs="?", help="Directory or container image to scan")
    parser.add_argument("--semgrep", action="store_true", help="Run Semgrep SAST")
    parser.add_argument("--trivy", action="store_true", help="Run Trivy vulnerability scan")
    parser.add_argument("--trivy-type", default="fs", choices=["image", "fs"], help="Trivy scan type")
    parser.add_argument("--gitleaks", action="store_true", help="Run Gitleaks secret detection")
    parser.add_argument("--fail-on", default="HIGH", help="Fail gate on severity (default: HIGH)")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    args = parser.parse_args()

    print("[*] DevSecOps Security Scanning Pipeline")
    report = {"timestamp": datetime.datetime.utcnow().isoformat() + "Z", "findings": []}

    if not args.target:
        print("[DEMO] Usage: python agent.py /path/to/code --semgrep --trivy --gitleaks")
        print("  Tools: semgrep (SAST), trivy (SCA/container), gitleaks (secrets)")
        print(json.dumps({"demo": True, "tools": ["semgrep", "trivy", "gitleaks"]}, indent=2))
        sys.exit(0)

    if args.semgrep:
        report["findings"].extend(run_semgrep(args.target))
    if args.trivy:
        report["findings"].extend(run_trivy(args.target, args.trivy_type))
    if args.gitleaks:
        report["findings"].extend(run_gitleaks(args.target))

    summary = aggregate_report(report["findings"])
    gate = enforce_gate(report["findings"], args.fail_on)
    report["summary"] = summary
    report["gate"] = gate

    print(f"[*] Total findings: {summary['total_findings']}")
    print(f"[*] By severity: {summary['by_severity']}")
    print(f"[*] Gate ({args.fail_on}): {'PASSED' if gate['passed'] else 'FAILED'}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)

    print(json.dumps({"gate_passed": gate["passed"], "total": summary["total_findings"]}, indent=2))
    sys.exit(0 if gate["passed"] else 1)


if __name__ == "__main__":
    main()
