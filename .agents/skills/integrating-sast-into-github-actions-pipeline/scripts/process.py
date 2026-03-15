#!/usr/bin/env python3
"""
SAST Pipeline Orchestration Script

Runs CodeQL and Semgrep scans, aggregates SARIF results, evaluates quality gates,
and produces a consolidated report. Designed to be invoked from GitHub Actions
or any CI/CD platform.

Usage:
    python process.py --repo-path /path/to/repo --output report.json
    python process.py --repo-path . --severity-threshold high --fail-on-findings
"""

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class ScanFinding:
    rule_id: str
    severity: str
    message: str
    file_path: str
    start_line: int
    end_line: int
    tool: str
    cwe: str = ""
    owasp: str = ""
    fingerprint: str = ""


@dataclass
class ScanResult:
    tool: str
    findings: list = field(default_factory=list)
    rules_evaluated: int = 0
    scan_duration_seconds: float = 0.0
    exit_code: int = 0
    error_message: str = ""


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "note": 4, "none": 5}


def run_semgrep(repo_path: str, config: str = "auto", extra_configs: Optional[list] = None) -> ScanResult:
    """Run Semgrep scan and return structured results."""
    result = ScanResult(tool="semgrep")
    sarif_output = os.path.join(repo_path, "semgrep-results.sarif")

    cmd = [
        "semgrep", "ci",
        "--config", config,
        "--sarif",
        "--output", sarif_output,
        "--json",
        "--quiet"
    ]

    if extra_configs:
        for cfg in extra_configs:
            cmd.extend(["--config", cfg])

    start_time = datetime.now(timezone.utc)

    try:
        proc = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=600
        )
        result.exit_code = proc.returncode

        if proc.returncode not in (0, 1):
            result.error_message = proc.stderr[:500]
            return result

    except subprocess.TimeoutExpired:
        result.error_message = "Semgrep scan timed out after 600 seconds"
        result.exit_code = -1
        return result
    except FileNotFoundError:
        result.error_message = "semgrep binary not found. Install with: pip install semgrep"
        result.exit_code = -1
        return result

    result.scan_duration_seconds = (datetime.now(timezone.utc) - start_time).total_seconds()

    if os.path.exists(sarif_output):
        result.findings = parse_sarif(sarif_output, "semgrep")
        with open(sarif_output, "r") as f:
            sarif_data = json.load(f)
            for run in sarif_data.get("runs", []):
                result.rules_evaluated = len(run.get("tool", {}).get("driver", {}).get("rules", []))

    return result


def run_codeql_query(repo_path: str, language: str, database_path: str) -> ScanResult:
    """Run CodeQL analysis on a pre-created database and return structured results."""
    result = ScanResult(tool=f"codeql-{language}")
    sarif_output = os.path.join(repo_path, f"codeql-{language}-results.sarif")

    cmd = [
        "codeql", "database", "analyze",
        database_path,
        f"codeql/{language}-queries:codeql-suites/{language}-security-extended.qls",
        "--format=sarifv2.1.0",
        f"--output={sarif_output}",
        "--threads=0"
    ]

    start_time = datetime.now(timezone.utc)

    try:
        proc = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=1200
        )
        result.exit_code = proc.returncode

        if proc.returncode != 0:
            result.error_message = proc.stderr[:500]

    except subprocess.TimeoutExpired:
        result.error_message = "CodeQL analysis timed out after 1200 seconds"
        result.exit_code = -1
        return result
    except FileNotFoundError:
        result.error_message = "codeql binary not found. Install from https://github.com/github/codeql-cli-binaries"
        result.exit_code = -1
        return result

    result.scan_duration_seconds = (datetime.now(timezone.utc) - start_time).total_seconds()

    if os.path.exists(sarif_output):
        result.findings = parse_sarif(sarif_output, f"codeql-{language}")
        with open(sarif_output, "r") as f:
            sarif_data = json.load(f)
            for run in sarif_data.get("runs", []):
                result.rules_evaluated = len(run.get("tool", {}).get("driver", {}).get("rules", []))

    return result


def parse_sarif(sarif_path: str, tool_name: str) -> list:
    """Parse a SARIF file and extract findings as ScanFinding objects."""
    findings = []

    with open(sarif_path, "r") as f:
        sarif_data = json.load(f)

    for run in sarif_data.get("runs", []):
        rules_map = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rule_id = rule.get("id", "")
            properties = rule.get("properties", {})
            cwe_tags = [t for t in properties.get("tags", []) if t.startswith("CWE")]
            owasp_tags = [t for t in properties.get("tags", []) if "owasp" in t.lower()]
            rules_map[rule_id] = {
                "cwe": cwe_tags[0] if cwe_tags else "",
                "owasp": owasp_tags[0] if owasp_tags else "",
                "severity": rule.get("defaultConfiguration", {}).get("level", "warning")
            }

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule_info = rules_map.get(rule_id, {})

            level = result.get("level", rule_info.get("severity", "warning"))
            severity_map = {"error": "high", "warning": "medium", "note": "low", "none": "none"}
            severity = severity_map.get(level, "medium")

            security_severity = None
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                if rule.get("id") == rule_id:
                    security_severity = rule.get("properties", {}).get("security-severity")
                    break

            if security_severity:
                score = float(security_severity)
                if score >= 9.0:
                    severity = "critical"
                elif score >= 7.0:
                    severity = "high"
                elif score >= 4.0:
                    severity = "medium"
                else:
                    severity = "low"

            locations = result.get("locations", [{}])
            physical = locations[0].get("physicalLocation", {}) if locations else {}
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})

            findings.append(ScanFinding(
                rule_id=rule_id,
                severity=severity,
                message=result.get("message", {}).get("text", ""),
                file_path=artifact.get("uri", "unknown"),
                start_line=region.get("startLine", 0),
                end_line=region.get("endLine", region.get("startLine", 0)),
                tool=tool_name,
                cwe=rule_info.get("cwe", ""),
                owasp=rule_info.get("owasp", ""),
                fingerprint=str(result.get("fingerprints", {}).get("primaryLocationLineHash", ""))
            ))

    return findings


def evaluate_quality_gate(findings: list, severity_threshold: str) -> dict:
    """Evaluate quality gate based on finding severities."""
    threshold_level = SEVERITY_ORDER.get(severity_threshold.lower(), 1)

    blocking_findings = [
        f for f in findings
        if SEVERITY_ORDER.get(f.severity.lower(), 5) <= threshold_level
    ]

    severity_counts = {}
    for f in findings:
        sev = f.severity.lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "passed": len(blocking_findings) == 0,
        "threshold": severity_threshold,
        "total_findings": len(findings),
        "blocking_findings": len(blocking_findings),
        "severity_counts": severity_counts,
        "blocking_details": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "file": f.file_path,
                "line": f.start_line,
                "tool": f.tool,
                "message": f.message[:200]
            }
            for f in blocking_findings
        ]
    }


def generate_report(scan_results: list, quality_gate: dict, repo_path: str) -> dict:
    """Generate a consolidated SAST report."""
    all_findings = []
    for sr in scan_results:
        all_findings.extend(sr.findings)

    cwe_counts = {}
    for f in all_findings:
        if f.cwe:
            cwe_counts[f.cwe] = cwe_counts.get(f.cwe, 0) + 1

    report = {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "repository": repo_path,
            "report_version": "1.0.0"
        },
        "scan_summary": [
            {
                "tool": sr.tool,
                "findings_count": len(sr.findings),
                "rules_evaluated": sr.rules_evaluated,
                "duration_seconds": sr.scan_duration_seconds,
                "status": "success" if sr.exit_code in (0, 1) else "error",
                "error": sr.error_message
            }
            for sr in scan_results
        ],
        "quality_gate": quality_gate,
        "top_cwes": sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:10],
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "tool": f.tool,
                "file": f.file_path,
                "line": f.start_line,
                "cwe": f.cwe,
                "owasp": f.owasp,
                "message": f.message[:300]
            }
            for f in sorted(all_findings, key=lambda x: SEVERITY_ORDER.get(x.severity.lower(), 5))
        ]
    }

    return report


def main():
    parser = argparse.ArgumentParser(description="SAST Pipeline Orchestration")
    parser.add_argument("--repo-path", required=True, help="Path to the repository to scan")
    parser.add_argument("--output", default="sast-report.json", help="Output report file path")
    parser.add_argument("--severity-threshold", default="high",
                        choices=["critical", "high", "medium", "low"],
                        help="Minimum severity to block pipeline")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="Exit with non-zero code if quality gate fails")
    parser.add_argument("--semgrep-config", default="auto",
                        help="Semgrep configuration (default: auto)")
    parser.add_argument("--semgrep-extra-configs", nargs="*",
                        help="Additional Semgrep config paths")
    parser.add_argument("--skip-semgrep", action="store_true", help="Skip Semgrep scan")
    parser.add_argument("--skip-codeql", action="store_true", help="Skip CodeQL scan")
    parser.add_argument("--codeql-language", default=None, help="Language for CodeQL analysis")
    parser.add_argument("--codeql-db-path", default=None, help="Path to CodeQL database")
    parser.add_argument("--sarif-only", nargs="*",
                        help="Only parse existing SARIF files instead of running scans")
    args = parser.parse_args()

    repo_path = os.path.abspath(args.repo_path)
    scan_results = []

    if args.sarif_only:
        for sarif_file in args.sarif_only:
            tool_name = Path(sarif_file).stem
            findings = parse_sarif(sarif_file, tool_name)
            sr = ScanResult(tool=tool_name, findings=findings)
            scan_results.append(sr)
    else:
        if not args.skip_semgrep:
            print("[*] Running Semgrep scan...")
            semgrep_result = run_semgrep(
                repo_path,
                config=args.semgrep_config,
                extra_configs=args.semgrep_extra_configs
            )
            scan_results.append(semgrep_result)
            print(f"    Found {len(semgrep_result.findings)} findings in {semgrep_result.scan_duration_seconds:.1f}s")

            if semgrep_result.error_message:
                print(f"    Warning: {semgrep_result.error_message}")

        if not args.skip_codeql and args.codeql_language and args.codeql_db_path:
            print(f"[*] Running CodeQL analysis for {args.codeql_language}...")
            codeql_result = run_codeql_query(repo_path, args.codeql_language, args.codeql_db_path)
            scan_results.append(codeql_result)
            print(f"    Found {len(codeql_result.findings)} findings in {codeql_result.scan_duration_seconds:.1f}s")

    all_findings = []
    for sr in scan_results:
        all_findings.extend(sr.findings)

    quality_gate = evaluate_quality_gate(all_findings, args.severity_threshold)

    report = generate_report(scan_results, quality_gate, repo_path)

    output_path = os.path.abspath(args.output)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[*] Report written to {output_path}")

    if quality_gate["passed"]:
        print(f"[PASS] Quality gate passed. {quality_gate['total_findings']} findings, none blocking.")
    else:
        print(f"[FAIL] Quality gate failed. {quality_gate['blocking_findings']} blocking findings:")
        for detail in quality_gate["blocking_details"]:
            print(f"  - [{detail['severity'].upper()}] {detail['rule_id']} in {detail['file']}:{detail['line']}")

    if args.fail_on_findings and not quality_gate["passed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
