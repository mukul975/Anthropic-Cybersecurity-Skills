#!/usr/bin/env python3
"""Semgrep SAST scanning agent.

Wraps the Semgrep CLI to perform static application security testing
using built-in rulesets and custom rules. Parses JSON output to produce
structured vulnerability findings with severity, CWE, and OWASP mappings.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone


def find_semgrep_binary():
    """Locate the semgrep binary on the system."""
    custom_path = os.environ.get("SEMGREP_PATH")
    if custom_path and os.path.isfile(custom_path):
        return custom_path
    for name in ["semgrep", "semgrep.exe"]:
        for directory in os.environ.get("PATH", "").split(os.pathsep):
            full_path = os.path.join(directory, name)
            if os.path.isfile(full_path):
                return full_path
    print("[!] semgrep not found. Install: pip install semgrep", file=sys.stderr)
    sys.exit(1)


def run_scan(semgrep_bin, target, configs=None, severity=None,
             exclude=None, include=None, max_target_bytes=None,
             timeout_per_rule=None, verbose=False):
    """Run semgrep scan and return JSON results."""
    cmd = [semgrep_bin, "scan", "--json"]

    if configs:
        for cfg in configs:
            cmd.extend(["--config", cfg])
    else:
        cmd.extend(["--config", "auto"])

    if severity:
        cmd.extend(["--severity", severity])
    if exclude:
        for pattern in exclude:
            cmd.extend(["--exclude", pattern])
    if include:
        for pattern in include:
            cmd.extend(["--include", pattern])
    if max_target_bytes:
        cmd.extend(["--max-target-bytes", str(max_target_bytes)])
    if timeout_per_rule:
        cmd.extend(["--timeout", str(timeout_per_rule)])
    if verbose:
        cmd.append("--verbose")

    cmd.append(target)

    print(f"[*] Running: {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=900,
    )
    return result.stdout, result.stderr, result.returncode


def parse_findings(raw_json):
    """Parse semgrep JSON output into structured findings."""
    findings = []
    if not raw_json:
        return findings, {}
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return findings, {}

    errors = data.get("errors", [])
    for result in data.get("results", []):
        metadata = result.get("extra", {}).get("metadata", {})
        finding = {
            "rule_id": result.get("check_id", "unknown"),
            "message": result.get("extra", {}).get("message", ""),
            "severity": result.get("extra", {}).get("severity", "WARNING"),
            "path": result.get("path", ""),
            "start_line": result.get("start", {}).get("line", 0),
            "end_line": result.get("end", {}).get("line", 0),
            "matched_code": result.get("extra", {}).get("lines", ""),
            "fix": result.get("extra", {}).get("fix", ""),
            "cwe": metadata.get("cwe", []),
            "owasp": metadata.get("owasp", []),
            "confidence": metadata.get("confidence", ""),
            "references": metadata.get("references", []),
            "category": metadata.get("category", ""),
            "technology": metadata.get("technology", []),
        }
        findings.append(finding)

    stats = {
        "total_findings": len(findings),
        "files_scanned": data.get("paths", {}).get("scanned", []),
        "files_scanned_count": len(data.get("paths", {}).get("scanned", [])),
        "errors": len(errors),
        "parse_errors": [e.get("message", "") for e in errors[:5]],
    }
    return findings, stats


def format_summary(findings, stats, target):
    """Print human-readable scan summary."""
    print(f"\n{'='*60}")
    print("  Semgrep SAST Scan Report")
    print(f"{'='*60}")
    print(f"  Target       : {target}")
    print(f"  Files Scanned: {stats.get('files_scanned_count', 0)}")
    print(f"  Findings     : {len(findings)}")
    print(f"  Parse Errors : {stats.get('errors', 0)}")

    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "WARNING")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\n  By Severity:")
    for sev in ["ERROR", "WARNING", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            print(f"    {sev:10s}: {count}")

    by_rule = {}
    for f in findings:
        by_rule.setdefault(f["rule_id"], []).append(f)

    print(f"\n  Top Rules ({len(by_rule)} unique):")
    for rule, items in sorted(by_rule.items(), key=lambda x: -len(x[1]))[:10]:
        short_rule = rule.split(".")[-1] if "." in rule else rule
        print(f"    {short_rule:45s}: {len(items)} hit(s)")

    by_file = {}
    for f in findings:
        by_file.setdefault(f["path"], []).append(f)

    print(f"\n  Most Affected Files ({len(by_file)} files):")
    for filepath, items in sorted(by_file.items(), key=lambda x: -len(x[1]))[:10]:
        print(f"    {filepath:50s}: {len(items)} finding(s)")

    if findings:
        print("\n  Critical/Error Findings:")
        for f in findings[:15]:
            if f["severity"] == "ERROR":
                cwe = f["cwe"][0] if f["cwe"] else ""
                print(f"    {f['path']}:{f['start_line']} [{cwe}] {f['rule_id']}")

    return severity_counts


def main():
    parser = argparse.ArgumentParser(
        description="Semgrep SAST scanning agent"
    )
    parser.add_argument("--target", required=True,
                        help="Path to source code directory or file to scan")
    parser.add_argument("--config", nargs="+", default=None,
                        help="Semgrep config(s): auto, p/security-audit, p/owasp-top-ten, or path to .yaml")
    parser.add_argument("--severity", choices=["INFO", "WARNING", "ERROR"],
                        help="Minimum severity to report")
    parser.add_argument("--exclude", nargs="+",
                        help="File patterns to exclude (e.g., tests/ vendor/)")
    parser.add_argument("--include", nargs="+",
                        help="File patterns to include (e.g., *.py *.js)")
    parser.add_argument("--timeout-per-rule", type=int, default=30,
                        help="Timeout per rule in seconds (default: 30)")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    semgrep_bin = find_semgrep_binary()
    print(f"[*] Using semgrep: {semgrep_bin}")

    raw_json, stderr, exit_code = run_scan(
        semgrep_bin, args.target, args.config, args.severity,
        args.exclude, args.include, timeout_per_rule=args.timeout_per_rule,
        verbose=args.verbose
    )

    findings, stats = parse_findings(raw_json)
    severity_counts = format_summary(findings, stats, args.target)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "semgrep",
        "target": args.target,
        "configs": args.config or ["auto"],
        "stats": stats,
        "severity_counts": severity_counts,
        "findings_count": len(findings),
        "findings": findings,
        "risk_level": (
            "CRITICAL" if severity_counts.get("ERROR", 0) > 5
            else "HIGH" if severity_counts.get("ERROR", 0) > 0
            else "MEDIUM" if severity_counts.get("WARNING", 0) > 0
            else "LOW"
        ),
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))

    print(f"\n[*] Risk Level: {report['risk_level']}")


if __name__ == "__main__":
    main()
