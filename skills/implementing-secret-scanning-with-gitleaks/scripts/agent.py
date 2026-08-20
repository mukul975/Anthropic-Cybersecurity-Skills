#!/usr/bin/env python3
"""Gitleaks secret scanning agent.

Wraps the Gitleaks CLI to scan git repositories, directories, or
specific commits for hardcoded secrets, API keys, tokens, and
credentials. Parses JSON output into structured findings.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone


def find_gitleaks_binary():
    """Locate the gitleaks binary on the system."""
    custom_path = os.environ.get("GITLEAKS_PATH")
    if custom_path and os.path.isfile(custom_path):
        return custom_path
    for name in ["gitleaks", "gitleaks.exe"]:
        for directory in os.environ.get("PATH", "").split(os.pathsep):
            full_path = os.path.join(directory, name)
            if os.path.isfile(full_path):
                return full_path
    print("[!] gitleaks binary not found. Install: https://github.com/gitleaks/gitleaks",
          file=sys.stderr)
    sys.exit(1)


def run_detect(gitleaks_bin, target, config=None, baseline=None,
               log_opts=None, no_git=False, verbose=False):
    """Run gitleaks detect on a repository or directory."""
    cmd = [gitleaks_bin, "detect"]
    if no_git:
        cmd.extend(["--no-git", "--source", target])
    else:
        cmd.extend(["--source", target])
    cmd.extend(["--report-format", "json", "--report-path", "/dev/stdout"])
    if config:
        cmd.extend(["--config", config])
    if baseline:
        cmd.extend(["--baseline-path", baseline])
    if log_opts:
        cmd.extend(["--log-opts", log_opts])
    if verbose:
        cmd.append("--verbose")
    cmd.extend(["--exit-code", "0"])

    print(f"[*] Running: {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode not in (0, 1):
        print(f"[!] Gitleaks error (exit {result.returncode}): {result.stderr}",
              file=sys.stderr)
    return result.stdout, result.stderr, result.returncode


def run_protect(gitleaks_bin, target, config=None, staged=False, verbose=False):
    """Run gitleaks protect for pre-commit scanning."""
    cmd = [gitleaks_bin, "protect", "--source", target]
    cmd.extend(["--report-format", "json", "--report-path", "/dev/stdout"])
    if staged:
        cmd.append("--staged")
    if config:
        cmd.extend(["--config", config])
    if verbose:
        cmd.append("--verbose")
    cmd.extend(["--exit-code", "0"])

    print(f"[*] Running protect mode: {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,
    )
    return result.stdout, result.stderr, result.returncode


def parse_findings(raw_json):
    """Parse gitleaks JSON output into structured findings."""
    findings = []
    if not raw_json or not raw_json.strip():
        return findings
    try:
        results = json.loads(raw_json)
    except json.JSONDecodeError:
        return findings
    if not isinstance(results, list):
        results = [results]
    for item in results:
        secret_val = item.get("Secret", "")
        findings.append({
            "rule_id": item.get("RuleID", "unknown"),
            "description": item.get("Description", ""),
            "secret": secret_val[:8] + "..." if secret_val else "",
            "file": item.get("File", ""),
            "line": item.get("StartLine", 0),
            "commit": (item.get("Commit", "") or "")[:12],
            "author": item.get("Author", ""),
            "email": item.get("Email", ""),
            "date": item.get("Date", ""),
            "message": (item.get("Message", "") or "")[:80],
            "entropy": item.get("Entropy", 0),
            "fingerprint": item.get("Fingerprint", ""),
            "tags": item.get("Tags", []),
        })
    return findings


def format_summary(findings, target):
    """Print human-readable summary of secrets found."""
    print(f"\n{'='*60}")
    print("  Gitleaks Secret Scan Report")
    print(f"{'='*60}")
    print(f"  Target    : {target}")
    print(f"  Secrets   : {len(findings)}")

    if not findings:
        print("  Status    : CLEAN - No secrets detected")
        print(f"{'='*60}")
        return

    by_rule = {}
    for f in findings:
        rule = f["rule_id"]
        by_rule.setdefault(rule, []).append(f)

    print("\n  Findings by Rule:")
    for rule, items in sorted(by_rule.items(), key=lambda x: -len(x[1])):
        print(f"    {rule:40s}: {len(items)} occurrence(s)")

    by_file = {}
    for f in findings:
        by_file.setdefault(f["file"], []).append(f)

    print(f"\n  Affected Files: {len(by_file)}")
    for filepath, items in sorted(by_file.items(), key=lambda x: -len(x[1]))[:10]:
        print(f"    {filepath} ({len(items)} secret(s))")

    print("\n  Top Findings:")
    for f in findings[:15]:
        print(f"    [{f['rule_id']:30s}] {f['file']}:{f['line']} "
              f"(commit: {f['commit']}, secret: {f['secret']})")


def main():
    parser = argparse.ArgumentParser(
        description="Gitleaks secret scanning agent"
    )
    parser.add_argument("--target", required=True,
                        help="Repository path or directory to scan")
    parser.add_argument("--mode", choices=["detect", "protect"], default="detect",
                        help="Scan mode: detect (full history) or protect (pre-commit)")
    parser.add_argument("--config", help="Path to custom .gitleaks.toml config")
    parser.add_argument("--baseline", help="Path to baseline file for known findings")
    parser.add_argument("--log-opts", help="Git log options (e.g., '--since=2026-01-01')")
    parser.add_argument("--no-git", action="store_true",
                        help="Scan files without git history")
    parser.add_argument("--staged", action="store_true",
                        help="Only scan staged changes (protect mode)")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    gitleaks_bin = find_gitleaks_binary()
    print(f"[*] Using gitleaks: {gitleaks_bin}")

    if args.mode == "protect":
        raw_json, stderr, exit_code = run_protect(
            gitleaks_bin, args.target, args.config, args.staged, args.verbose
        )
    else:
        raw_json, stderr, exit_code = run_detect(
            gitleaks_bin, args.target, args.config, args.baseline,
            args.log_opts, args.no_git, args.verbose
        )

    findings = parse_findings(raw_json)
    format_summary(findings, args.target)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "gitleaks",
        "target": args.target,
        "mode": args.mode,
        "secrets_found": len(findings),
        "findings": findings,
        "risk_level": (
            "CRITICAL" if len(findings) > 10
            else "HIGH" if len(findings) > 0
            else "LOW"
        ),
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))

    if findings:
        print(f"\n[!] {len(findings)} secret(s) detected - remediation required")
    else:
        print("\n[+] No secrets detected")


if __name__ == "__main__":
    main()
