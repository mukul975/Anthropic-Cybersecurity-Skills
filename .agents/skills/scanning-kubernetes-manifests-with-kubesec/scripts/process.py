#!/usr/bin/env python3
"""
Kubesec Manifest Scanner Automation

Scans Kubernetes manifests using Kubesec, aggregates results,
and generates security posture reports with remediation guidance.
"""

import json
import subprocess
import sys
import argparse
from pathlib import Path
from collections import defaultdict


MINIMUM_SCORE_THRESHOLD = 0
RECOMMENDED_SCORE_THRESHOLD = 5


def scan_manifest_with_kubesec(file_path: str, kubesec_url: str = "") -> list[dict]:
    """Scan a single manifest file using kubesec."""
    path = Path(file_path)
    if not path.exists():
        print(f"[ERROR] File not found: {file_path}")
        return []

    try:
        if kubesec_url:
            result = subprocess.run(
                ["curl", "-sSX", "POST", "--data-binary", f"@{file_path}", f"{kubesec_url}/scan"],
                capture_output=True, text=True, timeout=30
            )
        else:
            result = subprocess.run(
                ["kubesec", "scan", file_path],
                capture_output=True, text=True, timeout=30
            )

        if result.returncode != 0:
            print(f"[ERROR] Scan failed for {file_path}: {result.stderr.strip()}")
            return []

        return json.loads(result.stdout)
    except FileNotFoundError:
        print("[ERROR] kubesec binary not found. Install from https://github.com/controlplaneio/kubesec")
        return []
    except json.JSONDecodeError:
        print(f"[ERROR] Invalid JSON output from kubesec for {file_path}")
        return []
    except subprocess.TimeoutExpired:
        print(f"[ERROR] Timeout scanning {file_path}")
        return []


def scan_directory(directory: str, kubesec_url: str = "") -> list[dict]:
    """Scan all YAML/JSON files in a directory."""
    dir_path = Path(directory)
    if not dir_path.is_dir():
        print(f"[ERROR] Directory not found: {directory}")
        return []

    all_results = []
    yaml_files = list(dir_path.glob("**/*.yaml")) + list(dir_path.glob("**/*.yml")) + list(dir_path.glob("**/*.json"))

    for manifest_file in sorted(yaml_files):
        print(f"[INFO] Scanning {manifest_file}...")
        results = scan_manifest_with_kubesec(str(manifest_file), kubesec_url)
        for r in results:
            r["source_file"] = str(manifest_file)
        all_results.extend(results)

    return all_results


def categorize_findings(results: list[dict]) -> dict:
    """Categorize scan findings by severity."""
    categories = {
        "critical": [],
        "warning": [],
        "info": [],
        "passed": []
    }

    for result in results:
        score = result.get("score", 0)
        obj = result.get("object", "unknown")
        source = result.get("source_file", "unknown")
        scoring = result.get("scoring", {})

        entry = {
            "object": obj,
            "source_file": source,
            "score": score,
            "critical": scoring.get("critical", []),
            "advise": scoring.get("advise", []),
            "passed": scoring.get("passed", [])
        }

        if score < 0:
            categories["critical"].append(entry)
        elif score < RECOMMENDED_SCORE_THRESHOLD:
            categories["warning"].append(entry)
        else:
            categories["passed"].append(entry)

    return categories


def generate_remediation(result: dict) -> list[str]:
    """Generate remediation recommendations for a scan result."""
    remediations = []
    scoring = result.get("scoring", {})

    for critical in scoring.get("critical", []):
        check_id = critical.get("id", "")
        selector = critical.get("selector", "")
        reason = critical.get("reason", "")
        remediations.append(f"[CRITICAL] {check_id}: {reason} (fix: {selector})")

    for advise in scoring.get("advise", []):
        check_id = advise.get("id", "")
        reason = advise.get("reason", "")
        points = advise.get("points", 0)
        remediations.append(f"[ADVISE +{points}pts] {check_id}: {reason}")

    return remediations


def generate_report(results: list[dict], output_format: str = "text") -> str:
    """Generate a comprehensive scanning report."""
    categories = categorize_findings(results)

    if output_format == "json":
        report = {
            "total_resources_scanned": len(results),
            "critical_count": len(categories["critical"]),
            "warning_count": len(categories["warning"]),
            "passed_count": len(categories["passed"]),
            "results": results,
            "categories": categories
        }
        return json.dumps(report, indent=2)

    lines = []
    lines.append("=" * 70)
    lines.append("KUBESEC MANIFEST SECURITY SCAN REPORT")
    lines.append("=" * 70)

    lines.append(f"\nTotal Resources Scanned: {len(results)}")
    lines.append(f"  Critical (score < 0): {len(categories['critical'])}")
    lines.append(f"  Warning (score < {RECOMMENDED_SCORE_THRESHOLD}): {len(categories['warning'])}")
    lines.append(f"  Passed (score >= {RECOMMENDED_SCORE_THRESHOLD}): {len(categories['passed'])}")

    if results:
        scores = [r.get("score", 0) for r in results]
        lines.append(f"\nScore Statistics:")
        lines.append(f"  Average: {sum(scores) / len(scores):.1f}")
        lines.append(f"  Min: {min(scores)}")
        lines.append(f"  Max: {max(scores)}")

    if categories["critical"]:
        lines.append(f"\n{'=' * 50}")
        lines.append("CRITICAL FINDINGS")
        lines.append(f"{'=' * 50}")
        for item in categories["critical"]:
            lines.append(f"\n  Resource: {item['object']}")
            lines.append(f"  File: {item['source_file']}")
            lines.append(f"  Score: {item['score']}")
            for crit in item["critical"]:
                lines.append(f"    [CRITICAL] {crit.get('id', '')}: {crit.get('reason', '')}")

    if categories["warning"]:
        lines.append(f"\n{'=' * 50}")
        lines.append("WARNINGS")
        lines.append(f"{'=' * 50}")
        for item in categories["warning"]:
            lines.append(f"\n  Resource: {item['object']}")
            lines.append(f"  File: {item['source_file']}")
            lines.append(f"  Score: {item['score']}")
            for adv in item["advise"][:5]:
                lines.append(f"    [ADVISE +{adv.get('points', 0)}] {adv.get('id', '')}: {adv.get('reason', '')}")

    lines.append(f"\n{'=' * 50}")
    lines.append("REMEDIATION SUMMARY")
    lines.append(f"{'=' * 50}")

    advise_counts = defaultdict(int)
    for result in results:
        for adv in result.get("scoring", {}).get("advise", []):
            advise_counts[adv.get("id", "")] += 1

    lines.append("\nMost Common Missing Controls:")
    for check, count in sorted(advise_counts.items(), key=lambda x: -x[1])[:10]:
        lines.append(f"  {check}: missing in {count}/{len(results)} resources")

    gate_pass = all(r.get("score", 0) >= MINIMUM_SCORE_THRESHOLD for r in results)
    lines.append(f"\n{'=' * 50}")
    lines.append(f"GATE RESULT: {'PASS' if gate_pass else 'FAIL'}")
    lines.append(f"{'=' * 50}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Kubesec Manifest Scanner Automation")
    parser.add_argument("--file", help="Single manifest file to scan")
    parser.add_argument("--directory", help="Directory containing manifests to scan")
    parser.add_argument("--url", default="", help="Kubesec API URL (optional, uses local binary if not set)")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--threshold", type=int, default=0, help="Minimum passing score (default: 0)")
    args = parser.parse_args()

    global MINIMUM_SCORE_THRESHOLD
    MINIMUM_SCORE_THRESHOLD = args.threshold

    if not args.file and not args.directory:
        print("[ERROR] Specify --file or --directory")
        sys.exit(1)

    results = []
    if args.file:
        results = scan_manifest_with_kubesec(args.file, args.url)
        for r in results:
            r["source_file"] = args.file
    elif args.directory:
        results = scan_directory(args.directory, args.url)

    if not results:
        print("[WARN] No scan results generated")
        sys.exit(1)

    report = generate_report(results, args.format)
    print(report)

    has_critical = any(r.get("score", 0) < MINIMUM_SCORE_THRESHOLD for r in results)
    sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    main()
