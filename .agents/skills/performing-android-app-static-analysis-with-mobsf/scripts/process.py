#!/usr/bin/env python3
"""
MobSF Automated Static Analysis Pipeline

Automates APK upload, scanning, and report generation via MobSF REST API.
Designed for CI/CD integration with configurable security score thresholds.

Usage:
    python process.py --apk target.apk --api-key <KEY> [--threshold 60] [--output report.json]
"""

import argparse
import json
import sys
import time
import hashlib
from pathlib import Path
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    print("ERROR: 'requests' package required. Install with: pip install requests")
    sys.exit(1)


class MobSFScanner:
    """Interfaces with MobSF REST API for automated static analysis."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"Authorization": api_key})

    def upload_apk(self, apk_path: str) -> dict:
        """Upload APK file to MobSF for analysis."""
        endpoint = f"{self.base_url}/api/v1/upload"
        apk_file = Path(apk_path)

        if not apk_file.exists():
            raise FileNotFoundError(f"APK not found: {apk_path}")

        if not apk_file.suffix.lower() in (".apk", ".aab", ".zip", ".ipa"):
            raise ValueError(f"Unsupported file type: {apk_file.suffix}")

        with open(apk_path, "rb") as f:
            files = {"file": (apk_file.name, f, "application/octet-stream")}
            response = self.session.post(endpoint, files=files)

        response.raise_for_status()
        result = response.json()
        print(f"[+] Uploaded: {apk_file.name} (hash: {result.get('hash', 'N/A')})")
        return result

    def run_static_scan(self, file_hash: str, file_name: str, scan_type: str = "apk") -> dict:
        """Trigger static analysis scan."""
        endpoint = f"{self.base_url}/api/v1/scan"
        data = {
            "scan_type": scan_type,
            "file_name": file_name,
            "hash": file_hash,
        }
        response = self.session.post(endpoint, data=data)
        response.raise_for_status()
        print(f"[+] Static scan completed for: {file_name}")
        return response.json()

    def get_report_json(self, file_hash: str) -> dict:
        """Retrieve JSON scan report."""
        endpoint = f"{self.base_url}/api/v1/report_json"
        data = {"hash": file_hash}
        response = self.session.post(endpoint, data=data)
        response.raise_for_status()
        return response.json()

    def get_scorecard(self, file_hash: str) -> dict:
        """Retrieve security scorecard."""
        endpoint = f"{self.base_url}/api/v1/scorecard"
        data = {"hash": file_hash}
        response = self.session.post(endpoint, data=data)
        response.raise_for_status()
        return response.json()

    def download_pdf_report(self, file_hash: str, output_path: str) -> str:
        """Download PDF report."""
        endpoint = f"{self.base_url}/api/v1/download_pdf"
        data = {"hash": file_hash}
        response = self.session.post(endpoint, data=data)
        response.raise_for_status()

        with open(output_path, "wb") as f:
            f.write(response.content)
        print(f"[+] PDF report saved: {output_path}")
        return output_path


def extract_critical_findings(report: dict) -> dict:
    """Extract and categorize critical findings from MobSF report."""
    findings = {
        "manifest_issues": [],
        "code_issues": [],
        "network_issues": [],
        "binary_issues": [],
        "crypto_issues": [],
    }

    # Manifest analysis
    manifest = report.get("manifest_analysis", [])
    if isinstance(manifest, list):
        for item in manifest:
            severity = item.get("stat", item.get("severity", "info"))
            if severity.lower() in ("high", "warning"):
                findings["manifest_issues"].append({
                    "title": item.get("title", "Unknown"),
                    "description": item.get("desc", item.get("description", "")),
                    "severity": severity,
                })

    # Code analysis
    code_analysis = report.get("code_analysis", {})
    if isinstance(code_analysis, dict):
        for category, items in code_analysis.items():
            if isinstance(items, dict):
                metadata = items.get("metadata", {})
                severity = metadata.get("severity", "info")
                if severity.lower() in ("high", "warning"):
                    findings["code_issues"].append({
                        "category": category,
                        "description": metadata.get("description", ""),
                        "severity": severity,
                        "files": list(items.get("files", {}).keys())[:5],
                    })

    # Network security
    network = report.get("network_security", [])
    if isinstance(network, list):
        for item in network:
            severity = item.get("severity", "info")
            if severity.lower() in ("high", "warning"):
                findings["network_issues"].append({
                    "title": item.get("scope", "Unknown"),
                    "description": item.get("description", ""),
                    "severity": severity,
                })

    return findings


def evaluate_security_score(scorecard: dict, threshold: int) -> bool:
    """Evaluate whether the app meets the minimum security threshold."""
    score = scorecard.get("security_score", 0)
    print(f"\n[*] Security Score: {score}/100 (threshold: {threshold})")

    if score >= threshold:
        print("[+] PASS: Application meets minimum security threshold")
        return True
    else:
        print("[-] FAIL: Application does not meet minimum security threshold")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="MobSF Automated Static Analysis Pipeline"
    )
    parser.add_argument("--apk", required=True, help="Path to APK/AAB file")
    parser.add_argument("--api-key", required=True, help="MobSF REST API key")
    parser.add_argument(
        "--url", default="http://localhost:8000", help="MobSF server URL"
    )
    parser.add_argument(
        "--threshold", type=int, default=60, help="Minimum security score (0-100)"
    )
    parser.add_argument("--output", default="mobsf_report.json", help="Output report path")
    parser.add_argument("--pdf", help="Optional PDF report output path")
    parser.add_argument(
        "--ci-mode", action="store_true", help="Exit with non-zero code on failure"
    )
    args = parser.parse_args()

    scanner = MobSFScanner(args.url, args.api_key)

    # Upload
    upload_result = scanner.upload_apk(args.apk)
    file_hash = upload_result["hash"]
    file_name = Path(args.apk).name
    scan_type = "apk" if file_name.endswith(".apk") else "aab"

    # Scan
    scanner.run_static_scan(file_hash, file_name, scan_type)

    # Get reports
    report = scanner.get_report_json(file_hash)
    scorecard = scanner.get_scorecard(file_hash)

    # Extract findings
    critical_findings = extract_critical_findings(report)

    # Build summary
    summary = {
        "file": file_name,
        "hash": file_hash,
        "security_score": scorecard.get("security_score", 0),
        "threshold": args.threshold,
        "pass": scorecard.get("security_score", 0) >= args.threshold,
        "findings_summary": {
            "manifest_issues": len(critical_findings["manifest_issues"]),
            "code_issues": len(critical_findings["code_issues"]),
            "network_issues": len(critical_findings["network_issues"]),
            "binary_issues": len(critical_findings["binary_issues"]),
            "crypto_issues": len(critical_findings["crypto_issues"]),
        },
        "critical_findings": critical_findings,
    }

    # Save JSON report
    with open(args.output, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"[+] Report saved: {args.output}")

    # Optional PDF
    if args.pdf:
        scanner.download_pdf_report(file_hash, args.pdf)

    # Evaluate
    passed = evaluate_security_score(scorecard, args.threshold)

    if args.ci_mode and not passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
