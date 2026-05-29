#!/usr/bin/env python3
"""MobSF Android static analysis agent.

Automates APK upload, static analysis scanning, and report retrieval
via the MobSF REST API. Extracts security findings including manifest
analysis, code analysis, binary analysis, and certificate checks.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("[!] 'requests' library required: pip install requests", file=sys.stderr)
    sys.exit(1)


def get_mobsf_config():
    """Return MobSF server URL and API key from env or defaults."""
    server = os.environ.get("MOBSF_URL", "http://localhost:8000")
    api_key = os.environ.get("MOBSF_API_KEY", "")
    if not api_key:
        print("[!] Set MOBSF_API_KEY environment variable", file=sys.stderr)
        sys.exit(1)
    return server.rstrip("/"), api_key


def upload_apk(server, api_key, apk_path):
    """Upload an APK file to MobSF and return the file hash."""
    url = f"{server}/api/v1/upload"
    headers = {"Authorization": api_key}
    if not os.path.isfile(apk_path):
        print(f"[!] File not found: {apk_path}", file=sys.stderr)
        sys.exit(1)
    print(f"[*] Uploading {os.path.basename(apk_path)} to MobSF...")
    with open(apk_path, "rb") as f:
        resp = requests.post(
            url,
            files={"file": (os.path.basename(apk_path), f, "application/octet-stream")},
            headers=headers,
            timeout=300,
        )
    resp.raise_for_status()
    data = resp.json()
    file_hash = data.get("hash", "")
    scan_type = data.get("scan_type", "apk")
    file_name = data.get("file_name", os.path.basename(apk_path))
    print(f"[+] Uploaded: {file_name} (hash: {file_hash}, type: {scan_type})")
    return file_hash, scan_type, file_name


def start_scan(server, api_key, file_hash, scan_type, file_name):
    """Trigger static analysis scan on the uploaded APK."""
    url = f"{server}/api/v1/scan"
    headers = {"Authorization": api_key}
    print(f"[*] Starting static analysis scan for {file_name}...")
    resp = requests.post(
        url,
        data={"hash": file_hash, "scan_type": scan_type, "file_name": file_name},
        headers=headers,
        timeout=600,
    )
    resp.raise_for_status()
    print("[+] Scan complete")
    return resp.json()


def get_report(server, api_key, file_hash):
    """Retrieve the JSON report for a scanned APK."""
    url = f"{server}/api/v1/report_json"
    headers = {"Authorization": api_key}
    resp = requests.post(
        url,
        data={"hash": file_hash},
        headers=headers,
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()


def get_scorecard(server, api_key, file_hash):
    """Retrieve the security scorecard for a scanned APK."""
    url = f"{server}/api/v1/scorecard"
    headers = {"Authorization": api_key}
    resp = requests.post(
        url,
        data={"hash": file_hash},
        headers=headers,
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


def extract_findings(report):
    """Extract structured security findings from MobSF report JSON."""
    findings = []

    # Manifest analysis
    for item in report.get("manifest_analysis", []):
        findings.append({
            "category": "manifest",
            "title": item.get("title", "Unknown"),
            "severity": item.get("severity", "info").upper(),
            "description": item.get("description", ""),
        })

    # Code analysis
    code_analysis = report.get("code_analysis", {})
    if isinstance(code_analysis, dict):
        for key, value in code_analysis.items():
            if isinstance(value, dict):
                findings.append({
                    "category": "code",
                    "title": value.get("metadata", {}).get("description", key),
                    "severity": value.get("metadata", {}).get("severity", "info").upper(),
                    "description": value.get("metadata", {}).get("cwe", ""),
                    "files": list(value.get("files", {}).keys())[:5],
                })

    # Binary analysis
    for item in report.get("binary_analysis", []):
        findings.append({
            "category": "binary",
            "title": item.get("name", "Unknown"),
            "severity": item.get("severity", "info").upper(),
            "description": item.get("description", ""),
        })

    # Certificate analysis
    cert_info = report.get("certificate_analysis", {})
    if isinstance(cert_info, dict):
        cert_findings = cert_info.get("certificate_findings", [])
        for item in cert_findings:
            findings.append({
                "category": "certificate",
                "title": item.get("title", "Certificate finding"),
                "severity": item.get("severity", "info").upper(),
                "description": item.get("description", ""),
            })

    # Permissions
    permissions = report.get("permissions", {})
    dangerous_perms = []
    if isinstance(permissions, dict):
        for perm, details in permissions.items():
            if isinstance(details, dict) and details.get("status") == "dangerous":
                dangerous_perms.append(perm)
    if dangerous_perms:
        findings.append({
            "category": "permissions",
            "title": f"{len(dangerous_perms)} dangerous permissions declared",
            "severity": "WARNING",
            "description": ", ".join(dangerous_perms[:10]),
        })

    return findings


def format_summary(report, findings):
    """Print a human-readable summary of the analysis."""
    app_name = report.get("app_name", "Unknown")
    package = report.get("package_name", "Unknown")
    version = report.get("version_name", "Unknown")
    sdk_min = report.get("min_sdk", "?")
    sdk_target = report.get("target_sdk", "?")
    security_score = report.get("security_score", "N/A")

    print(f"\n{'='*60}")
    print("  MobSF Static Analysis Report")
    print(f"{'='*60}")
    print(f"  App Name    : {app_name}")
    print(f"  Package     : {package}")
    print(f"  Version     : {version}")
    print(f"  Min SDK     : {sdk_min} | Target SDK: {sdk_target}")
    print(f"  Security    : {security_score}/100")
    print(f"{'='*60}")

    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\n  Findings Summary:")
    for sev in ["CRITICAL", "HIGH", "WARNING", "MEDIUM", "INFO", "LOW"]:
        if sev in severity_counts:
            print(f"    {sev:10s}: {severity_counts[sev]}")

    print("\n  Top Findings:")
    high_findings = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH", "WARNING")]
    for f in high_findings[:10]:
        print(f"    [{f['severity']:8s}] [{f['category']:12s}] {f['title']}")

    return severity_counts


def main():
    parser = argparse.ArgumentParser(
        description="MobSF Android static analysis agent - upload, scan, and report"
    )
    parser.add_argument("--apk", required=True, help="Path to the APK file to analyze")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--server", help="MobSF server URL (or set MOBSF_URL env var)")
    parser.add_argument("--api-key", help="MobSF API key (or set MOBSF_API_KEY env var)")
    parser.add_argument("--hash", help="Skip upload; use existing hash to retrieve report")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    if args.server:
        os.environ["MOBSF_URL"] = args.server
    if args.api_key:
        os.environ["MOBSF_API_KEY"] = args.api_key

    server, api_key = get_mobsf_config()

    if args.hash:
        file_hash = args.hash
        print(f"[*] Using existing hash: {file_hash}")
    else:
        file_hash, scan_type, file_name = upload_apk(server, api_key, args.apk)
        start_scan(server, api_key, file_hash, scan_type, file_name)

    report = get_report(server, api_key, file_hash)
    findings = extract_findings(report)
    severity_counts = format_summary(report, findings)

    output_report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "MobSF",
        "apk": args.apk,
        "app_name": report.get("app_name", ""),
        "package_name": report.get("package_name", ""),
        "version": report.get("version_name", ""),
        "security_score": report.get("security_score", 0),
        "severity_counts": severity_counts,
        "findings": findings,
        "risk_level": (
            "CRITICAL" if severity_counts.get("CRITICAL", 0) > 0
            else "HIGH" if severity_counts.get("HIGH", 0) > 0
            else "MEDIUM" if severity_counts.get("WARNING", 0) > 0
            else "LOW"
        ),
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(output_report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(output_report, indent=2))

    print(f"\n[*] Risk Level: {output_report['risk_level']}")


if __name__ == "__main__":
    main()
