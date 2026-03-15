#!/usr/bin/env python3
# For authorized penetration testing and lab environments only
"""Mobile App Penetration Testing Agent - Tests Android/iOS apps for OWASP MASTG vulnerabilities."""

import json
import logging
import argparse
import subprocess
from datetime import datetime

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def decompile_apk(apk_path, output_dir):
    """Decompile Android APK using apktool for static analysis."""
    cmd = ["apktool", "d", apk_path, "-o", output_dir, "-f"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode == 0:
        logger.info("APK decompiled to %s", output_dir)
        return True
    logger.error("Decompilation failed: %s", result.stderr[:200])
    return False


def extract_strings_from_apk(apk_path):
    """Extract hardcoded strings from APK for sensitive data detection."""
    cmd = ["strings", apk_path]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    sensitive_patterns = {
        "api_key": [], "password": [], "secret": [], "token": [],
        "http://": [], "aws_access": [], "private_key": [],
    }
    for line in result.stdout.split("\n"):
        line_lower = line.strip().lower()
        for pattern in sensitive_patterns:
            if pattern in line_lower and len(line.strip()) < 200:
                sensitive_patterns[pattern].append(line.strip())
    total = sum(len(v) for v in sensitive_patterns.values())
    logger.info("Extracted %d sensitive strings from APK", total)
    return sensitive_patterns


def check_android_manifest(manifest_path):
    """Analyze AndroidManifest.xml for security misconfigurations."""
    findings = []
    with open(manifest_path, "r", errors="ignore") as f:
        content = f.read()
    checks = [
        ("android:debuggable=\"true\"", "App is debuggable - allows runtime manipulation"),
        ("android:allowBackup=\"true\"", "Backup allowed - data extractable via adb backup"),
        ("android:exported=\"true\"", "Components exported without permission protection"),
        ("android:usesCleartextTraffic=\"true\"", "Cleartext HTTP traffic allowed"),
        ("android:networkSecurityConfig", None),
    ]
    for pattern, description in checks:
        if description and pattern in content:
            findings.append({"check": pattern, "finding": description, "severity": "Medium"})
    if "android:networkSecurityConfig" not in content:
        findings.append({
            "check": "Missing networkSecurityConfig",
            "finding": "No custom network security configuration - may trust user-installed CAs",
            "severity": "Medium",
        })
    logger.info("Manifest analysis: %d findings", len(findings))
    return findings


def test_certificate_pinning(target_url):
    """Test if the app enforces certificate pinning via mitmproxy check."""
    try:
        resp = requests.get(target_url, timeout=10, verify=False)
        return {
            "url": target_url,
            "status": resp.status_code,
            "pinning_bypassed": resp.status_code == 200,
            "note": "If 200 with proxy active, cert pinning is not enforced",
        }
    except requests.RequestException as e:
        return {"url": target_url, "pinning_bypassed": False, "error": str(e)}


def check_insecure_storage_adb():
    """Check for insecure data storage on connected Android device via adb."""
    checks = [
        ("shared_prefs", "run-as com.target.app ls /data/data/com.target.app/shared_prefs/"),
        ("databases", "run-as com.target.app ls /data/data/com.target.app/databases/"),
        ("external_storage", "ls /sdcard/Android/data/com.target.app/"),
    ]
    findings = []
    for check_name, adb_cmd in checks:
        cmd = ["adb", "shell"] + adb_cmd.split()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            findings.append({
                "check": check_name,
                "files_found": result.stdout.strip().split("\n"),
                "severity": "High" if check_name == "external_storage" else "Medium",
            })
    logger.info("Storage checks: %d findings", len(findings))
    return findings


def test_api_endpoints(base_url, endpoints, auth_token=None):
    """Test mobile app API endpoints for common vulnerabilities."""
    headers = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    results = []
    for endpoint in endpoints:
        url = f"{base_url}{endpoint}"
        try:
            resp = requests.get(url, headers=headers, timeout=10, verify=False)
            result = {
                "endpoint": endpoint,
                "status": resp.status_code,
                "response_size": len(resp.content),
            }
            no_auth_resp = requests.get(url, timeout=10, verify=False)
            if no_auth_resp.status_code == 200 and resp.status_code == 200:
                result["auth_bypass"] = True
                result["severity"] = "Critical"
            else:
                result["auth_bypass"] = False
            results.append(result)
        except requests.RequestException:
            continue
    return results


def check_root_detection(package_name):
    """Check if the app implements root/jailbreak detection."""
    cmd = ["adb", "shell", "pm", "dump", package_name]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    root_indicators = ["rootbeer", "rootdetect", "safetynet", "integrity", "tamper"]
    found = [ind for ind in root_indicators if ind in result.stdout.lower()]
    return {
        "package": package_name,
        "root_detection_indicators": found,
        "likely_protected": len(found) > 0,
    }


def generate_report(apk_analysis, manifest_findings, storage_findings, api_results, cert_pinning):
    """Generate mobile app penetration test report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "sensitive_strings": {k: len(v) for k, v in apk_analysis.items()},
        "manifest_findings": manifest_findings,
        "storage_findings": storage_findings,
        "api_security": api_results,
        "certificate_pinning": cert_pinning,
    }
    total = len(manifest_findings) + len(storage_findings) + len([r for r in api_results if r.get("auth_bypass")])
    print(f"MOBILE PENTEST REPORT - {total} findings")
    return report


def main():
    parser = argparse.ArgumentParser(description="Mobile App Penetration Testing Agent")
    parser.add_argument("--apk", help="Path to Android APK file")
    parser.add_argument("--manifest", help="Path to AndroidManifest.xml")
    parser.add_argument("--api-url", help="Backend API base URL")
    parser.add_argument("--auth-token", help="Auth token for API testing")
    parser.add_argument("--output", default="mobile_pentest_report.json")
    args = parser.parse_args()

    apk_strings = extract_strings_from_apk(args.apk) if args.apk else {}
    manifest_findings = check_android_manifest(args.manifest) if args.manifest else []
    storage = check_insecure_storage_adb()

    api_results = []
    if args.api_url:
        endpoints = ["/api/v1/user/profile", "/api/v1/users", "/api/v1/settings", "/api/v1/admin"]
        api_results = test_api_endpoints(args.api_url, endpoints, args.auth_token)

    cert_pinning = test_certificate_pinning(args.api_url) if args.api_url else {}

    report = generate_report(apk_strings, manifest_findings, storage, api_results, cert_pinning)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
