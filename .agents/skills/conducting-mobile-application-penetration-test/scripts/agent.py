#!/usr/bin/env python3
"""Mobile application penetration testing agent using Frida and objection."""

import json
import sys
import argparse
import subprocess
from datetime import datetime


def run_apktool_decompile(apk_path):
    """Decompile Android APK for static analysis."""
    cmd = ["apktool", "d", apk_path, "-o", f"{apk_path}_decompiled", "-f"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {"status": "completed", "output_dir": f"{apk_path}_decompiled"}
    except FileNotFoundError:
        return {"status": "error", "message": "apktool not installed"}


def check_android_manifest(manifest_path):
    """Analyze AndroidManifest.xml for security issues."""
    findings = []
    try:
        with open(manifest_path, "r") as f:
            content = f.read()
        checks = [
            ("android:debuggable=\"true\"", "App is debuggable", "HIGH"),
            ("android:allowBackup=\"true\"", "App allows backup extraction", "MEDIUM"),
            ("android:exported=\"true\"", "Exported component found", "MEDIUM"),
            ("android:usesCleartextTraffic=\"true\"", "Cleartext traffic allowed", "HIGH"),
            ("android.permission.WRITE_EXTERNAL_STORAGE", "External storage write", "LOW"),
            ("android.permission.READ_PHONE_STATE", "Phone state access", "MEDIUM"),
        ]
        for pattern, desc, severity in checks:
            if pattern.lower() in content.lower():
                findings.append({"finding": desc, "pattern": pattern, "severity": severity})
    except FileNotFoundError:
        findings.append({"error": f"Manifest not found: {manifest_path}"})
    return findings


def scan_hardcoded_secrets(source_dir):
    """Scan decompiled source for hardcoded secrets."""
    import re
    patterns = {
        "API Key": re.compile(r'["\'](?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', re.I),
        "AWS Key": re.compile(r'AKIA[0-9A-Z]{16}'),
        "Private Key": re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),
        "Password": re.compile(r'["\'](?:password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']+)["\']', re.I),
        "Firebase URL": re.compile(r'https://[a-z0-9-]+\.firebaseio\.com'),
    }
    findings = []
    import os
    for root, _, files in os.walk(source_dir):
        for fname in files:
            if fname.endswith((".smali", ".java", ".xml", ".json", ".properties")):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        content = f.read()
                    for secret_type, pattern in patterns.items():
                        matches = pattern.findall(content)
                        for match in matches:
                            findings.append({
                                "type": secret_type,
                                "file": os.path.relpath(fpath, source_dir),
                                "severity": "CRITICAL" if "key" in secret_type.lower() else "HIGH",
                            })
                except OSError:
                    pass
    return findings


def check_ssl_pinning(package_name):
    """Check for SSL pinning implementation."""
    cmd = ["objection", "-g", package_name, "run", "android", "sslpinning", "disable"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {"ssl_pinning": "enabled" if "error" not in result.stdout.lower() else "not_detected"}
    except FileNotFoundError:
        return {"status": "error", "message": "objection not installed: pip install objection"}


def run_pentest(apk_path):
    """Execute mobile application penetration test."""
    print(f"\n{'='*60}")
    print(f"  MOBILE APP PENETRATION TEST")
    print(f"  APK: {apk_path}")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    decomp = run_apktool_decompile(apk_path)
    print(f"--- DECOMPILATION ---")
    print(f"  Status: {decomp['status']}")

    if decomp["status"] == "completed":
        manifest = check_android_manifest(f"{decomp['output_dir']}/AndroidManifest.xml")
        print(f"\n--- MANIFEST ANALYSIS ({len(manifest)} findings) ---")
        for f in manifest:
            if "error" not in f:
                print(f"  [{f['severity']}] {f['finding']}")

        secrets = scan_hardcoded_secrets(decomp["output_dir"])
        print(f"\n--- HARDCODED SECRETS ({len(secrets)} findings) ---")
        for s in secrets[:10]:
            print(f"  [{s['severity']}] {s['type']} in {s['file']}")

        return {"decompilation": decomp, "manifest": manifest, "secrets": secrets}
    return {"decompilation": decomp}


def main():
    parser = argparse.ArgumentParser(description="Mobile App Pentest Agent")
    parser.add_argument("--apk", required=True, help="Path to APK file")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_pentest(args.apk)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
