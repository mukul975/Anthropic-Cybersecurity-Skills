#!/usr/bin/env python3
"""
Deep Link Vulnerability Scanner

Extracts deep link definitions from AndroidManifest.xml and tests for common vulnerabilities.

Usage:
    python process.py --manifest AndroidManifest.xml [--package com.target.app] [--output report.json]
"""

import argparse
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path


def extract_deep_links(manifest_path: str) -> list:
    """Extract deep link definitions from AndroidManifest.xml."""
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    ns = {"android": "http://schemas.android.com/apk/res/android"}

    deep_links = []

    for activity in root.findall(".//activity"):
        activity_name = activity.get(f"{{{ns['android']}}}name", "unknown")
        exported = activity.get(f"{{{ns['android']}}}exported", "false")

        for intent_filter in activity.findall("intent-filter"):
            actions = [a.get(f"{{{ns['android']}}}name", "") for a in intent_filter.findall("action")]
            categories = [c.get(f"{{{ns['android']}}}name", "") for c in intent_filter.findall("category")]

            if "android.intent.action.VIEW" not in actions:
                continue

            for data in intent_filter.findall("data"):
                scheme = data.get(f"{{{ns['android']}}}scheme", "")
                host = data.get(f"{{{ns['android']}}}host", "")
                path = data.get(f"{{{ns['android']}}}path", "")
                path_prefix = data.get(f"{{{ns['android']}}}pathPrefix", "")
                path_pattern = data.get(f"{{{ns['android']}}}pathPattern", "")

                if scheme:
                    deep_links.append({
                        "activity": activity_name,
                        "exported": exported,
                        "scheme": scheme,
                        "host": host,
                        "path": path or path_prefix or path_pattern or "/",
                        "browsable": "android.intent.category.BROWSABLE" in categories,
                        "url": f"{scheme}://{host}{path or path_prefix or path_pattern or '/'}",
                    })

    return deep_links


def assess_deep_link_security(deep_links: list) -> list:
    """Assess security of discovered deep links."""
    findings = []

    for link in deep_links:
        issues = []

        # Custom scheme (not https) - hijacking risk
        if link["scheme"] not in ("http", "https"):
            issues.append({
                "issue": "custom_scheme_hijackable",
                "severity": "HIGH",
                "description": f"Custom scheme '{link['scheme']}://' can be registered by any app",
            })

        # Exported activity without specific path
        if link["exported"] == "true" and link["path"] == "/":
            issues.append({
                "issue": "broad_path_matching",
                "severity": "MEDIUM",
                "description": "Activity matches all paths - wide attack surface",
            })

        # Browsable without verified links
        if link["browsable"] and link["scheme"] not in ("http", "https"):
            issues.append({
                "issue": "browsable_custom_scheme",
                "severity": "MEDIUM",
                "description": "Browsable intent with custom scheme invocable from web browsers",
            })

        if issues:
            findings.append({
                "deep_link": link["url"],
                "activity": link["activity"],
                "issues": issues,
            })

    return findings


def generate_test_commands(deep_links: list, package: str) -> list:
    """Generate ADB commands for testing deep links."""
    commands = []
    injection_payloads = [
        ("redirect_test", "?redirect=https://evil.com"),
        ("xss_test", "?q=<script>alert(1)</script>"),
        ("path_traversal", "/../../../etc/passwd"),
        ("sql_injection", "?id=1' OR '1'='1"),
    ]

    for link in deep_links:
        base_url = link["url"]

        # Basic invocation
        commands.append({
            "name": f"invoke_{link['activity']}",
            "command": f'adb shell am start -a android.intent.action.VIEW -d "{base_url}" {package}',
            "type": "basic",
        })

        # Injection tests
        for test_name, payload in injection_payloads:
            commands.append({
                "name": f"{test_name}_{link['activity']}",
                "command": f'adb shell am start -a android.intent.action.VIEW -d "{base_url}{payload}" {package}',
                "type": test_name,
            })

    return commands


def main():
    parser = argparse.ArgumentParser(description="Deep Link Vulnerability Scanner")
    parser.add_argument("--manifest", required=True, help="Path to AndroidManifest.xml")
    parser.add_argument("--package", default="com.target.app", help="Package name")
    parser.add_argument("--output", default="deeplink_report.json", help="Output report")
    args = parser.parse_args()

    if not Path(args.manifest).exists():
        print(f"[-] File not found: {args.manifest}")
        sys.exit(1)

    print("[*] Extracting deep links...")
    deep_links = extract_deep_links(args.manifest)
    print(f"[+] Found {len(deep_links)} deep link definitions")

    print("[*] Assessing security...")
    findings = assess_deep_link_security(deep_links)

    print("[*] Generating test commands...")
    commands = generate_test_commands(deep_links, args.package)

    report = {
        "scan": {
            "manifest": args.manifest,
            "package": args.package,
            "date": datetime.now().isoformat(),
        },
        "deep_links": deep_links,
        "findings": findings,
        "test_commands": commands,
        "summary": {
            "total_deep_links": len(deep_links),
            "total_findings": len(findings),
            "test_commands_generated": len(commands),
        },
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[+] Report saved: {args.output}")
    for f in findings:
        for issue in f["issues"]:
            print(f"    [{issue['severity']}] {f['deep_link']}: {issue['issue']}")


if __name__ == "__main__":
    main()
