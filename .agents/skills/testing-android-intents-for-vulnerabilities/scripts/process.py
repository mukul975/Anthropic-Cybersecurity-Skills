#!/usr/bin/env python3
"""
Android Intent Vulnerability Scanner

Parses AndroidManifest.xml to identify exported components and generate
Drozer/ADB test commands for IPC security assessment.

Usage:
    python process.py --manifest AndroidManifest.xml [--package com.target.app] [--output report.json]
"""

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path


def parse_manifest(manifest_path: str) -> dict:
    """Parse AndroidManifest.xml for exported components."""
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    ns = {"android": "http://schemas.android.com/apk/res/android"}

    package = root.get("package", "unknown")
    target_sdk = ""
    for sdk in root.findall(".//uses-sdk"):
        target_sdk = sdk.get(f"{{{ns['android']}}}targetSdkVersion", "unknown")

    components = {"activities": [], "services": [], "receivers": [], "providers": []}

    for comp_type, tag in [("activities", "activity"), ("services", "service"),
                            ("receivers", "receiver"), ("providers", "provider")]:
        for elem in root.findall(f".//{tag}"):
            name = elem.get(f"{{{ns['android']}}}name", "")
            exported = elem.get(f"{{{ns['android']}}}exported", "")
            permission = elem.get(f"{{{ns['android']}}}permission", "")
            has_intent_filter = len(elem.findall("intent-filter")) > 0

            # Determine effective export status
            if exported == "true":
                is_exported = True
            elif exported == "false":
                is_exported = False
            else:
                is_exported = has_intent_filter  # Default: exported if has intent-filter (pre API 31)

            if is_exported:
                component = {
                    "name": name,
                    "exported": True,
                    "permission": permission,
                    "has_intent_filter": has_intent_filter,
                    "protected": bool(permission),
                }

                # Get intent filter actions
                actions = []
                for intent_filter in elem.findall("intent-filter"):
                    for action in intent_filter.findall("action"):
                        actions.append(action.get(f"{{{ns['android']}}}name", ""))
                component["actions"] = actions

                # Provider-specific attributes
                if tag == "provider":
                    component["authorities"] = elem.get(f"{{{ns['android']}}}authorities", "")
                    component["read_permission"] = elem.get(f"{{{ns['android']}}}readPermission", "")
                    component["write_permission"] = elem.get(f"{{{ns['android']}}}writePermission", "")

                components[comp_type].append(component)

    return {"package": package, "target_sdk": target_sdk, "components": components}


def generate_test_commands(parsed: dict) -> list:
    """Generate Drozer and ADB test commands."""
    commands = []
    pkg = parsed["package"]

    for activity in parsed["components"]["activities"]:
        commands.append({
            "component": activity["name"],
            "type": "activity",
            "tool": "drozer",
            "command": f'run app.activity.start --component {pkg} {activity["name"]}',
            "risk": "HIGH" if not activity["protected"] else "LOW",
        })

    for receiver in parsed["components"]["receivers"]:
        for action in receiver.get("actions", []):
            commands.append({
                "component": receiver["name"],
                "type": "receiver",
                "tool": "adb",
                "command": f'adb shell am broadcast -a {action} -n {pkg}/{receiver["name"]}',
                "risk": "HIGH" if not receiver["protected"] else "LOW",
            })

    for provider in parsed["components"]["providers"]:
        auth = provider.get("authorities", "")
        if auth:
            commands.append({
                "component": provider["name"],
                "type": "provider_query",
                "tool": "drozer",
                "command": f'run app.provider.query content://{auth}/',
                "risk": "CRITICAL" if not provider.get("read_permission") else "MEDIUM",
            })
            commands.append({
                "component": provider["name"],
                "type": "provider_injection",
                "tool": "drozer",
                "command": f'run scanner.provider.injection -a {pkg}',
                "risk": "CRITICAL",
            })

    return commands


def assess_findings(parsed: dict) -> list:
    """Assess security of exported components."""
    findings = []
    components = parsed["components"]

    for comp_type, items in components.items():
        for item in items:
            if not item.get("protected"):
                findings.append({
                    "component": item["name"],
                    "type": comp_type,
                    "issue": f"Exported {comp_type[:-1]} without permission protection",
                    "severity": "HIGH" if comp_type in ("providers", "receivers") else "MEDIUM",
                    "owasp_mobile": "M8",
                    "cwe": "CWE-926",
                })

    # Check for sensitive-looking unprotected components
    sensitive_keywords = ["admin", "debug", "internal", "settings", "config", "payment", "auth"]
    for comp_type, items in components.items():
        for item in items:
            name_lower = item["name"].lower()
            if any(kw in name_lower for kw in sensitive_keywords) and not item.get("protected"):
                findings.append({
                    "component": item["name"],
                    "type": comp_type,
                    "issue": f"Sensitive component '{item['name']}' exported without protection",
                    "severity": "CRITICAL",
                    "owasp_mobile": "M8",
                    "cwe": "CWE-926",
                })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Android Intent Vulnerability Scanner")
    parser.add_argument("--manifest", required=True, help="AndroidManifest.xml path")
    parser.add_argument("--output", default="intent_scan.json", help="Output report")
    args = parser.parse_args()

    if not Path(args.manifest).exists():
        print(f"[-] Not found: {args.manifest}")
        sys.exit(1)

    parsed = parse_manifest(args.manifest)
    commands = generate_test_commands(parsed)
    findings = assess_findings(parsed)

    total_exported = sum(len(v) for v in parsed["components"].values())

    report = {
        "scan": {"manifest": args.manifest, "package": parsed["package"],
                 "target_sdk": parsed["target_sdk"], "date": datetime.now().isoformat()},
        "attack_surface": {
            "total_exported": total_exported,
            "activities": len(parsed["components"]["activities"]),
            "services": len(parsed["components"]["services"]),
            "receivers": len(parsed["components"]["receivers"]),
            "providers": len(parsed["components"]["providers"]),
        },
        "findings": findings,
        "test_commands": commands,
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[+] Package: {parsed['package']}")
    print(f"[+] Exported components: {total_exported}")
    print(f"[+] Findings: {len(findings)}")
    print(f"[+] Test commands generated: {len(commands)}")
    print(f"[+] Report saved: {args.output}")


if __name__ == "__main__":
    main()
