#!/usr/bin/env python3
"""
MAM Policy Compliance Checker

Validates Intune App Protection Policy configurations against security baselines.

Usage:
    python process.py --policy policy.json [--baseline tier2] [--output report.json]
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

BASELINE_TIER2 = {
    "pin_required": True,
    "min_pin_length": 6,
    "biometric_enabled": True,
    "encrypt_app_data": True,
    "screen_capture_blocked": True,
    "backup_blocked": True,
    "clipboard_restriction": "managedApps",
    "jailbreak_blocked": True,
    "offline_grace_period_max_minutes": 1440,
    "max_pin_retries": 5,
}

BASELINE_TIER3 = {
    **BASELINE_TIER2,
    "min_pin_length": 8,
    "clipboard_restriction": "blocked",
    "offline_grace_period_max_minutes": 720,
    "save_as_blocked": True,
    "printing_blocked": True,
    "max_pin_retries": 3,
}


def check_compliance(policy: dict, baseline: dict) -> list:
    """Check policy against baseline requirements."""
    findings = []
    data = policy.get("dataProtectionSettings", {})
    access = policy.get("accessSettings", {})
    conditional = policy.get("conditionalLaunchSettings", {})

    checks = {
        "pin_required": access.get("pinRequired"),
        "min_pin_length": access.get("minimumPinLength", 0),
        "biometric_enabled": access.get("biometricEnabled"),
        "encrypt_app_data": data.get("encryptAppData"),
        "screen_capture_blocked": data.get("screenCaptureBlocked"),
        "backup_blocked": data.get("backupBlocked"),
        "jailbreak_blocked": conditional.get("jailbreakBlocked"),
    }

    for control, expected in baseline.items():
        actual = checks.get(control)
        if actual is None:
            findings.append({
                "control": control,
                "status": "MISSING",
                "expected": expected,
                "actual": None,
                "severity": "HIGH",
            })
        elif isinstance(expected, bool) and actual != expected:
            findings.append({
                "control": control,
                "status": "NON_COMPLIANT",
                "expected": expected,
                "actual": actual,
                "severity": "HIGH",
            })
        elif isinstance(expected, int) and isinstance(actual, int) and actual < expected:
            findings.append({
                "control": control,
                "status": "BELOW_MINIMUM",
                "expected": f">= {expected}",
                "actual": actual,
                "severity": "MEDIUM",
            })

    return findings


def main():
    parser = argparse.ArgumentParser(description="MAM Policy Compliance Checker")
    parser.add_argument("--policy", required=True, help="Policy JSON file")
    parser.add_argument("--baseline", choices=["tier2", "tier3"], default="tier2")
    parser.add_argument("--output", default="mam_compliance.json")
    args = parser.parse_args()

    with open(args.policy) as f:
        policy = json.load(f)

    baseline = BASELINE_TIER3 if args.baseline == "tier3" else BASELINE_TIER2
    findings = check_compliance(policy, baseline)

    compliant_count = len(baseline) - len(findings)
    report = {
        "check": {"policy": args.policy, "baseline": args.baseline, "date": datetime.now().isoformat()},
        "summary": {
            "total_controls": len(baseline),
            "compliant": compliant_count,
            "non_compliant": len(findings),
        },
        "findings": findings,
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Compliance: {compliant_count}/{len(baseline)} controls pass")
    print(f"[+] Report saved: {args.output}")


if __name__ == "__main__":
    main()
