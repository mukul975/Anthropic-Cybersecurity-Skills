#!/usr/bin/env python3
"""Windows Defender advanced configuration audit agent."""

import json
import sys
import argparse
import subprocess
from datetime import datetime


def get_defender_status():
    """Get Windows Defender status via PowerShell."""
    cmd = ["powershell", "-Command", "Get-MpComputerStatus | ConvertTo-Json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return json.loads(result.stdout) if result.stdout.strip() else {"error": "No output"}
    except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired) as e:
        return {"error": str(e)}


def get_defender_preferences():
    """Get Windows Defender preference settings."""
    cmd = ["powershell", "-Command", "Get-MpPreference | ConvertTo-Json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return json.loads(result.stdout) if result.stdout.strip() else {"error": "No output"}
    except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired) as e:
        return {"error": str(e)}


def audit_asr_rules():
    """Audit Attack Surface Reduction rules configuration."""
    cmd = ["powershell", "-Command",
           "Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids | ConvertTo-Json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        rule_ids = json.loads(result.stdout) if result.stdout.strip() else []
    except (FileNotFoundError, json.JSONDecodeError):
        rule_ids = []
    critical_asr_rules = {
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "Block executable content from email and webmail",
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Block all Office applications from creating child processes",
        "3b576869-a4ec-4529-8536-b80a7769e899": "Block Office applications from creating executable content",
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "Block Office applications from injecting code",
        "d3e037e1-3eb8-44c8-a917-57927947596d": "Block JavaScript or VBScript from launching downloaded content",
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc": "Block execution of potentially obfuscated scripts",
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "Block Win32 API calls from Office macros",
        "56a863a9-875e-4185-98a7-b882c64b5ce5": "Block abuse of exploited vulnerable signed drivers",
    }
    configured = set(rule_ids) if isinstance(rule_ids, list) else set()
    missing = []
    for rule_id, desc in critical_asr_rules.items():
        if rule_id not in configured:
            missing.append({"rule_id": rule_id, "description": desc, "severity": "HIGH"})
    return {"configured_count": len(configured), "missing_critical": missing}


def check_tamper_protection():
    """Check tamper protection status."""
    cmd = ["powershell", "-Command",
           "(Get-MpComputerStatus).IsTamperProtected"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        enabled = "true" in result.stdout.strip().lower()
        return {"tamper_protection": enabled,
                "severity": "CRITICAL" if not enabled else "INFO"}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {"error": "Cannot check tamper protection"}


def run_audit():
    """Execute Windows Defender audit."""
    print(f"\n{'='*60}")
    print(f"  WINDOWS DEFENDER ADVANCED SETTINGS AUDIT")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    status = get_defender_status()
    print(f"--- DEFENDER STATUS ---")
    if "error" not in status:
        print(f"  Real-time protection: {status.get('RealTimeProtectionEnabled', 'N/A')}")
        print(f"  Behavior monitoring: {status.get('BehaviorMonitorEnabled', 'N/A')}")
        print(f"  Cloud protection: {status.get('OnAccessProtectionEnabled', 'N/A')}")
        print(f"  Signature version: {status.get('AntivirusSignatureVersion', 'N/A')}")

    asr = audit_asr_rules()
    print(f"\n--- ASR RULES ---")
    print(f"  Configured: {asr['configured_count']}")
    print(f"  Missing critical: {len(asr['missing_critical'])}")
    for rule in asr["missing_critical"][:5]:
        print(f"    [{rule['severity']}] {rule['description']}")

    tamper = check_tamper_protection()
    print(f"\n--- TAMPER PROTECTION ---")
    print(f"  Enabled: {tamper.get('tamper_protection', 'N/A')}")

    return {"status": status, "asr": asr, "tamper": tamper}


def main():
    parser = argparse.ArgumentParser(description="Windows Defender Audit Agent")
    parser.add_argument("--audit", action="store_true", help="Run full audit")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    if args.audit:
        report = run_audit()
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n[+] Report saved to {args.output}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
