#!/usr/bin/env python3
"""
Windows Defender Configuration Auditor

Collects and audits Microsoft Defender for Endpoint settings across endpoints,
identifies configuration gaps, and generates compliance reports.
"""

import json
import subprocess
import sys
import os
from datetime import datetime


RECOMMENDED_SETTINGS = {
    "RealTimeProtectionEnabled": True,
    "BehaviorMonitoringEnabled": True,
    "IoavProtectionEnabled": True,
    "AntispywareEnabled": True,
    "AntivirusEnabled": True,
    "MAPSReporting": 2,  # Advanced
    "SubmitSamplesConsent": 3,  # SendAllSamples
    "PUAProtection": 1,  # Enabled
    "DisableBlockAtFirstSeen": False,
    "CloudBlockLevel": 2,  # High
    "CloudExtendedTimeout": 50,
    "EnableNetworkProtection": 1,  # Enabled
    "EnableControlledFolderAccess": 1,  # Enabled
    "SignatureUpdateInterval": 1,  # Hourly
}

RECOMMENDED_ASR_RULES = {
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550": {"name": "Block executable content from email", "mode": 1},
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A": {"name": "Block Office child processes", "mode": 1},
    "3B576869-A4EC-4529-8536-B80A7769E899": {"name": "Block Office executable creation", "mode": 1},
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84": {"name": "Block Office code injection", "mode": 1},
    "D3E037E1-3EB8-44C8-A917-57927947596D": {"name": "Block JS/VBS launching executables", "mode": 1},
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC": {"name": "Block obfuscated scripts", "mode": 1},
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B": {"name": "Block Win32 API from macros", "mode": 1},
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2": {"name": "Block LSASS credential stealing", "mode": 1},
    "D1E49AAC-8F56-4280-B9BA-993A6D77406C": {"name": "Block PSExec/WMI processes", "mode": 1},
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4": {"name": "Block untrusted USB processes", "mode": 1},
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B": {"name": "Block WMI persistence", "mode": 1},
    "56A863A9-875E-4185-98A7-B882C64B5CE5": {"name": "Block vulnerable signed drivers", "mode": 1},
}


def collect_defender_settings() -> dict:
    """Collect current Defender settings via PowerShell."""
    ps_cmd = """
    $prefs = Get-MpPreference
    $status = Get-MpComputerStatus
    $result = @{
        Preferences = @{
            RealTimeProtectionEnabled = $prefs.DisableRealtimeMonitoring -eq $false
            BehaviorMonitoringEnabled = $prefs.DisableBehaviorMonitoring -eq $false
            IoavProtectionEnabled = $prefs.DisableIOAVProtection -eq $false
            AntispywareEnabled = $status.AntispywareEnabled
            AntivirusEnabled = $status.AntivirusEnabled
            MAPSReporting = $prefs.MAPSReporting
            SubmitSamplesConsent = $prefs.SubmitSamplesConsent
            PUAProtection = $prefs.PUAProtection
            DisableBlockAtFirstSeen = $prefs.DisableBlockAtFirstSeen
            CloudBlockLevel = $prefs.CloudBlockLevel
            CloudExtendedTimeout = $prefs.CloudExtendedTimeout
            EnableNetworkProtection = $prefs.EnableNetworkProtection
            EnableControlledFolderAccess = $prefs.EnableControlledFolderAccess
            SignatureUpdateInterval = $prefs.SignatureUpdateInterval
        }
        ASRRules = @{}
        Status = @{
            AMEngineVersion = $status.AMEngineVersion
            AMProductVersion = $status.AMProductVersion
            AntispywareSignatureVersion = $status.AntispywareSignatureVersion
            AntivirusSignatureVersion = $status.AntivirusSignatureVersion
            AntivirusSignatureLastUpdated = $status.AntivirusSignatureLastUpdated.ToString('o')
            FullScanEndTime = if($status.FullScanEndTime) { $status.FullScanEndTime.ToString('o') } else { 'Never' }
            QuickScanEndTime = if($status.QuickScanEndTime) { $status.QuickScanEndTime.ToString('o') } else { 'Never' }
            RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
            TamperProtectionSource = $status.IsTamperProtected
        }
    }
    $ids = $prefs.AttackSurfaceReductionRules_Ids
    $actions = $prefs.AttackSurfaceReductionRules_Actions
    if ($ids -and $actions) {
        for ($i=0; $i -lt $ids.Count; $i++) {
            $result.ASRRules[$ids[$i].ToString().ToUpper()] = $actions[$i]
        }
    }
    $result | ConvertTo-Json -Depth 3
    """

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
        else:
            return {"error": result.stderr or "Failed to collect Defender settings"}
    except FileNotFoundError:
        return {"error": "PowerShell not available (requires Windows)"}
    except subprocess.TimeoutExpired:
        return {"error": "PowerShell command timed out"}
    except json.JSONDecodeError as e:
        return {"error": f"Failed to parse PowerShell output: {e}"}


def audit_settings(settings: dict) -> dict:
    """Audit collected settings against recommended baseline."""
    findings = {
        "compliant": [],
        "non_compliant": [],
        "asr_rules": {
            "enabled_block": [],
            "enabled_audit": [],
            "disabled": [],
            "missing": [],
        },
        "score": 0.0,
    }

    prefs = settings.get("Preferences", {})
    total_checks = 0
    passed_checks = 0

    for setting, expected in RECOMMENDED_SETTINGS.items():
        total_checks += 1
        actual = prefs.get(setting)

        if actual == expected:
            passed_checks += 1
            findings["compliant"].append({
                "setting": setting,
                "expected": expected,
                "actual": actual,
            })
        else:
            findings["non_compliant"].append({
                "setting": setting,
                "expected": expected,
                "actual": actual,
                "severity": "high" if setting in (
                    "RealTimeProtectionEnabled", "AntivirusEnabled",
                    "EnableNetworkProtection", "MAPSReporting",
                ) else "medium",
            })

    asr_rules = settings.get("ASRRules", {})
    for rule_guid, rule_info in RECOMMENDED_ASR_RULES.items():
        total_checks += 1
        mode = asr_rules.get(rule_guid)

        if mode == 1:
            passed_checks += 1
            findings["asr_rules"]["enabled_block"].append({
                "guid": rule_guid, "name": rule_info["name"],
            })
        elif mode == 2:
            findings["asr_rules"]["enabled_audit"].append({
                "guid": rule_guid, "name": rule_info["name"],
            })
        elif mode == 0:
            findings["asr_rules"]["disabled"].append({
                "guid": rule_guid, "name": rule_info["name"],
            })
        else:
            findings["asr_rules"]["missing"].append({
                "guid": rule_guid, "name": rule_info["name"],
            })

    if total_checks > 0:
        findings["score"] = round((passed_checks / total_checks) * 100, 2)

    return findings


def generate_report(settings: dict, findings: dict, output_path: str) -> None:
    """Generate configuration audit report."""
    report = {
        "report_generated": datetime.utcnow().isoformat() + "Z",
        "defender_status": settings.get("Status", {}),
        "compliance_score": findings["score"],
        "total_compliant": len(findings["compliant"]),
        "total_non_compliant": len(findings["non_compliant"]),
        "asr_summary": {
            "block_mode": len(findings["asr_rules"]["enabled_block"]),
            "audit_mode": len(findings["asr_rules"]["enabled_audit"]),
            "disabled": len(findings["asr_rules"]["disabled"]),
            "not_configured": len(findings["asr_rules"]["missing"]),
        },
        "non_compliant_settings": findings["non_compliant"],
        "asr_details": findings["asr_rules"],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "."

    print("Collecting Microsoft Defender settings...")
    settings = collect_defender_settings()

    if "error" in settings:
        print(f"Error: {settings['error']}")
        print("This tool requires Windows with Microsoft Defender for Endpoint.")
        sys.exit(1)

    print("Auditing against recommended baseline...")
    findings = audit_settings(settings)

    report_path = os.path.join(output_dir, "defender_audit_report.json")
    generate_report(settings, findings, report_path)
    print(f"Audit report: {report_path}")

    print(f"\n--- Defender Configuration Audit ---")
    print(f"Compliance Score: {findings['score']}%")
    print(f"Compliant settings: {len(findings['compliant'])}")
    print(f"Non-compliant: {len(findings['non_compliant'])}")
    print(f"\nASR Rules:")
    print(f"  Block mode: {len(findings['asr_rules']['enabled_block'])}")
    print(f"  Audit mode: {len(findings['asr_rules']['enabled_audit'])}")
    print(f"  Disabled: {len(findings['asr_rules']['disabled'])}")
    print(f"  Not configured: {len(findings['asr_rules']['missing'])}")

    if findings["non_compliant"]:
        print(f"\nNon-compliant settings requiring remediation:")
        for item in findings["non_compliant"]:
            print(f"  [{item['severity'].upper()}] {item['setting']}: expected={item['expected']}, actual={item['actual']}")
