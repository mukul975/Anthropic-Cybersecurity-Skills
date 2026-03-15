#!/usr/bin/env python3
"""
BitLocker Compliance Checker

Checks BitLocker encryption status across endpoints and generates
compliance reports for audit purposes.
"""

import json
import subprocess
import sys
import os
import csv
from datetime import datetime


def check_bitlocker_status() -> dict:
    """Check BitLocker status on local Windows endpoint."""
    ps_cmd = """
    $volumes = Get-BitLockerVolume
    $results = @()
    foreach ($vol in $volumes) {
        $protectors = @()
        foreach ($kp in $vol.KeyProtector) {
            $protectors += @{
                Type = $kp.KeyProtectorType.ToString()
                Id = $kp.KeyProtectorId
            }
        }
        $results += @{
            MountPoint = $vol.MountPoint
            VolumeStatus = $vol.VolumeStatus.ToString()
            ProtectionStatus = $vol.ProtectionStatus.ToString()
            EncryptionMethod = $vol.EncryptionMethod.ToString()
            EncryptionPercentage = $vol.EncryptionPercentage
            VolumeType = $vol.VolumeType.ToString()
            KeyProtectors = $protectors
            AutoUnlockEnabled = $vol.AutoUnlockEnabled
            AutoUnlockKeyStored = $vol.AutoUnlockKeyStored
        }
    }
    $tpm = Get-Tpm
    @{
        Hostname = $env:COMPUTERNAME
        Volumes = $results
        TPM = @{
            Present = $tpm.TpmPresent
            Ready = $tpm.TpmReady
            Enabled = $tpm.TpmEnabled
            Activated = $tpm.TpmActivated
        }
    } | ConvertTo-Json -Depth 4
    """

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
        return {"error": result.stderr or "Failed to check BitLocker status"}
    except FileNotFoundError:
        return {"error": "PowerShell not available (requires Windows)"}
    except subprocess.TimeoutExpired:
        return {"error": "Command timed out"}
    except json.JSONDecodeError as e:
        return {"error": f"Parse error: {e}"}


def assess_compliance(status: dict) -> dict:
    """Assess BitLocker compliance against security baseline."""
    findings = {
        "hostname": status.get("Hostname", "unknown"),
        "overall_compliant": True,
        "tpm_status": "compliant",
        "volume_findings": [],
    }

    tpm = status.get("TPM", {})
    if not tpm.get("Present") or not tpm.get("Ready"):
        findings["tpm_status"] = "non-compliant"
        findings["overall_compliant"] = False

    for vol in status.get("Volumes", []):
        vol_finding = {
            "mount_point": vol["MountPoint"],
            "compliant": True,
            "issues": [],
        }

        if vol["VolumeStatus"] != "FullyEncrypted":
            vol_finding["compliant"] = False
            vol_finding["issues"].append(f"Not fully encrypted: {vol['VolumeStatus']}")

        if vol["ProtectionStatus"] != "On":
            vol_finding["compliant"] = False
            vol_finding["issues"].append(f"Protection not enabled: {vol['ProtectionStatus']}")

        if vol["EncryptionMethod"] not in ("XtsAes256", "XtsAes128"):
            vol_finding["issues"].append(f"Weak encryption method: {vol['EncryptionMethod']}")

        protector_types = [kp["Type"] for kp in vol.get("KeyProtectors", [])]
        has_recovery = "RecoveryPassword" in protector_types or "NumericalPassword" in protector_types
        if not has_recovery:
            vol_finding["compliant"] = False
            vol_finding["issues"].append("No recovery password protector configured")

        has_tpm = any(t in protector_types for t in ["Tpm", "TpmPin", "TpmPinStartupKey"])
        if vol["VolumeType"] == "OperatingSystem" and not has_tpm:
            vol_finding["compliant"] = False
            vol_finding["issues"].append("OS volume missing TPM protector")

        if not vol_finding["compliant"]:
            findings["overall_compliant"] = False

        findings["volume_findings"].append(vol_finding)

    return findings


def generate_report(status: dict, compliance: dict, output_path: str) -> None:
    """Generate BitLocker compliance report."""
    report = {
        "report_generated": datetime.utcnow().isoformat() + "Z",
        "hostname": status.get("Hostname", "unknown"),
        "overall_compliance": "COMPLIANT" if compliance["overall_compliant"] else "NON-COMPLIANT",
        "tpm_status": compliance["tpm_status"],
        "tpm_details": status.get("TPM", {}),
        "volumes": [],
    }

    for vol, finding in zip(status.get("Volumes", []), compliance["volume_findings"]):
        report["volumes"].append({
            "mount_point": vol["MountPoint"],
            "status": vol["VolumeStatus"],
            "protection": vol["ProtectionStatus"],
            "encryption_method": vol["EncryptionMethod"],
            "encryption_percent": vol["EncryptionPercentage"],
            "key_protectors": [kp["Type"] for kp in vol.get("KeyProtectors", [])],
            "compliant": finding["compliant"],
            "issues": finding["issues"],
        })

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "."

    print("Checking BitLocker status...")
    status = check_bitlocker_status()

    if "error" in status:
        print(f"Error: {status['error']}")
        print("This tool requires Windows with BitLocker support.")
        sys.exit(1)

    print("Assessing compliance...")
    compliance = assess_compliance(status)

    report_path = os.path.join(output_dir, "bitlocker_compliance.json")
    generate_report(status, compliance, report_path)
    print(f"Compliance report: {report_path}")

    print(f"\n--- BitLocker Compliance ---")
    print(f"Hostname: {compliance['hostname']}")
    print(f"Overall: {'COMPLIANT' if compliance['overall_compliant'] else 'NON-COMPLIANT'}")
    print(f"TPM: {compliance['tpm_status']}")

    for vf in compliance["volume_findings"]:
        status_icon = "PASS" if vf["compliant"] else "FAIL"
        print(f"\n  [{status_icon}] {vf['mount_point']}")
        for issue in vf["issues"]:
            print(f"    - {issue}")
