#!/usr/bin/env python3
"""Agent for auditing and managing BitLocker disk encryption across endpoints."""

import json
import argparse
import subprocess
import re
from datetime import datetime
from pathlib import Path


def get_bitlocker_status():
    """Get BitLocker status on local machine via manage-bde."""
    try:
        result = subprocess.run(
            ["manage-bde", "-status"], capture_output=True, text=True, timeout=30)
        volumes = []
        current = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Volume"):
                if current:
                    volumes.append(current)
                current = {"volume": line}
            elif ":" in line:
                key, _, value = line.partition(":")
                current[key.strip()] = value.strip()
        if current:
            volumes.append(current)
        return volumes
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def parse_bitlocker_report(report_path):
    """Parse BitLocker compliance report (CSV or JSON)."""
    entries = []
    if report_path.endswith(".json"):
        with open(report_path) as f:
            entries = json.load(f)
    else:
        import csv
        with open(report_path, newline="", encoding="utf-8-sig") as f:
            entries = list(csv.DictReader(f))
    return entries


def audit_bitlocker_compliance(devices):
    """Audit BitLocker compliance across fleet."""
    findings = []
    for device in devices:
        hostname = device.get("hostname", device.get("ComputerName", ""))
        protection = device.get("protection_status", device.get("ProtectionStatus", ""))
        encryption = device.get("encryption_method", device.get("EncryptionMethod", ""))
        key_protector = device.get("key_protector", device.get("KeyProtector", ""))
        recovery_key = device.get("recovery_key_escrowed",
                                  device.get("RecoveryKeyEscrowed", ""))
        if "off" in str(protection).lower() or protection == "0":
            findings.append({
                "hostname": hostname, "issue": "bitlocker_disabled",
                "severity": "CRITICAL",
            })
        if encryption and "aes" not in str(encryption).lower():
            findings.append({
                "hostname": hostname, "issue": "weak_encryption_method",
                "value": encryption, "severity": "HIGH",
            })
        if "128" in str(encryption):
            findings.append({
                "hostname": hostname, "issue": "aes_128_not_256",
                "severity": "MEDIUM",
                "recommendation": "Upgrade to AES-256",
            })
        if not key_protector or "tpm" not in str(key_protector).lower():
            findings.append({
                "hostname": hostname, "issue": "no_tpm_protector",
                "severity": "HIGH",
            })
        if str(recovery_key).lower() in ("no", "false", "0", ""):
            findings.append({
                "hostname": hostname, "issue": "recovery_key_not_escrowed",
                "severity": "HIGH",
                "recommendation": "Escrow recovery key to Active Directory",
            })
    return findings


def generate_gpo_recommendations():
    """Generate Group Policy recommendations for BitLocker."""
    return {
        "Computer Configuration": {
            "path": "Administrative Templates > Windows Components > BitLocker Drive Encryption",
            "settings": [
                {"name": "Choose drive encryption method (OS)",
                 "value": "AES-256", "policy": "Enabled"},
                {"name": "Require additional authentication at startup",
                 "value": "Allow BitLocker without compatible TPM: Disabled",
                 "policy": "Enabled"},
                {"name": "Choose how BitLocker-protected OS drives can be recovered",
                 "value": "Save to AD DS, Do not enable until stored",
                 "policy": "Enabled"},
                {"name": "Enforce drive encryption type on OS drives",
                 "value": "Full encryption", "policy": "Enabled"},
            ],
        },
    }


def calculate_compliance_metrics(devices, findings):
    """Calculate fleet encryption compliance metrics."""
    total = len(devices)
    encrypted = total - sum(1 for f in findings if f["issue"] == "bitlocker_disabled")
    strong_enc = encrypted - sum(1 for f in findings if f["issue"] in
                                  ("weak_encryption_method", "aes_128_not_256"))
    escrowed = total - sum(1 for f in findings if f["issue"] == "recovery_key_not_escrowed")
    return {
        "total_devices": total,
        "encrypted": encrypted,
        "encryption_rate": round(encrypted / total * 100, 1) if total else 0,
        "strong_encryption": strong_enc,
        "recovery_keys_escrowed": escrowed,
        "escrow_rate": round(escrowed / total * 100, 1) if total else 0,
    }


def main():
    parser = argparse.ArgumentParser(description="BitLocker Disk Encryption Agent")
    parser.add_argument("--report", help="BitLocker report CSV/JSON")
    parser.add_argument("--local", action="store_true", help="Check local machine")
    parser.add_argument("--output", default="bitlocker_audit_report.json")
    parser.add_argument("--action", choices=["audit", "local", "gpo", "full"], default="full")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.action in ("local", "full") and args.local:
        status = get_bitlocker_status()
        report["findings"]["local_status"] = status
        print(f"[+] Local volumes: {len(status)}")

    if args.action in ("audit", "full") and args.report:
        devices = parse_bitlocker_report(args.report)
        findings = audit_bitlocker_compliance(devices)
        metrics = calculate_compliance_metrics(devices, findings)
        report["findings"]["compliance_audit"] = findings
        report["findings"]["metrics"] = metrics
        print(f"[+] Devices: {metrics['total_devices']}, Encrypted: {metrics['encryption_rate']}%")

    if args.action in ("gpo", "full"):
        gpo = generate_gpo_recommendations()
        report["findings"]["gpo_recommendations"] = gpo
        print("[+] GPO recommendations generated")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
