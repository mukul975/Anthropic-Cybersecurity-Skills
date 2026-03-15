#!/usr/bin/env python3
"""Device posture assessment agent for zero trust endpoint compliance evaluation."""

import argparse
import json
import logging
import os
import platform
import subprocess
import sys
from datetime import datetime
from typing import Dict, List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def check_os_version() -> dict:
    """Check OS version and patch level."""
    return {
        "os": platform.system(),
        "version": platform.version(),
        "release": platform.release(),
        "machine": platform.machine(),
    }


def check_disk_encryption() -> dict:
    """Check if disk encryption is enabled."""
    system = platform.system()
    if system == "Windows":
        try:
            result = subprocess.run(
                ["manage-bde", "-status", "C:"], capture_output=True, text=True, timeout=10)
            encrypted = "Fully Encrypted" in result.stdout or "100%" in result.stdout
            return {"enabled": encrypted, "tool": "BitLocker", "output": result.stdout[:200]}
        except FileNotFoundError:
            return {"enabled": False, "tool": "BitLocker", "error": "manage-bde not found"}
    elif system == "Darwin":
        try:
            result = subprocess.run(
                ["fdesetup", "status"], capture_output=True, text=True, timeout=10)
            return {"enabled": "On" in result.stdout, "tool": "FileVault"}
        except FileNotFoundError:
            return {"enabled": False, "error": "fdesetup not found"}
    elif system == "Linux":
        try:
            result = subprocess.run(
                ["lsblk", "-o", "NAME,TYPE,FSTYPE"], capture_output=True, text=True, timeout=10)
            encrypted = "crypto_LUKS" in result.stdout or "crypt" in result.stdout
            return {"enabled": encrypted, "tool": "LUKS"}
        except FileNotFoundError:
            return {"enabled": False, "error": "lsblk not found"}
    return {"enabled": False, "error": "Unsupported OS"}


def check_firewall_status() -> dict:
    """Check if host firewall is enabled."""
    system = platform.system()
    if system == "Windows":
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=10)
            enabled = "ON" in result.stdout.upper()
            return {"enabled": enabled, "tool": "Windows Firewall"}
        except FileNotFoundError:
            return {"enabled": False, "error": "netsh not found"}
    elif system == "Linux":
        try:
            result = subprocess.run(
                ["ufw", "status"], capture_output=True, text=True, timeout=10)
            return {"enabled": "active" in result.stdout.lower(), "tool": "UFW"}
        except FileNotFoundError:
            return {"enabled": False, "error": "ufw not found"}
    return {"enabled": False, "error": "Unsupported OS"}


def check_antivirus() -> dict:
    """Check if antivirus/EDR is running."""
    system = platform.system()
    if system == "Windows":
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15)
            if result.stdout:
                data = json.loads(result.stdout)
                return {"enabled": data.get("RealTimeProtectionEnabled", False),
                        "tool": "Windows Defender"}
        except (FileNotFoundError, json.JSONDecodeError):
            pass
    return {"enabled": False, "tool": "unknown"}


def check_screen_lock() -> dict:
    """Check if screen lock is configured with timeout."""
    system = platform.system()
    if system == "Windows":
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').InactivityTimeoutSecs"],
                capture_output=True, text=True, timeout=10)
            timeout = int(result.stdout.strip()) if result.stdout.strip() else 0
            return {"configured": timeout > 0, "timeout_seconds": timeout}
        except (FileNotFoundError, ValueError):
            pass
    return {"configured": False, "timeout_seconds": 0}


def compute_posture_score(checks: dict) -> dict:
    """Compute device posture compliance score."""
    weights = {"disk_encryption": 25, "firewall": 20, "antivirus": 25,
               "screen_lock": 15, "os_supported": 15}
    score = 0
    if checks.get("disk_encryption", {}).get("enabled"):
        score += weights["disk_encryption"]
    if checks.get("firewall", {}).get("enabled"):
        score += weights["firewall"]
    if checks.get("antivirus", {}).get("enabled"):
        score += weights["antivirus"]
    if checks.get("screen_lock", {}).get("configured"):
        score += weights["screen_lock"]
    score += weights["os_supported"]
    if score >= 80:
        compliance = "COMPLIANT"
    elif score >= 50:
        compliance = "PARTIAL"
    else:
        compliance = "NON_COMPLIANT"
    return {"score": score, "max_score": 100, "compliance": compliance}


def generate_report() -> dict:
    """Generate device posture assessment report."""
    checks = {
        "os_info": check_os_version(),
        "disk_encryption": check_disk_encryption(),
        "firewall": check_firewall_status(),
        "antivirus": check_antivirus(),
        "screen_lock": check_screen_lock(),
    }
    posture = compute_posture_score(checks)
    recommendations = []
    if not checks["disk_encryption"].get("enabled"):
        recommendations.append("Enable disk encryption (BitLocker/FileVault/LUKS)")
    if not checks["firewall"].get("enabled"):
        recommendations.append("Enable host firewall")
    if not checks["antivirus"].get("enabled"):
        recommendations.append("Enable antivirus/EDR with real-time protection")
    return {
        "analysis_date": datetime.utcnow().isoformat(),
        "hostname": platform.node(),
        "checks": checks,
        "posture": posture,
        "recommendations": recommendations,
    }


def main():
    parser = argparse.ArgumentParser(description="Device Posture Assessment Agent")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--output", default="device_posture_report.json")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    report = generate_report()
    out_path = os.path.join(args.output_dir, args.output)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", out_path)
    print(json.dumps(report["posture"], indent=2))


if __name__ == "__main__":
    main()
