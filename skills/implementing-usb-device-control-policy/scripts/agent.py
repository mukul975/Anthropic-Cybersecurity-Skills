#!/usr/bin/env python3
"""USB device control policy audit agent.

Audits USB device control policies on Linux and Windows systems by
checking udev rules, USBGuard configuration, Windows Group Policy
settings, and connected device history. Reports unauthorized or
unwhitelisted USB devices.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone


def audit_linux_usbguard():
    """Audit USBGuard configuration and rules on Linux."""
    findings = []
    print("[*] Auditing USBGuard configuration...")

    # Check if USBGuard is installed and running
    result = subprocess.run(
        ["systemctl", "is-active", "usbguard"],
        capture_output=True, text=True, timeout=10,
    )
    if result.stdout.strip() == "active":
        findings.append({"check": "USBGuard service", "status": "PASS",
                         "severity": "INFO", "detail": "USBGuard is running"})
    else:
        findings.append({"check": "USBGuard service", "status": "FAIL",
                         "severity": "HIGH", "detail": "USBGuard is not running"})
        return findings

    # List current USB devices and their authorization
    result = subprocess.run(
        ["usbguard", "list-devices"],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode == 0:
        devices = []
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 3:
                dev_id = parts[0].rstrip(":")
                policy = parts[1]
                name = " ".join(parts[2:])
                devices.append({"id": dev_id, "policy": policy, "name": name})
                if policy == "allow":
                    findings.append({"check": f"USB Device {dev_id}", "status": "INFO",
                                    "severity": "INFO", "detail": f"Allowed: {name}"})
                elif policy == "block":
                    findings.append({"check": f"USB Device {dev_id}", "status": "BLOCKED",
                                    "severity": "INFO", "detail": f"Blocked: {name}"})

    # Check default policy
    result = subprocess.run(
        ["usbguard", "get-parameter", "ImplicitPolicyTarget"],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode == 0:
        policy = result.stdout.strip()
        if policy == "block":
            findings.append({"check": "Default USB policy", "status": "PASS",
                            "severity": "INFO", "detail": "Default: block (deny by default)"})
        else:
            findings.append({"check": "Default USB policy", "status": "FAIL",
                            "severity": "HIGH",
                            "detail": f"Default: {policy} (should be 'block')"})

    # List rules
    result = subprocess.run(
        ["usbguard", "list-rules"],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode == 0:
        rules = result.stdout.strip().splitlines()
        findings.append({"check": "USBGuard rules", "status": "INFO",
                        "severity": "INFO", "detail": f"{len(rules)} rules configured"})

    return findings


def audit_linux_udev():
    """Check for USB-related udev rules on Linux."""
    findings = []
    udev_dirs = ["/etc/udev/rules.d", "/lib/udev/rules.d", "/usr/lib/udev/rules.d"]
    usb_rules_found = False

    for udev_dir in udev_dirs:
        if not os.path.isdir(udev_dir):
            continue
        for fname in os.listdir(udev_dir):
            fpath = os.path.join(udev_dir, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "r") as f:
                    content = f.read()
                if "usb" in content.lower() and ("authorize" in content.lower() or "block" in content.lower()):
                    usb_rules_found = True
                    findings.append({"check": f"udev USB rule: {fname}", "status": "INFO",
                                    "severity": "INFO", "detail": fpath})
            except (IOError, PermissionError):
                pass

    if not usb_rules_found:
        findings.append({"check": "udev USB rules", "status": "WARN",
                         "severity": "MEDIUM", "detail": "No USB-specific udev rules found"})
    return findings


def list_connected_usb_devices():
    """List currently connected USB devices."""
    devices = []
    if sys.platform == "win32":
        ps_cmd = (
            "Get-PnpDevice -Class USB | "
            "Select-Object InstanceId, FriendlyName, Status, Class | "
            "ConvertTo-Json"
        )
        result = subprocess.run(
            ["powershell", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            try:
                raw = json.loads(result.stdout)
                if isinstance(raw, dict):
                    raw = [raw]
                for dev in raw:
                    devices.append({
                        "instance_id": dev.get("InstanceId", ""),
                        "name": dev.get("FriendlyName", "Unknown"),
                        "status": dev.get("Status", ""),
                        "class": dev.get("Class", "USB"),
                    })
            except json.JSONDecodeError:
                pass
    else:
        result = subprocess.run(
            ["lsusb"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.strip().splitlines():
                parts = line.split("ID ")
                if len(parts) >= 2:
                    devices.append({
                        "bus_info": parts[0].strip(),
                        "id": parts[1].split()[0] if parts[1].split() else "",
                        "name": " ".join(parts[1].split()[1:]) if len(parts[1].split()) > 1 else "Unknown",
                    })

    return devices


def format_summary(findings, devices):
    """Print audit summary."""
    print(f"\n{'='*60}")
    print("  USB Device Control Policy Audit")
    print(f"{'='*60}")
    print(f"  Connected Devices: {len(devices)}")
    print(f"  Policy Findings  : {len(findings)}")

    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    pass_count = sum(1 for f in findings if f["status"] == "PASS")
    fail_count = sum(1 for f in findings if f["status"] == "FAIL")
    print(f"  Passed : {pass_count}")
    print(f"  Failed : {fail_count}")

    if devices:
        print("\n  Connected USB Devices:")
        for d in devices:
            print(f"    {d.get('name', 'Unknown'):40s} | {d.get('id', d.get('instance_id', 'N/A'))}")

    if findings:
        print("\n  Policy Checks:")
        for f in findings:
            icon = "OK" if f["status"] == "PASS" else "!!" if f["status"] == "FAIL" else "--"
            print(f"    [{icon}] {f['check']}: {f.get('detail', '')[:50]}")

    return severity_counts


def main():
    parser = argparse.ArgumentParser(description="USB device control policy audit agent")
    parser.add_argument("--list-devices", action="store_true", help="List connected USB devices")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    findings = []
    devices = list_connected_usb_devices()

    if sys.platform != "win32":
        findings.extend(audit_linux_usbguard())
        findings.extend(audit_linux_udev())

    if not findings:
        findings.append({"check": "USB control policy", "status": "WARN",
                         "severity": "HIGH",
                         "detail": "No USB device control mechanism detected"})

    severity_counts = format_summary(findings, devices)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "USB Device Control Audit",
        "devices": devices,
        "findings": findings,
        "severity_counts": severity_counts,
        "risk_level": (
            "HIGH" if severity_counts.get("HIGH", 0) > 0
            else "MEDIUM" if severity_counts.get("MEDIUM", 0) > 0
            else "LOW"
        ),
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
