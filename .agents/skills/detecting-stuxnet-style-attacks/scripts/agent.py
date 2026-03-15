#!/usr/bin/env python3
"""Agent for detecting Stuxnet-style ICS/SCADA attacks targeting PLCs."""

import argparse
import json
import os
import re
import struct
import subprocess
import sys
from datetime import datetime, timezone


STUXNET_IOCS = {
    "file_hashes": [
        "b4b290906e3a8f1eabbb2b2864e6e7f7",
        "e757c7e29297b7b7a090695e2de82b4b",
    ],
    "registry_keys": [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MS-DOS Emulation",
        r"HKLM\SYSTEM\CurrentControlSet\Services\MRxCls",
        r"HKLM\SYSTEM\CurrentControlSet\Services\MRxNet",
    ],
    "mutex_names": [
        "Global\\{A3BD0EA3-CD10-4258-8784-2F53E56E2010}",
    ],
    "driver_files": [
        "mrxcls.sys", "mrxnet.sys",
    ],
}

MODBUS_FUNCTION_CODES = {
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
}


def check_plc_communication(pcap_path):
    """Analyze PCAP for suspicious Modbus/S7 PLC communication."""
    findings = []
    try:
        result = subprocess.check_output(
            ["tshark", "-r", pcap_path, "-Y", "modbus || s7comm",
             "-T", "fields", "-e", "ip.src", "-e", "ip.dst",
             "-e", "modbus.func_code", "-e", "s7comm.param.func",
             "-e", "frame.time"],
            text=True, errors="replace", timeout=60
        )
        write_count = 0
        for line in result.strip().splitlines():
            fields = line.split("\t")
            if len(fields) >= 3:
                func_code = fields[2] if fields[2] else None
                if func_code:
                    try:
                        fc = int(func_code)
                        if fc in MODBUS_FUNCTION_CODES:
                            write_count += 1
                            if write_count <= 20:
                                findings.append({
                                    "src": fields[0], "dst": fields[1],
                                    "function": MODBUS_FUNCTION_CODES[fc],
                                    "func_code": fc,
                                })
                    except ValueError:
                        pass
        if write_count > 100:
            findings.append({
                "alert": f"Excessive PLC write operations: {write_count}",
                "severity": "CRITICAL",
            })
    except (subprocess.SubprocessError, FileNotFoundError):
        findings.append({"error": "tshark not available or PCAP parse failed"})
    return findings


def scan_for_rootkit_drivers():
    """Check for Stuxnet-style rootkit driver files."""
    findings = []
    search_dirs = [r"C:\Windows\System32\drivers", r"C:\Windows\inf"]
    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        for fname in os.listdir(d):
            if fname.lower() in [df.lower() for df in STUXNET_IOCS["driver_files"]]:
                findings.append({
                    "type": "rootkit_driver",
                    "path": os.path.join(d, fname),
                    "severity": "CRITICAL",
                })
    return findings


def check_registry_indicators():
    """Check Windows registry for Stuxnet IOCs."""
    findings = []
    if sys.platform != "win32":
        return findings
    for key in STUXNET_IOCS["registry_keys"]:
        try:
            result = subprocess.check_output(
                ["reg", "query", key], text=True, errors="replace", timeout=5
            )
            if result.strip():
                findings.append({
                    "type": "registry_ioc",
                    "key": key,
                    "severity": "CRITICAL",
                })
        except subprocess.SubprocessError:
            pass
    return findings


def analyze_step7_project(project_dir):
    """Check Step 7 project files for unauthorized OB modifications."""
    findings = []
    if not os.path.isdir(project_dir):
        return findings
    for root, _, files in os.walk(project_dir):
        for f in files:
            fpath = os.path.join(root, f)
            if f.lower().startswith("ob") and f.lower().endswith((".awl", ".mc7")):
                stat = os.stat(fpath)
                findings.append({
                    "file": fpath,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    "note": "Organization Block file — verify integrity",
                })
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Detect Stuxnet-style ICS/SCADA attacks"
    )
    parser.add_argument("--pcap", help="PCAP file with ICS network traffic")
    parser.add_argument("--step7-project", help="Siemens Step 7 project directory")
    parser.add_argument("--check-host", action="store_true", help="Check host for IOCs")
    parser.add_argument("--output", "-o", help="Output JSON report")
    args = parser.parse_args()

    print("[*] Stuxnet-Style ICS Attack Detection Agent")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "findings": {}}

    if args.pcap:
        plc = check_plc_communication(args.pcap)
        report["findings"]["plc_traffic"] = plc
        print(f"[*] PLC traffic findings: {len(plc)}")

    if args.check_host:
        drivers = scan_for_rootkit_drivers()
        registry = check_registry_indicators()
        report["findings"]["rootkit_drivers"] = drivers
        report["findings"]["registry_iocs"] = registry
        print(f"[*] Driver IOCs: {len(drivers)}, Registry IOCs: {len(registry)}")

    if args.step7_project:
        s7 = analyze_step7_project(args.step7_project)
        report["findings"]["step7_files"] = s7
        print(f"[*] Step 7 files to verify: {len(s7)}")

    total = sum(len(v) if isinstance(v, list) else 0 for v in report["findings"].values())
    report["risk_level"] = "CRITICAL" if total >= 3 else "HIGH" if total >= 1 else "LOW"

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
