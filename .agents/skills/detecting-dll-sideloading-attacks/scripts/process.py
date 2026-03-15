#!/usr/bin/env python3
"""
DLL Sideloading Detection Script
Analyzes DLL load events for sideloading indicators including unsigned DLLs,
path anomalies, and known vulnerable application abuse.
"""

import json
import csv
import argparse
import datetime
import re
from collections import defaultdict
from pathlib import Path

KNOWN_SIDELOAD_TARGETS = {
    "version.dll": ["OneDriveUpdater.exe", "Grammarly.exe"],
    "cryptsp.dll": ["Teams.exe"],
    "dismcore.dll": ["DismHost.exe"],
    "mpclient.dll": ["MpCmdRun.exe"],
    "dbgcore.dll": ["WerFault.exe"],
    "wbemcomn.dll": ["mmc.exe"],
    "comsvcs.dll": ["rundll32.exe"],
    "uxtheme.dll": ["Multiple"],
    "dwmapi.dll": ["Multiple"],
    "winmm.dll": ["Multiple"],
    "dxgi.dll": ["Multiple"],
}

LEGITIMATE_DLL_PATHS = [
    r"C:\\Windows\\System32\\",
    r"C:\\Windows\\SysWOW64\\",
    r"C:\\Windows\\WinSxS\\",
    r"C:\\Program Files\\",
    r"C:\\Program Files \(x86\)\\",
]

SUSPICIOUS_DLL_PATHS = [
    r"\\Temp\\", r"\\tmp\\", r"\\AppData\\Local\\Temp\\",
    r"\\Users\\Public\\", r"\\Downloads\\", r"\\Desktop\\",
    r"\\ProgramData\\(?!Microsoft)",
]


def parse_logs(input_path: str) -> list[dict]:
    path = Path(input_path)
    if path.suffix == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else data.get("events", [])
    elif path.suffix == ".csv":
        with open(path, "r", encoding="utf-8-sig") as f:
            return [dict(row) for row in csv.DictReader(f)]
    return []


def normalize_event(event: dict) -> dict:
    field_map = {
        "event_id": ["EventCode", "EventID"],
        "image": ["Image", "InitiatingProcessFileName"],
        "dll_loaded": ["ImageLoaded", "FileName", "FolderPath"],
        "signed": ["Signed", "IsSigned"],
        "signature": ["Signature", "SignatureType"],
        "hashes": ["Hashes", "SHA256"],
        "hostname": ["Computer", "DeviceName"],
        "user": ["User", "AccountName"],
        "timestamp": ["UtcTime", "Timestamp"],
    }
    normalized = {}
    for target, sources in field_map.items():
        for src in sources:
            if src in event and event[src]:
                normalized[target] = str(event[src])
                break
        if target not in normalized:
            normalized[target] = ""
    return normalized


def detect_sideloading(event: dict) -> dict | None:
    if event.get("event_id") != "7":
        return None

    dll_path = event.get("dll_loaded", "").lower()
    image_path = event.get("image", "").lower()
    signed = event.get("signed", "").lower()
    dll_name = dll_path.split("\\")[-1] if dll_path else ""
    app_name = image_path.split("\\")[-1] if image_path else ""

    risk = 0
    indicators = []

    # Check if DLL is a known sideloading target
    if dll_name in KNOWN_SIDELOAD_TARGETS:
        # Check if loaded from non-standard path
        is_legit_path = any(re.search(p, dll_path, re.IGNORECASE) for p in LEGITIMATE_DLL_PATHS)
        if not is_legit_path:
            risk += 40
            indicators.append(f"Known sideload target DLL: {dll_name}")

    # Check for unsigned DLL
    if signed in ("false", "0", ""):
        risk += 20
        indicators.append("Unsigned DLL loaded")

    # Check for suspicious DLL path
    for pattern in SUSPICIOUS_DLL_PATHS:
        if re.search(pattern, dll_path, re.IGNORECASE):
            risk += 25
            indicators.append(f"DLL in suspicious path: {pattern}")
            break

    # Check for app running from unusual location
    app_in_standard = any(re.search(p, image_path, re.IGNORECASE) for p in LEGITIMATE_DLL_PATHS)
    if not app_in_standard and app_name:
        for pattern in SUSPICIOUS_DLL_PATHS:
            if re.search(pattern, image_path, re.IGNORECASE):
                risk += 20
                indicators.append(f"Host application in suspicious path")
                break

    if not indicators:
        return None

    risk_level = "CRITICAL" if risk >= 70 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 30 else "LOW"

    return {
        "detection_type": "DLL_SIDELOADING",
        "technique": "T1574.002",
        "host_application": image_path,
        "sideloaded_dll": dll_path,
        "dll_name": dll_name,
        "signed": signed,
        "hostname": event.get("hostname", "unknown"),
        "user": event.get("user", "unknown"),
        "timestamp": event.get("timestamp", "unknown"),
        "risk_score": risk,
        "risk_level": risk_level,
        "indicators": indicators,
    }


def run_hunt(input_path: str, output_dir: str) -> None:
    print(f"[*] DLL Sideloading Hunt - {datetime.datetime.now().isoformat()}")
    events = [normalize_event(e) for e in parse_logs(input_path)]
    print(f"[*] Loaded {len(events)} events")

    findings = [f for f in (detect_sideloading(e) for e in events) if f]

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    with open(output_path / "sideload_findings.json", "w", encoding="utf-8") as f:
        json.dump({
            "hunt_id": f"TH-SIDELOAD-{datetime.date.today().isoformat()}",
            "total_events": len(events),
            "findings": sorted(findings, key=lambda x: x["risk_score"], reverse=True),
        }, f, indent=2)

    print(f"[+] {len(findings)} findings written to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="DLL Sideloading Detection")
    subparsers = parser.add_subparsers(dest="command")
    hunt_p = subparsers.add_parser("hunt")
    hunt_p.add_argument("--input", "-i", required=True)
    hunt_p.add_argument("--output", "-o", default="./sideload_output")
    subparsers.add_parser("queries")
    args = parser.parse_args()
    if args.command == "hunt":
        run_hunt(args.input, args.output)
    elif args.command == "queries":
        print("=== Sysmon DLL Load Queries ===")
        print('index=sysmon EventCode=7 Signed=false\n| stats count by Image ImageLoaded Computer\n| sort -count')
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
