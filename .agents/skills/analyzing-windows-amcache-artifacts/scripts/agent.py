#!/usr/bin/env python3
"""Windows Amcache.hve forensic analysis agent.

Parses Amcache.hve registry hive to extract program execution history,
file metadata, and device information using the regipy library.
"""

import argparse
import json
import os
import sys
import datetime
import struct

try:
    from regipy.registry import RegistryHive
    HAS_REGIPY = True
except ImportError:
    HAS_REGIPY = False


AMCACHE_FILE_KEY = "Root\InventoryApplicationFile"
AMCACHE_APP_KEY = "Root\InventoryApplication"
AMCACHE_DEVICE_KEY = "Root\InventoryDevicePnp"
AMCACHE_DRIVER_KEY = "Root\InventoryDriverBinary"

SUSPICIOUS_PATHS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp",
    "\\downloads\\", "\\public\\", "\\programdata\\",
    "\\recycle", "\\users\\public",
]

SUSPICIOUS_NAMES = [
    "mimikatz", "psexec", "lazagne", "procdump", "rubeus",
    "sharphound", "bloodhound", "cobalt", "beacon",
    "powershell_ise", "certutil", "mshta",
]


def parse_amcache_files(hive_path):
    """Parse InventoryApplicationFile entries from Amcache.hve."""
    if not HAS_REGIPY:
        return {"error": "regipy not installed. pip install regipy"}
    try:
        reg = RegistryHive(hive_path)
        entries = []
        for subkey in reg.get_key(AMCACHE_FILE_KEY).iter_subkeys():
            values = {v.name: v.value for v in subkey.iter_values()}
            entries.append({
                "name": values.get("Name", ""),
                "lower_case_path": values.get("LowerCaseLongPath", ""),
                "publisher": values.get("Publisher", ""),
                "version": values.get("Version", ""),
                "sha1": values.get("FileId", "").lstrip("0000").lower() if values.get("FileId") else "",
                "size": values.get("Size", 0),
                "link_date": values.get("LinkDate", ""),
                "program_id": values.get("ProgramId", ""),
                "last_modified": subkey.header.last_modified.isoformat() if subkey.header.last_modified else "",
            })
        return entries
    except Exception as e:
        return {"error": str(e)}


def parse_amcache_apps(hive_path):
    """Parse InventoryApplication entries."""
    if not HAS_REGIPY:
        return {"error": "regipy not installed"}
    try:
        reg = RegistryHive(hive_path)
        apps = []
        for subkey in reg.get_key(AMCACHE_APP_KEY).iter_subkeys():
            values = {v.name: v.value for v in subkey.iter_values()}
            apps.append({
                "name": values.get("Name", ""),
                "version": values.get("Version", ""),
                "publisher": values.get("Publisher", ""),
                "install_date": values.get("InstallDate", ""),
                "source": values.get("Source", ""),
                "uninstall_string": values.get("UninstallString", ""),
                "registry_key_path": values.get("RegistryKeyPath", ""),
            })
        return apps
    except Exception as e:
        return {"error": str(e)}


def detect_suspicious(entries):
    """Flag suspicious entries based on path and name patterns."""
    findings = []
    for entry in entries:
        if isinstance(entry, dict) and "error" not in entry:
            path = entry.get("lower_case_path", "").lower()
            name = entry.get("name", "").lower()
            reasons = []
            for sp in SUSPICIOUS_PATHS:
                if sp in path:
                    reasons.append(f"Suspicious path: {sp}")
            for sn in SUSPICIOUS_NAMES:
                if sn in name:
                    reasons.append(f"Suspicious name: {sn}")
            if not entry.get("publisher"):
                reasons.append("Missing publisher metadata")
            if reasons:
                findings.append({
                    "name": entry.get("name", ""),
                    "path": entry.get("lower_case_path", ""),
                    "sha1": entry.get("sha1", ""),
                    "reasons": reasons,
                })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Amcache.hve forensic analysis agent")
    parser.add_argument("hive", nargs="?", help="Path to Amcache.hve file")
    parser.add_argument("--apps", action="store_true", help="Parse InventoryApplication entries")
    parser.add_argument("--suspicious-only", action="store_true", help="Show only suspicious entries")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    args = parser.parse_args()

    print("[*] Amcache.hve Forensic Analysis Agent")
    print(f"    regipy available: {HAS_REGIPY}")

    if not args.hive:
        print("\n[DEMO] Amcache.hve location: C:\\Windows\\AppCompat\\Programs\\Amcache.hve")
        print("  Usage: python agent.py Amcache.hve [--apps] [--suspicious-only]")
        print("  Extracts: file paths, SHA-1 hashes, publisher, timestamps, install info")
        print(json.dumps({"demo": True, "regipy_available": HAS_REGIPY}, indent=2))
        sys.exit(0)

    report = {"timestamp": datetime.datetime.utcnow().isoformat() + "Z", "hive": args.hive}

    files = parse_amcache_files(args.hive)
    if isinstance(files, list):
        report["file_entries"] = len(files)
        suspicious = detect_suspicious(files)
        report["suspicious_count"] = len(suspicious)
        if args.suspicious_only:
            report["findings"] = suspicious
        else:
            report["entries"] = files[:100]
            report["suspicious"] = suspicious
        print(f"[*] File entries: {len(files)}")
        print(f"[*] Suspicious: {len(suspicious)}")
        for s in suspicious[:10]:
            print(f"    [!] {s['name']}: {', '.join(s['reasons'])}")
    else:
        report["error"] = files

    if args.apps:
        apps = parse_amcache_apps(args.hive)
        if isinstance(apps, list):
            report["app_entries"] = len(apps)
            print(f"[*] Application entries: {len(apps)}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)

    print(json.dumps({"file_entries": report.get("file_entries", 0),
                       "suspicious": report.get("suspicious_count", 0)}, indent=2))


if __name__ == "__main__":
    main()
