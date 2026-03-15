#!/usr/bin/env python3
"""Agent for analyzing Windows Registry hives for forensic artifacts."""

import os
import json
import codecs
import struct
import argparse
from datetime import datetime, timedelta

from regipy.registry import RegistryHive


def extract_autorun_entries(software_hive_path):
    """Extract Run/RunOnce autostart entries from SOFTWARE hive."""
    reg = RegistryHive(software_hive_path)
    autorun_paths = [
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Microsoft\\Windows\\CurrentVersion\\RunServices",
        "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    ]
    entries = []
    for path in autorun_paths:
        try:
            key = reg.get_key(path)
            for val in key.iter_values():
                entries.append({
                    "path": path,
                    "name": val.name,
                    "value": str(val.value),
                    "last_modified": str(key.header.last_modified),
                })
        except Exception:
            pass
    return entries


def extract_user_autorun(ntuser_path):
    """Extract per-user autorun entries from NTUSER.DAT."""
    reg = RegistryHive(ntuser_path)
    paths = [
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ]
    entries = []
    for path in paths:
        try:
            key = reg.get_key(path)
            for val in key.iter_values():
                entries.append({
                    "path": path,
                    "name": val.name,
                    "value": str(val.value),
                    "last_modified": str(key.header.last_modified),
                })
        except Exception:
            pass
    return entries


def extract_userassist(ntuser_path):
    """Extract UserAssist program execution history (ROT13 decoded)."""
    reg = RegistryHive(ntuser_path)
    ua_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
    programs = []
    try:
        ua_key = reg.get_key(ua_path)
    except Exception:
        return programs
    for guid_key in ua_key.iter_subkeys():
        try:
            count_key = guid_key.get_subkey("Count")
        except Exception:
            continue
        for val in count_key.iter_values():
            decoded_name = codecs.decode(val.name, "rot_13")
            data = val.value
            if isinstance(data, bytes) and len(data) >= 16:
                run_count = struct.unpack_from("<I", data, 4)[0]
                timestamp = 0
                if len(data) >= 68:
                    timestamp = struct.unpack_from("<Q", data, 60)[0]
                last_run = ""
                if timestamp > 0:
                    ts = datetime(1601, 1, 1) + timedelta(microseconds=timestamp // 10)
                    last_run = ts.strftime("%Y-%m-%d %H:%M:%S")
                programs.append({
                    "program": decoded_name,
                    "run_count": run_count,
                    "last_run": last_run,
                })
    return programs


def extract_recent_docs(ntuser_path):
    """Extract RecentDocs MRU from NTUSER.DAT."""
    reg = RegistryHive(ntuser_path)
    path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
    docs = []
    try:
        key = reg.get_key(path)
        for val in key.iter_values():
            if val.name != "MRUListEx" and isinstance(val.value, bytes):
                try:
                    name = val.value.split(b"\x00\x00")[0].decode("utf-16-le", errors="ignore")
                    docs.append({"index": val.name, "filename": name})
                except Exception:
                    pass
    except Exception:
        pass
    return docs


def extract_system_info(system_hive_path):
    """Extract computer name, timezone, and shutdown time from SYSTEM hive."""
    reg = RegistryHive(system_hive_path)
    info = {}
    select_key = reg.get_key("Select")
    current = select_key.get_value("Current")
    cs = f"ControlSet{current:03d}"
    try:
        cn_key = reg.get_key(f"{cs}\\Control\\ComputerName\\ComputerName")
        info["computer_name"] = cn_key.get_value("ComputerName")
    except Exception:
        pass
    try:
        tz_key = reg.get_key(f"{cs}\\Control\\TimeZoneInformation")
        info["timezone"] = tz_key.get_value("TimeZoneKeyName")
    except Exception:
        pass
    return info


def extract_installed_software(software_hive_path):
    """Extract installed software from Uninstall registry key."""
    reg = RegistryHive(software_hive_path)
    path = "Microsoft\\Windows\\CurrentVersion\\Uninstall"
    software = []
    try:
        key = reg.get_key(path)
        for subkey in key.iter_subkeys():
            entry = {"key": subkey.name}
            for val in subkey.iter_values():
                if val.name in ("DisplayName", "DisplayVersion", "Publisher", "InstallDate"):
                    entry[val.name] = str(val.value)
            if "DisplayName" in entry:
                software.append(entry)
    except Exception:
        pass
    return software


def flag_suspicious_autorun(entries):
    """Flag autorun entries with suspicious characteristics."""
    suspicious = []
    suspect_paths = ["\\temp\\", "\\appdata\\", "\\programdata\\", "\\public\\", "powershell", "cmd"]
    for entry in entries:
        val_lower = entry.get("value", "").lower()
        if any(s in val_lower for s in suspect_paths):
            entry["suspicious"] = True
            entry["reason"] = "Path contains suspicious directory"
            suspicious.append(entry)
    return suspicious


def main():
    parser = argparse.ArgumentParser(description="Windows Registry Forensic Analysis Agent")
    parser.add_argument("--system-hive", help="Path to SYSTEM hive")
    parser.add_argument("--software-hive", help="Path to SOFTWARE hive")
    parser.add_argument("--ntuser", help="Path to NTUSER.DAT hive")
    parser.add_argument("--output-dir", default="./registry_analysis")
    parser.add_argument("--action", choices=[
        "autorun", "userassist", "recent_docs", "system_info",
        "installed_software", "full_analysis"
    ], default="full_analysis")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    report = {"generated_at": datetime.utcnow().isoformat()}

    if args.system_hive and args.action in ("system_info", "full_analysis"):
        report["system_info"] = extract_system_info(args.system_hive)
        print(f"[+] System: {report['system_info']}")

    if args.software_hive and args.action in ("autorun", "full_analysis"):
        autorun = extract_autorun_entries(args.software_hive)
        suspicious = flag_suspicious_autorun(autorun)
        report["autorun_software"] = autorun
        report["suspicious_autorun"] = suspicious
        print(f"[+] Autorun entries (SOFTWARE): {len(autorun)}, suspicious: {len(suspicious)}")

    if args.ntuser and args.action in ("autorun", "full_analysis"):
        user_autorun = extract_user_autorun(args.ntuser)
        report["autorun_user"] = user_autorun
        print(f"[+] Autorun entries (NTUSER): {len(user_autorun)}")

    if args.ntuser and args.action in ("userassist", "full_analysis"):
        ua = extract_userassist(args.ntuser)
        report["userassist"] = ua
        print(f"[+] UserAssist programs: {len(ua)}")

    if args.ntuser and args.action in ("recent_docs", "full_analysis"):
        docs = extract_recent_docs(args.ntuser)
        report["recent_docs"] = docs
        print(f"[+] Recent documents: {len(docs)}")

    if args.software_hive and args.action in ("installed_software", "full_analysis"):
        sw = extract_installed_software(args.software_hive)
        report["installed_software"] = sw
        print(f"[+] Installed software: {len(sw)}")

    output_path = os.path.join(args.output_dir, "registry_report.json")
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {output_path}")


if __name__ == "__main__":
    main()
