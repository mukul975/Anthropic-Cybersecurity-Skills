#!/usr/bin/env python3
"""Agent for analyzing USB device connection history from Windows registry hives."""

import os
import json
import argparse
import csv
from datetime import datetime

from regipy.registry import RegistryHive


def parse_usbstor(system_hive_path):
    """Parse USBSTOR registry key to enumerate USB storage devices."""
    reg = RegistryHive(system_hive_path)
    select_key = reg.get_key("Select")
    current = select_key.get_value("Current")
    controlset = f"ControlSet{current:03d}"
    usbstor_path = f"{controlset}\\Enum\\USBSTOR"
    devices = []
    try:
        usbstor_key = reg.get_key(usbstor_path)
    except Exception:
        return devices
    for device_class in usbstor_key.iter_subkeys():
        parts = device_class.name.split("&")
        vendor = parts[1].replace("Ven_", "") if len(parts) > 1 else "Unknown"
        product = parts[2].replace("Prod_", "") if len(parts) > 2 else "Unknown"
        revision = parts[3].replace("Rev_", "") if len(parts) > 3 else "Unknown"
        for instance in device_class.iter_subkeys():
            serial = instance.name
            device_info = {
                "vendor": vendor,
                "product": product,
                "revision": revision,
                "serial": serial,
                "last_connected": str(instance.header.last_modified),
            }
            for val in instance.iter_values():
                if val.name == "FriendlyName":
                    device_info["friendly_name"] = val.value
            devices.append(device_info)
    return devices


def parse_mounted_devices(system_hive_path):
    """Parse MountedDevices to map drive letters to USB devices."""
    import struct
    reg = RegistryHive(system_hive_path)
    mounted_key = reg.get_key("MountedDevices")
    mappings = []
    for val in mounted_key.iter_values():
        if val.name.startswith("\\DosDevices\\"):
            drive_letter = val.name.replace("\\DosDevices\\", "")
            data = val.value
            if isinstance(data, bytes) and len(data) > 24:
                try:
                    device_path = data.decode("utf-16-le").strip("\x00")
                    if "USBSTOR" in device_path or "USB#" in device_path:
                        mappings.append({
                            "drive_letter": drive_letter,
                            "device_path": device_path,
                        })
                except (UnicodeDecodeError, ValueError):
                    pass
    return mappings


def parse_mountpoints2(ntuser_path):
    """Parse MountPoints2 from NTUSER.DAT to find user-accessed volumes."""
    reg = RegistryHive(ntuser_path)
    mp2_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2"
    mount_points = []
    try:
        mp2_key = reg.get_key(mp2_path)
    except Exception:
        return mount_points
    for subkey in mp2_key.iter_subkeys():
        if "{" in subkey.name:
            mount_points.append({
                "volume_guid": subkey.name,
                "last_accessed": str(subkey.header.last_modified),
            })
    return mount_points


def parse_setupapi_log(log_path):
    """Parse setupapi.dev.log for USB first-install timestamps."""
    import re
    installs = []
    with open(log_path, "r", errors="ignore") as f:
        content = f.read()
    pattern = r">>>\s+\[Device Install.*?\n.*?Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*?\n(.*?)<<<"
    for match in re.finditer(pattern, content, re.DOTALL):
        timestamp, section = match.group(1), match.group(2)
        dev_match = re.search(r"(USBSTOR\\[^\s]+|USB\\VID_\w+&PID_\w+[^\s]*)", section)
        if dev_match:
            installs.append({
                "first_install": timestamp,
                "device_id": dev_match.group(1),
            })
    return installs


def build_timeline(devices, mappings, mount_points):
    """Build a unified USB activity timeline."""
    timeline = []
    for dev in devices:
        timeline.append({
            "timestamp": dev["last_connected"],
            "source": "USBSTOR",
            "device": f"{dev['vendor']} {dev['product']}",
            "serial": dev["serial"],
            "event": "Last Connected",
            "detail": dev.get("friendly_name", ""),
        })
    for mp in mount_points:
        timeline.append({
            "timestamp": mp["last_accessed"],
            "source": "MountPoints2",
            "device": mp["volume_guid"],
            "serial": "",
            "event": "Volume Accessed",
            "detail": "",
        })
    timeline.sort(key=lambda x: x["timestamp"])
    return timeline


def export_timeline_csv(timeline, output_path):
    """Export timeline to CSV."""
    if not timeline:
        return
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=timeline[0].keys())
        writer.writeheader()
        writer.writerows(timeline)


def main():
    parser = argparse.ArgumentParser(description="USB Device Connection History Agent")
    parser.add_argument("--system-hive", required=True, help="Path to SYSTEM registry hive")
    parser.add_argument("--ntuser", help="Path to NTUSER.DAT hive")
    parser.add_argument("--setupapi-log", help="Path to setupapi.dev.log")
    parser.add_argument("--output-dir", default="./usb_analysis")
    parser.add_argument("--case-id", default="CASE-001")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    devices = parse_usbstor(args.system_hive)
    print(f"[+] USBSTOR devices: {len(devices)}")
    for d in devices:
        print(f"    {d['vendor']} {d['product']} | Serial: {d['serial']}")

    mappings = parse_mounted_devices(args.system_hive)
    print(f"[+] USB drive mappings: {len(mappings)}")

    mount_points = []
    if args.ntuser:
        mount_points = parse_mountpoints2(args.ntuser)
        print(f"[+] MountPoints2 entries: {len(mount_points)}")

    if args.setupapi_log:
        installs = parse_setupapi_log(args.setupapi_log)
        print(f"[+] SetupAPI installations: {len(installs)}")

    timeline = build_timeline(devices, mappings, mount_points)
    csv_path = os.path.join(args.output_dir, "usb_timeline.csv")
    export_timeline_csv(timeline, csv_path)
    print(f"[+] Timeline exported to {csv_path} ({len(timeline)} events)")

    report = {
        "case_id": args.case_id,
        "total_devices": len(devices),
        "devices": devices,
        "drive_mappings": mappings,
        "timeline_events": len(timeline),
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
