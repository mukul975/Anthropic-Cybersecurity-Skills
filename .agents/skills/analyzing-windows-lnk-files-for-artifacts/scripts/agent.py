#!/usr/bin/env python3
"""Agent for analyzing Windows LNK shortcut files for forensic artifacts."""

import os
import json
import csv
import argparse
from datetime import datetime
from pathlib import Path

import LnkParse3


def parse_lnk_file(filepath):
    """Parse a single LNK file and extract forensic artifacts."""
    with open(filepath, "rb") as f:
        lnk = LnkParse3.lnk_file(f)
        info = lnk.get_json()

    parsed = {
        "lnk_file": os.path.basename(filepath),
        "target_path": "",
        "working_dir": "",
        "arguments": "",
        "target_created": "",
        "target_modified": "",
        "target_accessed": "",
        "file_size": "",
        "drive_type": "",
        "volume_serial": "",
        "volume_label": "",
        "machine_id": "",
        "mac_address": "",
    }

    header = info.get("header", {})
    parsed["target_created"] = str(header.get("creation_time", ""))
    parsed["target_modified"] = str(header.get("modified_time", ""))
    parsed["target_accessed"] = str(header.get("accessed_time", ""))
    parsed["file_size"] = str(header.get("file_size", ""))

    link_info = info.get("link_info", {})
    if link_info:
        local_path = link_info.get("local_base_path", "")
        net_link = link_info.get("common_network_relative_link", {})
        network_path = net_link.get("net_name", "") if net_link else ""
        parsed["target_path"] = local_path or network_path

        vol_info = link_info.get("volume_id", {})
        if vol_info:
            parsed["drive_type"] = str(vol_info.get("drive_type", ""))
            parsed["volume_serial"] = str(vol_info.get("drive_serial_number", ""))
            parsed["volume_label"] = str(vol_info.get("volume_label", ""))

    string_data = info.get("string_data", {})
    parsed["working_dir"] = str(string_data.get("working_dir", ""))
    parsed["arguments"] = str(string_data.get("command_line_arguments", ""))

    extra = info.get("extra", {})
    tracker = extra.get("DISTRIBUTED_LINK_TRACKER_BLOCK", {})
    if tracker:
        parsed["machine_id"] = str(tracker.get("machine_id", ""))
        parsed["mac_address"] = str(tracker.get("mac_address", ""))

    return parsed


def parse_lnk_directory(directory):
    """Parse all LNK files in a directory."""
    results = []
    for filename in sorted(os.listdir(directory)):
        if not filename.lower().endswith(".lnk"):
            continue
        filepath = os.path.join(directory, filename)
        try:
            parsed = parse_lnk_file(filepath)
            results.append(parsed)
        except Exception as e:
            print(f"  Error parsing {filename}: {e}")
    return results


def filter_removable_media(results):
    """Filter LNK files that point to removable media."""
    return [r for r in results if "removable" in r.get("drive_type", "").lower()]


def filter_network_shares(results):
    """Filter LNK files pointing to network shares."""
    return [
        r for r in results
        if "network" in r.get("drive_type", "").lower()
        or r.get("target_path", "").startswith("\\\\")
    ]


def detect_suspicious_startup(startup_dir):
    """Analyze Startup folder LNK files for potential persistence."""
    suspicious = []
    for filename in os.listdir(startup_dir):
        if not filename.lower().endswith(".lnk"):
            continue
        filepath = os.path.join(startup_dir, filename)
        try:
            parsed = parse_lnk_file(filepath)
            target = parsed["target_path"].lower()
            args = parsed["arguments"].lower()
            if any(s in target for s in ["temp", "appdata", "programdata", "public"]):
                parsed["risk"] = "HIGH"
                suspicious.append(parsed)
            elif any(s in args for s in ["-enc", "powershell", "cmd /c", "wscript"]):
                parsed["risk"] = "HIGH"
                suspicious.append(parsed)
        except Exception:
            pass
    return suspicious


def export_csv(results, output_path):
    """Export parsed LNK results to CSV."""
    if not results:
        return
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)


def extract_unique_machines(results):
    """Extract unique machine IDs and MAC addresses from LNK files."""
    machines = {}
    for r in results:
        mid = r.get("machine_id", "")
        mac = r.get("mac_address", "")
        if mid:
            machines[mid] = mac
    return machines


def main():
    parser = argparse.ArgumentParser(description="Windows LNK File Forensic Analysis Agent")
    parser.add_argument("--lnk-dir", required=True, help="Directory containing LNK files")
    parser.add_argument("--startup-dir", help="Startup folder to check for persistence")
    parser.add_argument("--output-dir", default="./lnk_analysis")
    parser.add_argument("--action", choices=[
        "parse_all", "removable", "network", "startup", "machines", "full_analysis"
    ], default="full_analysis")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    all_results = parse_lnk_directory(args.lnk_dir)
    print(f"[+] Parsed {len(all_results)} LNK files")

    if args.action in ("parse_all", "full_analysis"):
        csv_path = os.path.join(args.output_dir, "lnk_analysis.csv")
        export_csv(all_results, csv_path)
        print(f"[+] Exported to {csv_path}")

    if args.action in ("removable", "full_analysis"):
        removable = filter_removable_media(all_results)
        print(f"[+] Removable media files: {len(removable)}")
        for r in removable:
            print(f"    {r['target_modified']} | {r['target_path']} | Vol: {r['volume_serial']}")

    if args.action in ("network", "full_analysis"):
        network = filter_network_shares(all_results)
        print(f"[+] Network share files: {len(network)}")

    if args.action in ("startup", "full_analysis") and args.startup_dir:
        suspicious = detect_suspicious_startup(args.startup_dir)
        print(f"[+] Suspicious startup LNK: {len(suspicious)}")
        for s in suspicious:
            print(f"    [{s.get('risk')}] {s['lnk_file']} -> {s['target_path']}")

    if args.action in ("machines", "full_analysis"):
        machines = extract_unique_machines(all_results)
        print(f"[+] Unique machines: {len(machines)}")
        for mid, mac in machines.items():
            print(f"    Machine: {mid} | MAC: {mac}")

    print(json.dumps({"total_lnk": len(all_results), "generated_at": datetime.utcnow().isoformat()}, indent=2))


if __name__ == "__main__":
    main()
