#!/usr/bin/env python3
"""Windows LNK file and Jump List artifact analysis agent.

Parses Windows Shell Link (.lnk) files and Jump List artifacts to extract
file access evidence, program execution history, and user activity timelines.
Uses LnkParse3 for binary parsing and supports LECmd/JLECmd CSV output analysis.
"""

import struct
import os
import sys
import json
import hashlib
import datetime
import re
import glob as glob_mod

try:
    import LnkParse3
    HAS_LNKPARSE = True
except ImportError:
    HAS_LNKPARSE = False


def compute_hash(filepath):
    """Compute SHA-256 hash of file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def parse_lnk_with_lnkparse3(filepath):
    """Parse LNK file using LnkParse3 library."""
    if not HAS_LNKPARSE:
        return {"error": "LnkParse3 not installed. pip install LnkParse3"}
    with open(filepath, "rb") as f:
        lnk = LnkParse3.lnk_file(f)
    info = lnk.get_json()
    result = {
        "target_path": info.get("data", {}).get("relative_path", ""),
        "working_dir": info.get("data", {}).get("working_directory", ""),
        "arguments": info.get("data", {}).get("command_line_arguments", ""),
        "icon_location": info.get("data", {}).get("icon_location", ""),
        "description": info.get("data", {}).get("description", ""),
    }
    header = info.get("header", {})
    result["creation_time"] = header.get("creation_time", "")
    result["access_time"] = header.get("access_time", "")
    result["write_time"] = header.get("write_time", "")
    result["file_size"] = header.get("file_size", 0)
    result["file_flags"] = header.get("file_attributes", "")
    link_info = info.get("link_info", {})
    if link_info:
        result["local_base_path"] = link_info.get("local_base_path", "")
        result["volume_serial"] = link_info.get("volume_serial_number", "")
        result["volume_label"] = link_info.get("volume_label", "")
        result["drive_type"] = link_info.get("drive_type", "")
    extra = info.get("extra", {})
    if extra:
        tracker = extra.get("DISTRIBUTED_LINK_TRACKER_BLOCK", {})
        if tracker:
            result["machine_id"] = tracker.get("machine_id", "")
            result["mac_address"] = tracker.get("mac_address", "")
            result["droid_volume_id"] = tracker.get("droid_volume_identifier", "")
            result["droid_file_id"] = tracker.get("droid_file_identifier", "")
    return result


def parse_lnk_header_raw(filepath):
    """Parse LNK file header manually from raw bytes."""
    with open(filepath, "rb") as f:
        data = f.read()

    if len(data) < 76:
        return {"error": "File too small for LNK header"}

    # Shell Link Header (76 bytes)
    header_size = struct.unpack_from("<I", data, 0)[0]
    if header_size != 0x4C:
        return {"error": f"Invalid header size: {header_size:#x} (expected 0x4C)"}

    # CLSID check: 00021401-0000-0000-C000-000000000046
    clsid = data[4:20]
    expected_clsid = bytes.fromhex("01140200000000c0000000000000046".replace("0", "0"))

    link_flags = struct.unpack_from("<I", data, 20)[0]
    file_attrs = struct.unpack_from("<I", data, 24)[0]

    creation_time = filetime_to_datetime(struct.unpack_from("<Q", data, 28)[0])
    access_time = filetime_to_datetime(struct.unpack_from("<Q", data, 36)[0])
    write_time = filetime_to_datetime(struct.unpack_from("<Q", data, 44)[0])

    file_size = struct.unpack_from("<I", data, 52)[0]
    icon_index = struct.unpack_from("<I", data, 56)[0]
    show_command = struct.unpack_from("<I", data, 60)[0]

    result = {
        "header_size": header_size,
        "link_flags": f"0x{link_flags:08X}",
        "file_attributes": f"0x{file_attrs:08X}",
        "creation_time": creation_time,
        "access_time": access_time,
        "write_time": write_time,
        "target_file_size": file_size,
        "icon_index": icon_index,
        "show_command": {1: "Normal", 3: "Maximized", 7: "Minimized"}.get(show_command, str(show_command)),
        "flags_decoded": decode_link_flags(link_flags),
    }
    return result


def filetime_to_datetime(filetime):
    """Convert Windows FILETIME to ISO string."""
    if filetime == 0:
        return "N/A"
    try:
        epoch = datetime.datetime(1601, 1, 1)
        delta = datetime.timedelta(microseconds=filetime // 10)
        return (epoch + delta).isoformat() + "Z"
    except (OverflowError, OSError):
        return "Invalid"


def decode_link_flags(flags):
    """Decode Shell Link header flags."""
    flag_names = {
        0x00000001: "HasLinkTargetIDList",
        0x00000002: "HasLinkInfo",
        0x00000004: "HasName",
        0x00000008: "HasRelativePath",
        0x00000010: "HasWorkingDir",
        0x00000020: "HasArguments",
        0x00000040: "HasIconLocation",
        0x00000080: "IsUnicode",
        0x00000100: "ForceNoLinkInfo",
        0x00000800: "RunInSeparateProcess",
        0x00001000: "HasDarwinID",
        0x00002000: "RunAsUser",
        0x00004000: "HasExpIcon",
        0x00020000: "HasExpString",
        0x00040000: "RunInSeparateProcess",
        0x00080000: "PreferEnvironmentPath",
        0x00200000: "DisableLinkPathTracking",
        0x00800000: "EnableTargetMetadata",
        0x04000000: "AllowLinkToLink",
    }
    decoded = []
    for bit, name in flag_names.items():
        if flags & bit:
            decoded.append(name)
    return decoded


JUMP_LIST_APP_IDS = {
    "1b4dd67f29cb1962": "Windows Explorer",
    "5d696d521de238c3": "Google Chrome",
    "9b9cdc69c1c24e2b": "Notepad",
    "f01b4d95cf55d32a": "Windows Explorer",
    "a7bd71699cd38d1c": "Notepad++",
    "918e0ecb43d17e23": "Notepad (Win10)",
    "12dc1ea8e34b5a6": "Microsoft Paint",
    "b8ab77100df80ab2": "Microsoft Word 2019",
    "a4a5324453625195": "Microsoft Excel 2019",
    "bc0c37e84e063727": "Microsoft PowerPoint 2019",
    "9839aec31243a928": "Microsoft Outlook 2019",
    "fb3b0dbfee58fac8": "Acrobat Reader DC",
    "ecd21b58c2f65a4f": "Firefox",
    "1bc392b8e104a00e": "Remote Desktop (mstsc)",
    "b91050d8b077a4e8": "WinRAR",
    "290532160612e071": "Windows Media Player",
    "28c8b86deab549a1": "Internet Explorer",
    "7e4dca80246863e3": "Control Panel",
    "e2a593822e01aed3": "Snipping Tool",
    "b74736c2bd8cc8a5": "WinSCP",
    "cfb56c56fa0f0478": "PuTTY",
}


def scan_jump_lists(jump_list_dir):
    """Scan Jump List directory for automatic and custom destinations."""
    results = []
    auto_pattern = os.path.join(jump_list_dir, "*.automaticDestinations-ms")
    custom_pattern = os.path.join(jump_list_dir, "*.customDestinations-ms")

    for jl_file in sorted(glob_mod.glob(auto_pattern) + glob_mod.glob(custom_pattern)):
        basename = os.path.basename(jl_file)
        app_id = basename.split(".")[0]
        jl_type = "automatic" if "automatic" in basename else "custom"
        app_name = JUMP_LIST_APP_IDS.get(app_id, "Unknown Application")
        results.append({
            "file": basename,
            "app_id": app_id,
            "app_name": app_name,
            "type": jl_type,
            "size": os.path.getsize(jl_file),
            "modified": datetime.datetime.fromtimestamp(
                os.path.getmtime(jl_file)).isoformat(),
        })
    return results


def detect_suspicious_lnk(parsed_lnk):
    """Detect suspicious characteristics in LNK files."""
    findings = []
    args = parsed_lnk.get("arguments", "")
    target = parsed_lnk.get("target_path", "") + " " + parsed_lnk.get("local_base_path", "")

    suspicious_patterns = [
        (r"powershell", "PowerShell execution via LNK"),
        (r"cmd\.exe\s*/c", "Command prompt execution via LNK"),
        (r"mshta", "MSHTA execution (HTA payload)"),
        (r"certutil.*-decode", "CertUtil decode (file download)"),
        (r"bitsadmin.*transfer", "BitsAdmin file download"),
        (r"regsvr32.*scrobj", "Regsvr32 COM scriptlet execution"),
        (r"wscript|cscript", "Script host execution"),
        (r"\\\\[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\\", "UNC path to IP address"),
        (r"http[s]?://", "URL in LNK arguments"),
        (r"-enc\s+[A-Za-z0-9+/=]{20,}", "Base64-encoded PowerShell"),
    ]
    combined = f"{target} {args}".lower()
    for pattern, description in suspicious_patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            findings.append({"indicator": description, "pattern": pattern})

    if parsed_lnk.get("drive_type") == "DRIVE_REMOTE":
        findings.append({"indicator": "Target on network drive", "pattern": "DRIVE_REMOTE"})

    return findings


def scan_lnk_directory(directory):
    """Scan directory for LNK files and analyze each."""
    results = []
    for lnk_file in sorted(glob_mod.glob(os.path.join(directory, "*.lnk"))):
        parsed = parse_lnk_with_lnkparse3(lnk_file) if HAS_LNKPARSE else parse_lnk_header_raw(lnk_file)
        suspicious = detect_suspicious_lnk(parsed)
        results.append({
            "file": os.path.basename(lnk_file),
            "sha256": compute_hash(lnk_file),
            "parsed": parsed,
            "suspicious": suspicious,
        })
    return results


if __name__ == "__main__":
    print("=" * 60)
    print("Windows LNK & Jump List Forensics Agent")
    print("Shell Link parsing, Jump List analysis, suspicious detection")
    print("=" * 60)

    target = sys.argv[1] if len(sys.argv) > 1 else None

    if not target or not os.path.exists(target):
        print("\n[DEMO] Usage:")
        print("  python agent.py <file.lnk>         # Analyze single LNK")
        print("  python agent.py <directory>         # Scan directory for LNK/JumpList")
        print(f"\n  LnkParse3 available: {HAS_LNKPARSE}")
        sys.exit(0)

    if os.path.isfile(target) and target.lower().endswith(".lnk"):
        print(f"\n[*] Analyzing: {target}")
        print(f"[*] SHA-256: {compute_hash(target)}")
        if HAS_LNKPARSE:
            parsed = parse_lnk_with_lnkparse3(target)
        else:
            parsed = parse_lnk_header_raw(target)
        print("\n--- LNK Properties ---")
        for k, v in parsed.items():
            print(f"  {k}: {v}")
        suspicious = detect_suspicious_lnk(parsed)
        if suspicious:
            print("\n--- Suspicious Indicators ---")
            for s in suspicious:
                print(f"  [!] {s['indicator']}")
    elif os.path.isdir(target):
        print(f"\n[*] Scanning directory: {target}")
        lnk_results = scan_lnk_directory(target)
        print(f"[*] Found {len(lnk_results)} LNK files")
        for r in lnk_results[:20]:
            print(f"  {r['file']}: {r['parsed'].get('target_path', r['parsed'].get('local_base_path', '?'))}")
            for s in r.get("suspicious", []):
                print(f"    [!] {s['indicator']}")

        jl_dir = os.path.join(target, "AutomaticDestinations")
        if not os.path.isdir(jl_dir):
            jl_dir = target
        jl_results = scan_jump_lists(jl_dir)
        if jl_results:
            print(f"\n--- Jump Lists ({len(jl_results)}) ---")
            for jl in jl_results:
                print(f"  {jl['app_name']:30s} [{jl['type']}] {jl['app_id']}")

    print(f"\n{json.dumps({'lnk_count': len(lnk_results) if os.path.isdir(target) else 1}, indent=2)}")
