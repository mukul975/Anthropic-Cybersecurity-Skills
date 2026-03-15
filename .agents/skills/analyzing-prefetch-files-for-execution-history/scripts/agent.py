#!/usr/bin/env python3
"""Windows Prefetch file analysis agent for program execution history forensics."""

import struct
import os
import sys
import hashlib
import datetime
import json
import glob


def parse_prefetch_header(filepath):
    """Parse the Prefetch file header to extract execution metadata."""
    with open(filepath, "rb") as f:
        data = f.read()

    # Check for compression (Windows 10 prefetch files are MAM compressed)
    if data[:4] == b"MAM\x04":
        # Windows 10 compressed format - need decompression
        return {"error": "Compressed prefetch (Windows 10 MAM format) - use PECmd for full parsing",
                "compressed": True, "raw_size": len(data)}

    # Standard prefetch header (versions 17, 23, 26, 30)
    if len(data) < 84:
        return {"error": "File too small to be a valid prefetch file"}

    version = struct.unpack_from("<I", data, 0)[0]
    signature = data[4:8]

    if signature != b"SCCA":
        return {"error": f"Invalid signature: {signature.hex()} (expected 53434341)"}

    file_size = struct.unpack_from("<I", data, 12)[0]
    exe_name = data[16:76].decode("utf-16-le", errors="replace").rstrip("\x00")
    hash_value = struct.unpack_from("<I", data, 76)[0]

    result = {
        "version": version,
        "signature": signature.hex(),
        "file_size": file_size,
        "executable_name": exe_name,
        "prefetch_hash": f"0x{hash_value:08X}",
    }

    # Version-specific parsing
    if version == 17:  # Windows XP
        result["format"] = "Windows XP"
        run_count = struct.unpack_from("<I", data, 144)[0]
        last_run = parse_filetime(struct.unpack_from("<Q", data, 120)[0])
        result["run_count"] = run_count
        result["last_run_time"] = last_run
    elif version == 23:  # Windows Vista/7
        result["format"] = "Windows Vista/7"
        run_count = struct.unpack_from("<I", data, 152)[0]
        last_run = parse_filetime(struct.unpack_from("<Q", data, 128)[0])
        result["run_count"] = run_count
        result["last_run_time"] = last_run
    elif version == 26:  # Windows 8/8.1
        result["format"] = "Windows 8/8.1"
        run_count = struct.unpack_from("<I", data, 208)[0]
        last_run = parse_filetime(struct.unpack_from("<Q", data, 128)[0])
        result["run_count"] = run_count
        result["last_run_time"] = last_run
    elif version == 30:  # Windows 10/11
        result["format"] = "Windows 10/11"
        result["note"] = "Use PECmd.exe for full Windows 10 prefetch parsing"
    else:
        result["format"] = f"Unknown version {version}"

    return result


def parse_filetime(filetime):
    """Convert Windows FILETIME (100ns intervals since 1601-01-01) to ISO string."""
    if filetime == 0:
        return "N/A"
    try:
        epoch = datetime.datetime(1601, 1, 1)
        delta = datetime.timedelta(microseconds=filetime // 10)
        dt = epoch + delta
        return dt.isoformat() + "Z"
    except (OverflowError, OSError):
        return "Invalid timestamp"


def parse_prefetch_filename(filename):
    """Parse executable name and hash from prefetch filename format: APPNAME-HASH.pf."""
    basename = os.path.basename(filename)
    if not basename.upper().endswith(".PF"):
        return None, None
    name_part = basename[:-3]  # Remove .pf
    parts = name_part.rsplit("-", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return name_part, None


def scan_prefetch_directory(prefetch_dir):
    """Scan a directory of prefetch files and extract execution history."""
    results = []
    pf_files = glob.glob(os.path.join(prefetch_dir, "*.pf"))
    pf_files.extend(glob.glob(os.path.join(prefetch_dir, "*.PF")))

    for pf_file in sorted(set(pf_files)):
        exe_name, pf_hash = parse_prefetch_filename(pf_file)
        header = parse_prefetch_header(pf_file)
        results.append({
            "file": os.path.basename(pf_file),
            "parsed_name": exe_name,
            "parsed_hash": pf_hash,
            "file_modified": datetime.datetime.fromtimestamp(
                os.path.getmtime(pf_file)).isoformat(),
            "header": header,
        })
    return results


SUSPICIOUS_EXECUTABLES = [
    "MIMIKATZ", "PSEXEC", "WMIC", "PROCDUMP", "RUBEUS", "SEATBELT",
    "BLOODHOUND", "SHARPHOUND", "LAZAGNE", "SECRETSDUMP", "NTDSUTIL",
    "CERTUTIL", "BITSADMIN", "MSHTA", "REGSVR32", "RUNDLL32",
    "CSCRIPT", "WSCRIPT", "POWERSHELL", "CMD", "MSBUILD",
    "INSTALLUTIL", "REGASM", "REGSVCS", "XWIZARD",
    "NETCAT", "NCAT", "NC", "NMAP", "MASSCAN",
    "RAR", "7Z", "WINRAR", "RCLONE",
]


def detect_suspicious_execution(prefetch_results):
    """Flag suspicious or known-attacker-tool prefetch files."""
    findings = []
    for result in prefetch_results:
        name = (result.get("parsed_name") or "").upper()
        for sus in SUSPICIOUS_EXECUTABLES:
            if sus in name:
                findings.append({
                    "severity": "HIGH",
                    "executable": result.get("parsed_name"),
                    "file": result.get("file"),
                    "reason": f"Known offensive/dual-use tool: {sus}",
                    "run_count": result.get("header", {}).get("run_count"),
                    "last_run": result.get("header", {}).get("last_run_time"),
                })
                break
    return findings


def build_execution_timeline(prefetch_results):
    """Build a chronological timeline of program execution."""
    timeline = []
    for result in prefetch_results:
        header = result.get("header", {})
        last_run = header.get("last_run_time")
        if last_run and last_run not in ("N/A", "Invalid timestamp"):
            timeline.append({
                "timestamp": last_run,
                "executable": result.get("parsed_name"),
                "run_count": header.get("run_count"),
                "prefetch_file": result.get("file"),
            })
    return sorted(timeline, key=lambda x: x["timestamp"])


def run_pecmd(prefetch_path, output_dir=None):
    """Run Eric Zimmerman's PECmd for comprehensive prefetch parsing."""
    cmd = f"PECmd.exe -f {prefetch_path}"
    if output_dir:
        cmd += f" --csv {output_dir}"
    import subprocess
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
    return result.stdout, result.returncode


if __name__ == "__main__":
    print("=" * 60)
    print("Windows Prefetch File Analysis Agent")
    print("Execution history, timeline building, suspicious tool detection")
    print("=" * 60)

    target = sys.argv[1] if len(sys.argv) > 1 else None

    if target and os.path.exists(target):
        if os.path.isdir(target):
            print(f"\n[*] Scanning prefetch directory: {target}")
            results = scan_prefetch_directory(target)
            print(f"[*] Found {len(results)} prefetch files")

            print("\n--- Execution History ---")
            for r in results[:20]:
                header = r.get("header", {})
                name = r.get("parsed_name", "?")
                count = header.get("run_count", "?")
                last = header.get("last_run_time", "?")
                print(f"  {name:30s} runs={count} last={last}")

            print("\n--- Suspicious Executables ---")
            suspicious = detect_suspicious_execution(results)
            for s in suspicious:
                print(f"  [!] {s['executable']}: {s['reason']} "
                      f"(runs={s['run_count']}, last={s['last_run']})")

            print("\n--- Execution Timeline ---")
            timeline = build_execution_timeline(results)
            for t in timeline[-20:]:
                print(f"  {t['timestamp']} | {t['executable']} (x{t['run_count']})")
        else:
            print(f"\n[*] Analyzing: {target}")
            exe_name, pf_hash = parse_prefetch_filename(target)
            print(f"  Name: {exe_name}, Hash: {pf_hash}")
            header = parse_prefetch_header(target)
            print(f"  {json.dumps(header, indent=2)}")
    else:
        print(f"\n[DEMO] Usage:")
        print(f"  python agent.py <prefetch_dir>    # Analyze all .pf files")
        print(f"  python agent.py <file.pf>         # Analyze single prefetch file")
