#!/usr/bin/env python3
"""Forensic disk image analysis agent using The Sleuth Kit (TSK) command-line tools."""

import subprocess
import os
import sys
import json
import csv
import datetime


def run_cmd(cmd):
    """Execute a shell command and return output."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def get_image_info(image_path):
    """Retrieve disk image metadata using img_stat."""
    stdout, _, rc = run_cmd(f"img_stat {image_path}")
    if rc == 0:
        info = {}
        for line in stdout.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                info[key.strip()] = val.strip()
        return info
    return None


def list_partitions(image_path):
    """List partition layout using mmls."""
    stdout, _, rc = run_cmd(f"mmls {image_path}")
    partitions = []
    if rc == 0:
        for line in stdout.splitlines():
            parts = line.split()
            if len(parts) >= 6 and parts[2].isdigit():
                partitions.append({
                    "slot": parts[0].rstrip(":"),
                    "start": int(parts[2]),
                    "end": int(parts[3]),
                    "length": int(parts[4]),
                    "description": " ".join(parts[5:]),
                })
    return partitions


def list_files(image_path, offset, path="/", recursive=False):
    """List files in a partition using fls."""
    flags = "-r" if recursive else ""
    cmd = f"fls {flags} -o {offset} {image_path}"
    if path != "/":
        cmd += f" -D {path}"
    stdout, _, rc = run_cmd(cmd)
    files = []
    if rc == 0:
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t", 1)
            if len(parts) == 2:
                meta = parts[0].strip()
                name = parts[1].strip()
                deleted = meta.startswith("*")
                file_type = "d" if "d/" in meta else "r"
                inode = ""
                for token in meta.split():
                    if "-" in token and token.replace("-", "").isdigit():
                        inode = token
                        break
                files.append({
                    "name": name,
                    "inode": inode,
                    "type": "directory" if file_type == "d" else "file",
                    "deleted": deleted,
                })
    return files


def list_deleted_files(image_path, offset):
    """List only deleted files using fls -rd."""
    stdout, _, rc = run_cmd(f"fls -rd -o {offset} {image_path}")
    deleted = []
    if rc == 0:
        for line in stdout.splitlines():
            line = line.strip()
            if line:
                deleted.append(line)
    return deleted


def recover_file(image_path, offset, inode, output_path):
    """Recover a file by inode using icat."""
    cmd = f"icat -o {offset} {image_path} {inode} > {output_path}"
    _, _, rc = run_cmd(cmd)
    return rc == 0


def get_file_metadata(image_path, offset, inode):
    """Get detailed file metadata using istat."""
    stdout, _, rc = run_cmd(f"istat -o {offset} {image_path} {inode}")
    return stdout if rc == 0 else None


def create_bodyfile(image_path, offset, output_path):
    """Generate a TSK bodyfile for timeline creation."""
    cmd = f'fls -r -m "/" -o {offset} {image_path} > {output_path}'
    _, _, rc = run_cmd(cmd)
    return rc == 0


def generate_timeline(bodyfile_path, output_csv, start_date=None, end_date=None):
    """Generate a timeline from a bodyfile using mactime."""
    cmd = f"mactime -b {bodyfile_path} -d"
    if start_date and end_date:
        cmd += f" {start_date}..{end_date}"
    cmd += f" > {output_csv}"
    _, _, rc = run_cmd(cmd)
    return rc == 0


def search_keywords(image_path, offset, keyword):
    """Search for keyword strings in the disk image."""
    cmd = f'srch_strings -a -o {offset} {image_path} | grep -i "{keyword}"'
    stdout, _, rc = run_cmd(cmd)
    return stdout.splitlines() if rc == 0 else []


def find_file_signature(image_path, offset, hex_signature):
    """Find file signatures at the sector level using sigfind."""
    stdout, _, rc = run_cmd(f"sigfind -o {offset} {image_path} {hex_signature}")
    return stdout if rc == 0 else None


def analyze_image(image_path, case_dir):
    """Run a full automated analysis workflow on a disk image."""
    os.makedirs(case_dir, exist_ok=True)
    results = {"image": image_path, "timestamp": datetime.datetime.utcnow().isoformat()}

    print(f"[*] Image info...")
    results["image_info"] = get_image_info(image_path)

    print(f"[*] Partition layout...")
    partitions = list_partitions(image_path)
    results["partitions"] = partitions

    for part in partitions:
        if "NTFS" in part.get("description", "") or "Linux" in part.get("description", ""):
            offset = part["start"]
            print(f"[*] Listing files at offset {offset} ({part['description']})...")
            files = list_files(image_path, offset, recursive=True)
            results[f"files_offset_{offset}"] = {
                "total": len(files),
                "deleted": sum(1 for f in files if f["deleted"]),
            }
            print(f"    Total: {len(files)}, Deleted: {results[f'files_offset_{offset}']['deleted']}")

            print(f"[*] Creating bodyfile for timeline...")
            bf_path = os.path.join(case_dir, f"bodyfile_{offset}.txt")
            create_bodyfile(image_path, offset, bf_path)

            tl_path = os.path.join(case_dir, f"timeline_{offset}.csv")
            generate_timeline(bf_path, tl_path)

    report_path = os.path.join(case_dir, "analysis_summary.json")
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"[*] Summary saved to {report_path}")
    return results


if __name__ == "__main__":
    print("=" * 60)
    print("Disk Image Forensic Analysis Agent")
    print("Tools: The Sleuth Kit (fls, icat, mmls, mactime)")
    print("=" * 60)

    if len(sys.argv) > 1:
        image = sys.argv[1]
        case = sys.argv[2] if len(sys.argv) > 2 else "/tmp/autopsy_case"
        if os.path.exists(image):
            analyze_image(image, case)
        else:
            print(f"[ERROR] Image not found: {image}")
    else:
        print("\n[DEMO] Usage: python agent.py <disk_image.dd> [case_directory]")
        print("[*] Supported operations:")
        print("    - Partition enumeration (mmls)")
        print("    - File listing with deleted file recovery (fls, icat)")
        print("    - Timeline generation (mactime)")
        print("    - Keyword searching (srch_strings)")
        print("    - File signature detection (sigfind)")
