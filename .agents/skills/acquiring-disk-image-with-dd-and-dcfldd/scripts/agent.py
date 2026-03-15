#!/usr/bin/env python3
"""Forensic disk image acquisition agent using dd and dcfldd with hash verification."""

import subprocess
import hashlib
import os
import sys
import datetime
import json


def run_cmd(cmd, capture=True):
    """Execute a shell command and return output."""
    result = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def list_block_devices():
    """Enumerate connected block devices."""
    stdout, _, rc = run_cmd("lsblk -J -o NAME,SIZE,TYPE,MOUNTPOINT,MODEL,SERIAL,RO")
    if rc == 0 and stdout:
        return json.loads(stdout)
    return {"blockdevices": []}


def check_write_protection(device):
    """Verify a device is set to read-only mode."""
    stdout, _, rc = run_cmd(f"blockdev --getro {device}")
    if rc == 0:
        return stdout.strip() == "1"
    return False


def enable_write_protection(device):
    """Enable software write-blocking on the target device."""
    _, _, rc = run_cmd(f"blockdev --setro {device}")
    if rc != 0:
        print(f"[ERROR] Failed to set {device} read-only. Run as root.")
        return False
    if check_write_protection(device):
        print(f"[OK] Write protection enabled on {device}")
        return True
    print(f"[ERROR] Write protection verification failed for {device}")
    return False


def compute_hash(path, algorithm="sha256", block_size=65536):
    """Compute the SHA-256 or MD5 hash of a file or device."""
    h = hashlib.new(algorithm)
    try:
        with open(path, "rb") as f:
            while True:
                block = f.read(block_size)
                if not block:
                    break
                h.update(block)
    except PermissionError:
        print(f"[ERROR] Permission denied reading {path}. Run as root.")
        return None
    except FileNotFoundError:
        print(f"[ERROR] Path not found: {path}")
        return None
    return h.hexdigest()


def acquire_with_dd(source, destination, block_size=4096, log_file=None):
    """Acquire a forensic image using dd with error handling."""
    cmd = (
        f"dd if={source} of={destination} bs={block_size} "
        f"conv=noerror,sync status=progress"
    )
    if log_file:
        cmd += f" 2>&1 | tee {log_file}"
    print(f"[*] Starting dd acquisition: {source} -> {destination}")
    print(f"[*] Block size: {block_size}")
    start = datetime.datetime.utcnow()
    _, stderr, rc = run_cmd(cmd, capture=False)
    elapsed = (datetime.datetime.utcnow() - start).total_seconds()
    print(f"[*] Acquisition completed in {elapsed:.1f} seconds (rc={rc})")
    return rc == 0


def acquire_with_dcfldd(source, destination, hash_alg="sha256", hash_log=None,
                        error_log=None, block_size=4096, split_size=None):
    """Acquire a forensic image using dcfldd with built-in hashing."""
    cmd = f"dcfldd if={source} of={destination} bs={block_size} conv=noerror,sync"
    cmd += f" hash={hash_alg}"
    if hash_log:
        cmd += f" hashlog={hash_log}"
    cmd += " hashwindow=1G"
    if error_log:
        cmd += f" errlog={error_log}"
    if split_size:
        cmd += f" split={split_size} splitformat=aa"
    print(f"[*] Starting dcfldd acquisition: {source} -> {destination}")
    start = datetime.datetime.utcnow()
    _, stderr, rc = run_cmd(cmd, capture=False)
    elapsed = (datetime.datetime.utcnow() - start).total_seconds()
    print(f"[*] dcfldd completed in {elapsed:.1f} seconds (rc={rc})")
    return rc == 0


def verify_image(source, image_path, algorithm="sha256"):
    """Verify image integrity by comparing hashes of source and acquired image."""
    print(f"[*] Computing {algorithm} hash of source: {source}")
    source_hash = compute_hash(source, algorithm)
    print(f"    Source hash:  {source_hash}")
    print(f"[*] Computing {algorithm} hash of image: {image_path}")
    image_hash = compute_hash(image_path, algorithm)
    print(f"    Image hash:   {image_hash}")
    if source_hash and image_hash:
        match = source_hash == image_hash
        status = "PASSED" if match else "FAILED"
        print(f"[{'OK' if match else 'FAIL'}] Verification: {status}")
        return match, source_hash, image_hash
    return False, source_hash, image_hash


def generate_report(case_dir, source_device, image_path, tool_used,
                    source_hash, image_hash, verified, elapsed_seconds=0):
    """Generate a forensic acquisition report."""
    report = {
        "report_type": "Disk Image Acquisition",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "case_directory": case_dir,
        "source_device": source_device,
        "image_file": image_path,
        "acquisition_tool": tool_used,
        "block_size": 4096,
        "source_hash_sha256": source_hash,
        "image_hash_sha256": image_hash,
        "hash_verified": verified,
        "duration_seconds": elapsed_seconds,
    }
    report_path = os.path.join(case_dir, "acquisition_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Report saved to {report_path}")
    return report


if __name__ == "__main__":
    print("=" * 60)
    print("Forensic Disk Image Acquisition Agent")
    print("Tools: dd / dcfldd with SHA-256 verification")
    print("=" * 60)

    # Demo: list block devices
    print("\n[*] Enumerating block devices...")
    devices = list_block_devices()
    for dev in devices.get("blockdevices", []):
        name = dev.get("name", "?")
        size = dev.get("size", "?")
        dtype = dev.get("type", "?")
        model = dev.get("model", "N/A")
        ro = "RO" if dev.get("ro") else "RW"
        print(f"    /dev/{name}  {size}  {dtype}  {model}  [{ro}]")

    # Demo workflow (dry run)
    demo_source = "/dev/sdb"
    demo_case = "/cases/demo-case/images"
    demo_image = os.path.join(demo_case, "evidence.dd")

    print(f"\n[DEMO] Acquisition workflow for {demo_source}:")
    print(f"  1. Enable write protection: blockdev --setro {demo_source}")
    print(f"  2. Acquire with dcfldd: dcfldd if={demo_source} of={demo_image} "
          f"hash=sha256 hashwindow=1G bs=4096 conv=noerror,sync")
    print(f"  3. Verify: compare SHA-256 of {demo_source} and {demo_image}")
    print(f"  4. Generate acquisition report with chain-of-custody metadata")
    print("\n[*] Agent ready. Provide a source device and case directory to begin.")
