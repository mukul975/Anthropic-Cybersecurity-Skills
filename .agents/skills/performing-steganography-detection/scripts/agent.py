#!/usr/bin/env python3
"""Steganography detection agent using Pillow, numpy, and subprocess tools."""

import os
import sys
import json
import subprocess
import struct
from pathlib import Path

try:
    from PIL import Image
    import numpy as np
except ImportError:
    print("Install: pip install Pillow numpy")
    sys.exit(1)


def check_trailing_data(filepath):
    """Check for data appended after JPEG/PNG end markers."""
    with open(filepath, "rb") as f:
        data = f.read()
    filesize = len(data)
    findings = {"filepath": filepath, "filesize": filesize, "trailing_bytes": 0}
    if data[:2] == b"\xff\xd8":
        jpeg_end = data.rfind(b"\xff\xd9")
        if jpeg_end > 0:
            trailing = filesize - jpeg_end - 2
            if trailing > 0:
                findings["trailing_bytes"] = trailing
                findings["format"] = "JPEG"
    elif data[:4] == b"\x89PNG":
        iend = data.rfind(b"IEND")
        if iend > 0:
            end_pos = iend + 8
            trailing = filesize - end_pos
            if trailing > 0:
                findings["trailing_bytes"] = trailing
                findings["format"] = "PNG"
    zip_offset = data.find(b"PK\x03\x04")
    rar_offset = data.find(b"Rar!\x1a\x07")
    if zip_offset > 0:
        findings["embedded_zip"] = zip_offset
    if rar_offset > 0:
        findings["embedded_rar"] = rar_offset
    return findings


def lsb_analysis(filepath):
    """Perform LSB analysis on image channels."""
    img = Image.open(filepath).convert("RGB")
    pixels = np.array(img)
    results = {}
    for channel, name in enumerate(["Red", "Green", "Blue"]):
        lsb_data = pixels[:, :, channel] & 1
        zeros = int(np.sum(lsb_data == 0))
        ones = int(np.sum(lsb_data == 1))
        total = zeros + ones
        ratio = ones / total if total > 0 else 0
        anomaly = "NORMAL"
        if abs(ratio - 0.5) < 0.01:
            anomaly = "NEAR_RANDOM"
        elif ratio > 0.55 or ratio < 0.45:
            anomaly = "SIGNIFICANT_DEVIATION"
        results[name] = {
            "zeros": zeros, "ones": ones, "ratio": round(ratio, 4),
            "anomaly": anomaly,
        }
    return results


def extract_lsb_data(filepath, output_path):
    """Extract LSB data from red channel and check for file signatures."""
    img = Image.open(filepath).convert("RGB")
    pixels = np.array(img)
    lsb_bits = (pixels[:, :, 0] & 1).flatten()
    lsb_bytes = np.packbits(lsb_bits)
    with open(output_path, "wb") as f:
        f.write(lsb_bytes.tobytes())
    header = bytes(lsb_bytes[:16])
    detected = None
    if header[:4] == b"PK\x03\x04":
        detected = "ZIP archive"
    elif header[:3] == b"GIF":
        detected = "GIF image"
    elif header[:4] == b"\x89PNG":
        detected = "PNG image"
    elif header[:2] == b"\xff\xd8":
        detected = "JPEG image"
    elif header[:4] == b"%PDF":
        detected = "PDF document"
    return {"output": output_path, "header_hex": header.hex(), "detected_format": detected}


def run_binwalk(filepath):
    """Run binwalk to detect embedded files."""
    try:
        result = subprocess.run(
            ["binwalk", filepath], capture_output=True, text=True, timeout=30
        )
        return {"tool": "binwalk", "output": result.stdout.strip()}
    except FileNotFoundError:
        return {"tool": "binwalk", "output": "binwalk not installed"}
    except subprocess.TimeoutExpired:
        return {"tool": "binwalk", "output": "timeout"}


def run_zsteg(filepath):
    """Run zsteg on PNG/BMP files for LSB detection."""
    try:
        result = subprocess.run(
            ["zsteg", filepath], capture_output=True, text=True, timeout=30
        )
        return {"tool": "zsteg", "output": result.stdout.strip()}
    except FileNotFoundError:
        return {"tool": "zsteg", "output": "zsteg not installed"}
    except subprocess.TimeoutExpired:
        return {"tool": "zsteg", "output": "timeout"}


def run_steghide_extract(filepath, passwords=None):
    """Attempt steghide extraction with multiple passwords."""
    if passwords is None:
        passwords = ["", "password", "secret", "hidden", "stego", "test", "123456"]
    results = []
    for pwd in passwords:
        try:
            out_file = f"/tmp/steghide_{pwd or 'empty'}.bin"
            result = subprocess.run(
                ["steghide", "extract", "-sf", filepath, "-p", pwd,
                 "-xf", out_file, "-f"],
                capture_output=True, text=True, timeout=10
            )
            if "extracted" in result.stdout.lower() or result.returncode == 0:
                results.append({"password": pwd or "(empty)", "success": True, "output": out_file})
        except (FileNotFoundError, subprocess.TimeoutExpired):
            break
    return results


def analyze_file(filepath, output_dir=None):
    """Full steganalysis pipeline for a single file."""
    if output_dir is None:
        output_dir = os.path.dirname(filepath)
    report = {"file": filepath, "findings": []}
    trailing = check_trailing_data(filepath)
    if trailing["trailing_bytes"] > 0:
        report["findings"].append({
            "type": "trailing_data",
            "detail": f"{trailing['trailing_bytes']} bytes after {trailing.get('format', 'unknown')} end marker",
        })
    if "embedded_zip" in trailing:
        report["findings"].append({"type": "embedded_archive", "detail": f"ZIP at offset {trailing['embedded_zip']}"})
    ext = Path(filepath).suffix.lower()
    if ext in (".png", ".bmp", ".jpg", ".jpeg", ".gif"):
        report["lsb_analysis"] = lsb_analysis(filepath)
        lsb_out = os.path.join(output_dir, "lsb_extracted.bin")
        report["lsb_extract"] = extract_lsb_data(filepath, lsb_out)
        if report["lsb_extract"]["detected_format"]:
            report["findings"].append({
                "type": "lsb_hidden_file",
                "detail": f"Detected {report['lsb_extract']['detected_format']} in LSB data",
            })
    report["binwalk"] = run_binwalk(filepath)
    if ext in (".png", ".bmp"):
        report["zsteg"] = run_zsteg(filepath)
    if ext in (".jpg", ".jpeg", ".bmp", ".wav", ".au"):
        report["steghide"] = run_steghide_extract(filepath)
        if report["steghide"]:
            report["findings"].append({
                "type": "steghide_extraction",
                "detail": f"Data extracted with {len(report['steghide'])} password(s)",
            })
    return report


def print_report(report):
    print("Steganalysis Report")
    print("=" * 40)
    print(f"File: {report['file']}")
    if "lsb_analysis" in report:
        print("\nLSB Analysis:")
        for channel, data in report["lsb_analysis"].items():
            print(f"  {channel}: ratio={data['ratio']} ({data['anomaly']})")
    print(f"\nFindings: {len(report['findings'])}")
    for f in report["findings"]:
        print(f"  [{f['type']}] {f['detail']}")
    if "binwalk" in report and report["binwalk"]["output"] != "binwalk not installed":
        print(f"\nBinwalk:\n{report['binwalk']['output']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python agent.py <image_file>")
        sys.exit(1)
    result = analyze_file(sys.argv[1])
    print_report(result)
