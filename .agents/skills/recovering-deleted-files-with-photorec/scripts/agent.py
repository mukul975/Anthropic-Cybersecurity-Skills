#!/usr/bin/env python3
"""Deleted file recovery agent using PhotoRec subprocess wrapper."""

import subprocess
import os
import sys
import json
import hashlib
from pathlib import Path
from collections import defaultdict
from datetime import datetime


def verify_photorec():
    """Check that PhotoRec is installed and available."""
    result = subprocess.run(
        ["photorec", "--version"], capture_output=True, text=True
    )
    if result.returncode == 0:
        return {"installed": True, "version": result.stdout.strip()}
    return {"installed": False}


def get_image_info(image_path):
    """Get forensic image information."""
    file_result = subprocess.run(
        ["file", image_path], capture_output=True, text=True
    )
    size = os.path.getsize(image_path) if os.path.exists(image_path) else 0
    return {
        "path": image_path,
        "size_bytes": size,
        "size_gb": round(size / (1024 ** 3), 2),
        "type": file_result.stdout.strip(),
    }


def run_photorec(image_path, output_dir, file_types=None, partition=None):
    """Run PhotoRec for file recovery using command-line interface."""
    os.makedirs(output_dir, exist_ok=True)
    cmd = ["photorec", "/d", output_dir, "/cmd", image_path]
    options = []
    if partition:
        options.append(f"partition_i_end,{partition}")
    if file_types:
        enable_list = ",".join(file_types)
        options.append(f"fileopt,everything,disable,{enable_list},enable")
    options.append("search")
    cmd.append(",".join(options) if options else "search")
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=14400
    )
    return {
        "command": " ".join(cmd),
        "returncode": result.returncode,
        "stdout": result.stdout[-1000:] if result.stdout else "",
        "stderr": result.stderr[-500:] if result.stderr else "",
        "output_dir": output_dir,
    }


def catalog_recovered_files(output_dir):
    """Catalog all recovered files by type, size, and hash."""
    catalog = defaultdict(list)
    total_files = 0
    total_bytes = 0
    for root, dirs, files in os.walk(output_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            ext = Path(filename).suffix.lower()
            try:
                size = os.path.getsize(filepath)
            except OSError:
                continue
            total_files += 1
            total_bytes += size
            entry = {
                "path": filepath,
                "filename": filename,
                "extension": ext,
                "size": size,
            }
            catalog[ext].append(entry)
    summary = {
        "total_files": total_files,
        "total_bytes": total_bytes,
        "total_mb": round(total_bytes / (1024 * 1024), 2),
        "by_extension": {
            ext: {"count": len(files), "total_bytes": sum(f["size"] for f in files)}
            for ext, files in sorted(catalog.items(), key=lambda x: -len(x[1]))
        },
    }
    return summary


def hash_recovered_files(output_dir, extensions=None):
    """Generate SHA-256 hashes for recovered files for evidence integrity."""
    hashes = []
    for root, dirs, files in os.walk(output_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            ext = Path(filename).suffix.lower()
            if extensions and ext not in extensions:
                continue
            try:
                with open(filepath, "rb") as f:
                    sha256 = hashlib.sha256(f.read()).hexdigest()
                hashes.append({
                    "file": filepath,
                    "sha256": sha256,
                    "size": os.path.getsize(filepath),
                })
            except (OSError, PermissionError):
                pass
    return hashes


def sort_recovered_files(output_dir, sorted_dir):
    """Sort recovered files into categorized directories."""
    categories = {
        "documents": [".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx",
                      ".odt", ".ods", ".txt", ".rtf", ".csv"],
        "images": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".svg", ".webp"],
        "databases": [".db", ".sqlite", ".mdb", ".accdb", ".sql"],
        "archives": [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"],
        "executables": [".exe", ".dll", ".bat", ".ps1", ".sh", ".msi"],
        "email": [".eml", ".msg", ".pst", ".ost", ".mbox"],
        "web": [".html", ".htm", ".css", ".js", ".json", ".xml"],
    }
    os.makedirs(sorted_dir, exist_ok=True)
    for cat in categories:
        os.makedirs(os.path.join(sorted_dir, cat), exist_ok=True)
    os.makedirs(os.path.join(sorted_dir, "other"), exist_ok=True)
    moved = defaultdict(int)
    for root, dirs, files in os.walk(output_dir):
        if root.startswith(sorted_dir):
            continue
        for filename in files:
            src = os.path.join(root, filename)
            ext = Path(filename).suffix.lower()
            target_cat = "other"
            for cat, exts in categories.items():
                if ext in exts:
                    target_cat = cat
                    break
            dst = os.path.join(sorted_dir, target_cat, filename)
            counter = 1
            while os.path.exists(dst):
                name, extension = os.path.splitext(filename)
                dst = os.path.join(sorted_dir, target_cat, f"{name}_{counter}{extension}")
                counter += 1
            try:
                os.rename(src, dst)
                moved[target_cat] += 1
            except OSError:
                pass
    return dict(moved)


def full_recovery_pipeline(image_path, output_dir, file_types=None):
    """Run complete file recovery pipeline."""
    results = {"timestamp": datetime.now().isoformat()}
    results["image_info"] = get_image_info(image_path)
    recovery_dir = os.path.join(output_dir, "recovered")
    results["recovery"] = run_photorec(image_path, recovery_dir, file_types=file_types)
    if os.path.exists(recovery_dir):
        results["catalog"] = catalog_recovered_files(recovery_dir)
        sorted_dir = os.path.join(output_dir, "sorted")
        results["sorting"] = sort_recovered_files(recovery_dir, sorted_dir)
    return results


def print_report(results):
    print("File Recovery Report")
    print("=" * 50)
    print(f"Date: {results.get('timestamp', 'N/A')}")
    img = results.get("image_info", {})
    print(f"Image: {img.get('path', 'N/A')} ({img.get('size_gb', 0)} GB)")
    cat = results.get("catalog", {})
    print(f"\nRecovered: {cat.get('total_files', 0)} files ({cat.get('total_mb', 0)} MB)")
    print("\nBy Extension:")
    for ext, info in list(cat.get("by_extension", {}).items())[:15]:
        print(f"  {ext:8s}: {info['count']:>5} files ({info['total_bytes'] // 1024:>8} KB)")
    sorting = results.get("sorting", {})
    if sorting:
        print("\nSorted Categories:")
        for cat_name, count in sorting.items():
            print(f"  {cat_name:15s}: {count} files")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python agent.py <disk_image> <output_dir> [file_types]")
        print("  file_types: comma-separated (e.g., jpg,pdf,doc)")
        sys.exit(1)
    image = sys.argv[1]
    output = sys.argv[2]
    types = sys.argv[3].split(",") if len(sys.argv) > 3 else None
    results = full_recovery_pipeline(image, output, file_types=types)
    print_report(results)
