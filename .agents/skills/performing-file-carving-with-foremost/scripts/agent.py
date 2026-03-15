#!/usr/bin/env python3
"""Agent for performing file carving with Foremost.

Automates file carving from disk images using foremost/scalpel,
validates carved files, and generates evidence catalogs with hashes.
"""

import subprocess
import os
import sys
import hashlib
import json
from collections import defaultdict
from pathlib import Path


class FileCarvingAgent:
    """Automates forensic file carving and validation workflows."""

    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run_foremost(self, image_path, file_types="all", config_path=None):
        """Execute foremost against a disk image."""
        carved_dir = self.output_dir / "foremost_output"
        if carved_dir.exists():
            subprocess.run(["rm", "-rf", str(carved_dir)], check=False)

        cmd = ["foremost"]
        if config_path:
            cmd.extend(["-c", config_path])
        cmd.extend(["-t", file_types, "-i", image_path, "-o", str(carved_dir)])

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Foremost error: {result.stderr}")
        return carved_dir

    def run_scalpel(self, image_path, config_path="/etc/scalpel/scalpel.conf"):
        """Execute scalpel for high-performance carving."""
        carved_dir = self.output_dir / "scalpel_output"
        cmd = ["scalpel", "-c", config_path, "-o", str(carved_dir), image_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Scalpel error: {result.stderr}")
        return carved_dir

    def validate_carved_files(self, carved_dir):
        """Validate carved files using the file command and size checks."""
        stats = defaultdict(lambda: {"total": 0, "valid": 0, "invalid": 0, "size": 0})
        carved_path = Path(carved_dir)

        for subdir in sorted(carved_path.iterdir()):
            if not subdir.is_dir() or subdir.name == "audit.txt":
                continue
            for filepath in sorted(subdir.iterdir()):
                if not filepath.is_file():
                    continue
                ext = subdir.name
                filesize = filepath.stat().st_size
                stats[ext]["total"] += 1
                stats[ext]["size"] += filesize

                if filesize == 0:
                    stats[ext]["invalid"] += 1
                    continue

                result = subprocess.run(
                    ["file", "--brief", str(filepath)],
                    capture_output=True, text=True
                )
                file_type = result.stdout.strip().lower()
                if "data" in file_type or "empty" in file_type:
                    stats[ext]["invalid"] += 1
                else:
                    stats[ext]["valid"] += 1

        return dict(stats)

    def hash_carved_files(self, carved_dir):
        """Generate SHA-256 hashes for all carved files."""
        hashes = []
        carved_path = Path(carved_dir)

        for subdir in sorted(carved_path.iterdir()):
            if not subdir.is_dir() or subdir.name == "audit.txt":
                continue
            for filepath in sorted(subdir.iterdir()):
                if not filepath.is_file() or filepath.stat().st_size == 0:
                    continue
                sha256 = hashlib.sha256(filepath.read_bytes()).hexdigest()
                hashes.append({
                    "filename": filepath.name,
                    "type": subdir.name,
                    "size": filepath.stat().st_size,
                    "sha256": sha256,
                    "path": str(filepath),
                })
        return hashes

    def build_evidence_catalog(self, carved_dir):
        """Build a comprehensive evidence catalog of carved files."""
        validation = self.validate_carved_files(carved_dir)
        file_hashes = self.hash_carved_files(carved_dir)

        catalog = {
            "carving_tool": "foremost",
            "source_directory": str(carved_dir),
            "validation_summary": validation,
            "total_files": sum(s["total"] for s in validation.values()),
            "valid_files": sum(s["valid"] for s in validation.values()),
            "invalid_files": sum(s["invalid"] for s in validation.values()),
            "total_size_bytes": sum(s["size"] for s in validation.values()),
            "files": file_hashes,
        }

        catalog_path = self.output_dir / "evidence_catalog.json"
        with open(catalog_path, "w") as f:
            json.dump(catalog, f, indent=2)
        return catalog

    def parse_audit_file(self, carved_dir):
        """Parse the foremost audit.txt file for carving summary."""
        audit_path = Path(carved_dir) / "audit.txt"
        if not audit_path.exists():
            return {"error": "audit.txt not found"}
        return {"content": audit_path.read_text(), "path": str(audit_path)}

    def remove_zero_byte_files(self, carved_dir):
        """Remove zero-byte carved files that are invalid."""
        removed = 0
        carved_path = Path(carved_dir)
        for subdir in carved_path.iterdir():
            if not subdir.is_dir():
                continue
            for filepath in subdir.iterdir():
                if filepath.is_file() and filepath.stat().st_size == 0:
                    filepath.unlink()
                    removed += 1
        return removed

    def generate_report(self, carved_dir):
        """Generate a file carving summary report."""
        validation = self.validate_carved_files(carved_dir)
        audit = self.parse_audit_file(carved_dir)

        print("FILE CARVING SUMMARY REPORT")
        print("=" * 50)
        print(f"{'Type':<10} {'Total':<8} {'Valid':<8} {'Invalid':<10} {'Size (MB)':<12}")
        print("-" * 50)
        for ext in sorted(validation.keys()):
            s = validation[ext]
            size_mb = s["size"] / (1024 * 1024)
            print(f"{ext:<10} {s['total']:<8} {s['valid']:<8} {s['invalid']:<10} {size_mb:>8.1f}")

        total = sum(s["total"] for s in validation.values())
        valid = sum(s["valid"] for s in validation.values())
        print(f"\nTotal: {total} files, {valid} valid")


def main():
    if len(sys.argv) < 3:
        print("Usage: agent.py <image_path> <output_dir> [file_types]")
        print("  file_types: comma-separated (e.g., jpg,pdf,doc) or 'all'")
        sys.exit(1)

    image_path = sys.argv[1]
    output_dir = sys.argv[2]
    file_types = sys.argv[3] if len(sys.argv) > 3 else "all"

    agent = FileCarvingAgent(output_dir)
    carved_dir = agent.run_foremost(image_path, file_types)
    agent.remove_zero_byte_files(carved_dir)
    agent.build_evidence_catalog(carved_dir)
    agent.generate_report(carved_dir)


if __name__ == "__main__":
    main()
