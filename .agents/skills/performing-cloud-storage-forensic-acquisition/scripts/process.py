#!/usr/bin/env python3
"""
Cloud Storage Forensic Acquisition Processor

Collects and analyzes local cloud storage sync client artifacts
from endpoint devices for OneDrive, Google Drive, and Dropbox.
"""

import sqlite3
import os
import sys
import json
import hashlib
from datetime import datetime
from pathlib import Path


class CloudStorageArtifactCollector:
    """Collect and analyze local cloud storage sync artifacts."""

    def __init__(self, evidence_root: str, output_dir: str):
        self.evidence_root = Path(evidence_root)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = {}

    def find_onedrive_artifacts(self) -> dict:
        """Locate and parse OneDrive sync artifacts."""
        onedrive_paths = [
            "AppData/Local/Microsoft/OneDrive/settings",
            "AppData/Local/Microsoft/OneDrive/logs",
        ]
        artifacts = {"databases": [], "logs": [], "config_files": []}

        for user_dir in self.evidence_root.glob("Users/*"):
            for rel_path in onedrive_paths:
                full_path = user_dir / rel_path
                if full_path.exists():
                    for f in full_path.rglob("*"):
                        if f.is_file():
                            category = "databases" if f.suffix in (".db", ".dat") else "logs"
                            artifacts[category].append(str(f))

        # Try to parse SyncEngineDatabase
        for db_path in artifacts["databases"]:
            if "SyncEngineDatabase" in db_path:
                try:
                    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                    cursor = conn.cursor()
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    artifacts["sync_tables"] = [r[0] for r in cursor.fetchall()]
                    conn.close()
                except Exception as e:
                    artifacts["sync_error"] = str(e)

        return artifacts

    def find_google_drive_artifacts(self) -> dict:
        """Locate and parse Google Drive FS artifacts."""
        artifacts = {"databases": [], "cache_files": [], "logs": []}

        for user_dir in self.evidence_root.glob("Users/*"):
            gdrive_path = user_dir / "AppData/Local/Google/DriveFS"
            if gdrive_path.exists():
                for f in gdrive_path.rglob("*"):
                    if f.is_file():
                        if "metadata_sqlite_db" in f.name:
                            artifacts["databases"].append(str(f))
                        elif "content_cache" in str(f):
                            artifacts["cache_files"].append(str(f))
                        elif f.suffix == ".log":
                            artifacts["logs"].append(str(f))

        return artifacts

    def find_dropbox_artifacts(self) -> dict:
        """Locate and parse Dropbox artifacts."""
        artifacts = {"databases": [], "cache_files": [], "config": []}

        for user_dir in self.evidence_root.glob("Users/*"):
            dropbox_path = user_dir / "AppData/Local/Dropbox"
            if dropbox_path.exists():
                for f in dropbox_path.rglob("*"):
                    if f.is_file():
                        if f.suffix in (".dbx", ".db"):
                            artifacts["databases"].append(str(f))
                        elif "cache" in str(f).lower():
                            artifacts["cache_files"].append(str(f))

            dropbox_cache = user_dir / "Dropbox/.dropbox.cache"
            if dropbox_cache.exists():
                for f in dropbox_cache.rglob("*"):
                    if f.is_file():
                        artifacts["cache_files"].append(str(f))

        return artifacts

    def generate_report(self) -> str:
        """Generate comprehensive cloud storage artifact report."""
        self.findings = {
            "analysis_timestamp": datetime.now().isoformat(),
            "evidence_root": str(self.evidence_root),
            "onedrive": self.find_onedrive_artifacts(),
            "google_drive": self.find_google_drive_artifacts(),
            "dropbox": self.find_dropbox_artifacts(),
        }

        report_path = self.output_dir / "cloud_storage_artifacts.json"
        with open(report_path, "w") as f:
            json.dump(self.findings, f, indent=2)

        for service in ["onedrive", "google_drive", "dropbox"]:
            data = self.findings[service]
            db_count = len(data.get("databases", []))
            print(f"[*] {service}: {db_count} databases found")

        print(f"[*] Report: {report_path}")
        return str(report_path)


def main():
    if len(sys.argv) < 3:
        print("Usage: python process.py <evidence_root> <output_dir>")
        sys.exit(1)
    collector = CloudStorageArtifactCollector(sys.argv[1], sys.argv[2])
    collector.generate_report()


if __name__ == "__main__":
    main()
