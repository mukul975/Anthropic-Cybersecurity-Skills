#!/usr/bin/env python3
"""
MFT Deleted File Recovery Analyzer

Parses MFT CSV output from MFTECmd to identify deleted files,
detect timestomping, and generate recovery reports.
"""

import csv
import json
import sys
import os
from datetime import datetime
from collections import defaultdict


class MFTDeletedFileAnalyzer:
    """Analyze MFTECmd CSV output for deleted file recovery."""

    def __init__(self, mft_csv_path: str, output_dir: str):
        self.mft_csv_path = mft_csv_path
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.deleted_files = []
        self.timestomped_files = []
        self.all_records = []

    def parse_csv(self):
        """Parse MFTECmd CSV output."""
        with open(self.mft_csv_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.all_records.append(row)
                if row.get("InUse", "").lower() == "false":
                    self.deleted_files.append(row)

    def detect_timestomping(self):
        """Identify files with timestomping indicators."""
        for row in self.all_records:
            si_created = row.get("Created0x10", "")
            fn_created = row.get("Created0x30", "")
            if si_created and fn_created and si_created != fn_created:
                try:
                    si_dt = datetime.fromisoformat(si_created.replace("Z", "+00:00"))
                    fn_dt = datetime.fromisoformat(fn_created.replace("Z", "+00:00"))
                    if si_dt < fn_dt:
                        self.timestomped_files.append({
                            "entry_number": row.get("EntryNumber", ""),
                            "filename": row.get("FileName", ""),
                            "parent_path": row.get("ParentPath", ""),
                            "si_created": si_created,
                            "fn_created": fn_created,
                            "delta_seconds": (fn_dt - si_dt).total_seconds()
                        })
                except (ValueError, TypeError):
                    continue

    def analyze_deleted_by_extension(self) -> dict:
        """Categorize deleted files by extension."""
        by_ext = defaultdict(list)
        for record in self.deleted_files:
            ext = record.get("Extension", "NO_EXT").upper()
            by_ext[ext].append({
                "filename": record.get("FileName", ""),
                "parent_path": record.get("ParentPath", ""),
                "file_size": record.get("FileSize", ""),
                "created": record.get("Created0x10", ""),
                "modified": record.get("LastModified0x10", "")
            })
        return dict(by_ext)

    def generate_report(self) -> str:
        """Generate comprehensive analysis report."""
        self.parse_csv()
        self.detect_timestomping()
        ext_analysis = self.analyze_deleted_by_extension()

        report = {
            "analysis_timestamp": datetime.now().isoformat(),
            "source_file": self.mft_csv_path,
            "total_records": len(self.all_records),
            "deleted_records": len(self.deleted_files),
            "timestomped_records": len(self.timestomped_files),
            "deleted_by_extension": {k: len(v) for k, v in ext_analysis.items()},
            "timestomping_details": self.timestomped_files[:50],
            "notable_deleted_files": [
                {
                    "filename": r.get("FileName", ""),
                    "parent_path": r.get("ParentPath", ""),
                    "file_size": r.get("FileSize", ""),
                    "entry_number": r.get("EntryNumber", "")
                }
                for r in self.deleted_files[:100]
            ]
        }

        report_path = os.path.join(self.output_dir, "mft_deleted_analysis.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"[*] Total MFT records: {report['total_records']}")
        print(f"[*] Deleted records: {report['deleted_records']}")
        print(f"[*] Timestomped records: {report['timestomped_records']}")
        print(f"[*] Report saved to: {report_path}")
        return report_path


def main():
    if len(sys.argv) < 3:
        print("Usage: python process.py <mft_csv_path> <output_dir>")
        sys.exit(1)

    analyzer = MFTDeletedFileAnalyzer(sys.argv[1], sys.argv[2])
    analyzer.generate_report()


if __name__ == "__main__":
    main()
