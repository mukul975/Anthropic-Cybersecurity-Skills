#!/usr/bin/env python3
"""
SQLite Database Forensic Analyzer

Performs forensic analysis of SQLite databases including freelist analysis,
WAL parsing, deleted record recovery, and timestamp decoding.
"""

import sqlite3
import struct
import os
import sys
import json
from datetime import datetime, timedelta
from pathlib import Path


class SQLiteForensicAnalyzer:
    """Comprehensive SQLite database forensic analysis."""

    def __init__(self, db_path: str, output_dir: str):
        self.db_path = db_path
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def parse_header(self) -> dict:
        """Parse the 100-byte SQLite database header."""
        with open(self.db_path, "rb") as f:
            header = f.read(100)

        if header[:16] != b"SQLite format 3\x00":
            return {"error": "Not a valid SQLite database"}

        page_size = struct.unpack(">H", header[16:18])[0]
        if page_size == 1:
            page_size = 65536

        return {
            "magic": header[:16].decode("ascii", errors="replace").strip("\x00"),
            "page_size": page_size,
            "write_version": header[18],
            "read_version": header[19],
            "reserved_space": header[20],
            "file_change_counter": struct.unpack(">I", header[24:28])[0],
            "database_size_pages": struct.unpack(">I", header[28:32])[0],
            "first_freelist_page": struct.unpack(">I", header[32:36])[0],
            "total_freelist_pages": struct.unpack(">I", header[36:40])[0],
            "schema_cookie": struct.unpack(">I", header[40:44])[0],
            "schema_format": struct.unpack(">I", header[44:48])[0],
            "text_encoding": {1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}.get(
                struct.unpack(">I", header[52:56])[0], "Unknown"
            ),
            "user_version": struct.unpack(">I", header[60:64])[0],
            "application_id": struct.unpack(">I", header[68:72])[0],
        }

    def get_schema(self) -> list:
        """Extract complete database schema."""
        conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        cursor.execute("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")
        schema = [
            {"type": row[0], "name": row[1], "table_name": row[2], "sql": row[3]}
            for row in cursor.fetchall()
        ]
        conn.close()
        return schema

    def get_table_stats(self) -> dict:
        """Get row counts and basic stats for all tables."""
        conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        stats = {}
        for table in tables:
            try:
                cursor.execute(f'SELECT COUNT(*) FROM "{table}"')
                count = cursor.fetchone()[0]
                cursor.execute(f'PRAGMA table_info("{table}")')
                columns = [
                    {"name": col[1], "type": col[2], "notnull": bool(col[3]), "pk": bool(col[5])}
                    for col in cursor.fetchall()
                ]
                stats[table] = {"row_count": count, "columns": columns}
            except sqlite3.OperationalError:
                stats[table] = {"error": "Could not read table"}

        conn.close()
        return stats

    def analyze_freelist(self) -> dict:
        """Analyze freelist for deleted data."""
        header = self.parse_header()
        page_size = header.get("page_size", 4096)
        first_freelist = header.get("first_freelist_page", 0)
        total_freelist = header.get("total_freelist_pages", 0)

        if first_freelist == 0:
            return {"freelist_pages": 0, "recoverable": False}

        freelist_pages = []
        with open(self.db_path, "rb") as f:
            trunk = first_freelist
            while trunk != 0:
                offset = (trunk - 1) * page_size
                f.seek(offset)
                data = f.read(page_size)
                next_trunk = struct.unpack(">I", data[0:4])[0]
                leaf_count = struct.unpack(">I", data[4:8])[0]
                leaves = []
                for i in range(min(leaf_count, (page_size - 8) // 4)):
                    leaf = struct.unpack(">I", data[8 + i * 4:12 + i * 4])[0]
                    leaves.append(leaf)
                freelist_pages.append({
                    "trunk_page": trunk,
                    "leaf_count": leaf_count,
                    "leaves": leaves
                })
                trunk = next_trunk

        return {
            "total_freelist_pages": total_freelist,
            "trunk_pages": len(freelist_pages),
            "details": freelist_pages,
            "recoverable": total_freelist > 0
        }

    def check_wal(self) -> dict:
        """Check for WAL file and analyze its contents."""
        wal_path = self.db_path + "-wal"
        if not os.path.exists(wal_path):
            return {"exists": False}

        wal_size = os.path.getsize(wal_path)
        with open(wal_path, "rb") as f:
            header = f.read(32)
            if len(header) < 32:
                return {"exists": True, "valid": False}

            magic = struct.unpack(">I", header[0:4])[0]
            page_size = struct.unpack(">I", header[8:12])[0]
            checkpoint = struct.unpack(">I", header[12:16])[0]

            frame_count = (wal_size - 32) // (24 + page_size) if page_size > 0 else 0

        return {
            "exists": True,
            "valid": magic in (0x377f0682, 0x377f0683),
            "size_bytes": wal_size,
            "page_size": page_size,
            "checkpoint_sequence": checkpoint,
            "estimated_frames": frame_count
        }

    def generate_report(self) -> str:
        """Generate comprehensive forensic analysis report."""
        report = {
            "analysis_timestamp": datetime.now().isoformat(),
            "database_path": self.db_path,
            "file_size": os.path.getsize(self.db_path),
            "header": self.parse_header(),
            "schema": self.get_schema(),
            "table_stats": self.get_table_stats(),
            "freelist": self.analyze_freelist(),
            "wal": self.check_wal(),
        }

        report_path = os.path.join(self.output_dir, "sqlite_forensic_report.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        print(f"[*] Database: {self.db_path}")
        print(f"[*] Page size: {report['header'].get('page_size', 'N/A')}")
        print(f"[*] Tables: {len(report['table_stats'])}")
        print(f"[*] Freelist pages: {report['freelist'].get('total_freelist_pages', 0)}")
        print(f"[*] WAL present: {report['wal'].get('exists', False)}")
        print(f"[*] Report: {report_path}")
        return report_path


def main():
    if len(sys.argv) < 3:
        print("Usage: python process.py <sqlite_db_path> <output_dir>")
        sys.exit(1)
    analyzer = SQLiteForensicAnalyzer(sys.argv[1], sys.argv[2])
    analyzer.generate_report()


if __name__ == "__main__":
    main()
