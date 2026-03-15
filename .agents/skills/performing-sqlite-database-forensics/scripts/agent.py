#!/usr/bin/env python3
"""Agent for SQLite database forensics.

Parses SQLite file headers, analyzes freelist pages for deleted records,
examines WAL files, decodes browser/app timestamps, and extracts
evidence from common forensic databases.
"""

import struct
import sqlite3
import json
import sys
import os
from datetime import datetime, timedelta
from pathlib import Path


class SQLiteForensicsAgent:
    """Performs forensic analysis on SQLite database files."""

    def __init__(self, db_path, output_dir="./sqlite_forensics"):
        self.db_path = db_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def parse_header(self):
        """Parse the 100-byte SQLite database header."""
        with open(self.db_path, "rb") as f:
            header = f.read(100)

        magic = header[0:16]
        if magic != b"SQLite format 3\x00":
            return {"error": "Not a valid SQLite database"}

        page_size = struct.unpack(">H", header[16:18])[0]
        if page_size == 1:
            page_size = 65536

        return {
            "magic": magic[:15].decode("ascii"),
            "page_size": page_size,
            "write_format": header[18],
            "read_format": header[19],
            "change_counter": struct.unpack(">I", header[24:28])[0],
            "db_size_pages": struct.unpack(">I", header[28:32])[0],
            "first_freelist_page": struct.unpack(">I", header[32:36])[0],
            "total_freelist_pages": struct.unpack(">I", header[36:40])[0],
            "schema_cookie": struct.unpack(">I", header[40:44])[0],
            "text_encoding": {1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}.get(
                struct.unpack(">I", header[52:56])[0], "unknown"),
            "db_size_bytes": os.path.getsize(self.db_path),
        }

    def analyze_freelist(self):
        """Walk freelist trunk chain to identify pages with deleted data."""
        with open(self.db_path, "rb") as f:
            header = f.read(100)
            page_size = struct.unpack(">H", header[16:18])[0]
            if page_size == 1:
                page_size = 65536
            first_trunk = struct.unpack(">I", header[32:36])[0]
            total_free = struct.unpack(">I", header[36:40])[0]

            if first_trunk == 0:
                return {"freelist_pages": 0, "trunk_pages": [], "leaf_pages": []}

            trunk_pages, leaf_pages = [], []
            trunk = first_trunk
            while trunk != 0:
                offset = (trunk - 1) * page_size
                f.seek(offset)
                page_data = f.read(page_size)
                next_trunk = struct.unpack(">I", page_data[0:4])[0]
                leaf_count = struct.unpack(">I", page_data[4:8])[0]
                leaves = []
                for i in range(leaf_count):
                    lp = struct.unpack(">I", page_data[8 + i * 4:12 + i * 4])[0]
                    leaves.append(lp)
                trunk_pages.append({"page": trunk, "leaf_count": leaf_count})
                leaf_pages.extend(leaves)
                trunk = next_trunk

        if leaf_pages:
            self.findings.append({"type": "freelist_data",
                                  "pages": len(leaf_pages),
                                  "note": "Deleted records may be recoverable"})
        return {"freelist_pages": total_free,
                "trunk_pages": trunk_pages, "leaf_pages": leaf_pages}

    def extract_freelist_pages(self):
        """Dump raw freelist leaf pages for hex analysis."""
        info = self.analyze_freelist()
        with open(self.db_path, "rb") as f:
            hdr = f.read(100)
            page_size = struct.unpack(">H", hdr[16:18])[0]
            if page_size == 1:
                page_size = 65536
            out_dir = self.output_dir / "freelist_pages"
            out_dir.mkdir(exist_ok=True)
            for pn in info["leaf_pages"]:
                f.seek((pn - 1) * page_size)
                data = f.read(page_size)
                (out_dir / f"page_{pn}.bin").write_bytes(data)
        return len(info["leaf_pages"])

    def parse_wal(self):
        """Parse WAL file frames for transaction history."""
        wal_path = self.db_path + "-wal"
        if not os.path.exists(wal_path):
            return {"wal_exists": False}

        with open(wal_path, "rb") as f:
            header = f.read(32)
            magic = struct.unpack(">I", header[0:4])[0]
            page_size = struct.unpack(">I", header[8:12])[0]
            checkpoint_seq = struct.unpack(">I", header[12:16])[0]
            file_size = os.path.getsize(wal_path)

            frames = []
            offset = 32
            frame_num = 0
            while offset + 24 + page_size <= file_size:
                f.seek(offset)
                fh = f.read(24)
                page_number = struct.unpack(">I", fh[0:4])[0]
                frames.append({"frame": frame_num, "page": page_number,
                                "offset": offset})
                offset += 24 + page_size
                frame_num += 1

        return {"wal_exists": True, "magic": hex(magic),
                "page_size": page_size, "checkpoint_seq": checkpoint_seq,
                "total_frames": len(frames), "frames": frames[:50]}

    def query_tables(self):
        """List all tables and row counts in the database."""
        conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = []
        for (name,) in cursor.fetchall():
            try:
                cursor.execute(f'SELECT COUNT(*) FROM "{name}"')
                count = cursor.fetchone()[0]
            except sqlite3.OperationalError:
                count = -1
            tables.append({"table": name, "row_count": count})
        conn.close()
        return tables

    @staticmethod
    def decode_timestamp(value, fmt="unix"):
        """Decode timestamps from common database formats."""
        try:
            if fmt == "unix":
                return datetime.utcfromtimestamp(value).isoformat()
            elif fmt == "chrome":
                epoch_delta = 11644473600
                return datetime.utcfromtimestamp(
                    (value / 1_000_000) - epoch_delta).isoformat()
            elif fmt == "mac_absolute":
                mac_epoch = datetime(2001, 1, 1)
                return (mac_epoch + timedelta(seconds=value)).isoformat()
            elif fmt == "mozilla":
                return datetime.utcfromtimestamp(value / 1_000_000).isoformat()
        except (OSError, ValueError, OverflowError):
            return None

    def generate_report(self):
        """Generate comprehensive forensic analysis report."""
        report = {
            "database": self.db_path,
            "analysis_date": datetime.utcnow().isoformat(),
            "header": self.parse_header(),
            "tables": self.query_tables(),
            "freelist": self.analyze_freelist(),
            "wal": self.parse_wal(),
            "findings": self.findings,
        }
        report_path = self.output_dir / "sqlite_forensics_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <database.db> [output_dir]")
        sys.exit(1)
    db_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "./sqlite_forensics"
    agent = SQLiteForensicsAgent(db_path, output_dir)
    agent.generate_report()


if __name__ == "__main__":
    main()
