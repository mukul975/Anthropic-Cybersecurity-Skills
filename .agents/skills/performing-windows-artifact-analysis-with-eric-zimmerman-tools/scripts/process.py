#!/usr/bin/env python3
"""
EZ Tools Forensic Artifact Processor

Automates the execution of Eric Zimmerman's tools against collected
forensic artifacts and generates consolidated analysis reports.
"""

import subprocess
import csv
import os
import sys
import json
import hashlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict


class EZToolsProcessor:
    """Orchestrates EZ Tools processing against forensic artifact collections."""

    def __init__(self, ez_tools_path: str, evidence_path: str, output_path: str):
        self.ez_tools_path = Path(ez_tools_path)
        self.evidence_path = Path(evidence_path)
        self.output_path = Path(output_path)
        self.output_path.mkdir(parents=True, exist_ok=True)
        self.results = {}
        self.tools = {
            "MFTECmd": self.ez_tools_path / "MFTECmd.exe",
            "PECmd": self.ez_tools_path / "PECmd.exe",
            "LECmd": self.ez_tools_path / "LECmd.exe",
            "JLECmd": self.ez_tools_path / "JLECmd.exe",
            "SBECmd": self.ez_tools_path / "SBECmd.exe",
            "EvtxECmd": self.ez_tools_path / "EvtxECmd.exe",
            "RECmd": self.ez_tools_path / "RECmd.exe",
            "RBCmd": self.ez_tools_path / "RBCmd.exe",
            "AmcacheParser": self.ez_tools_path / "AmcacheParser.exe",
            "AppCompatCacheParser": self.ez_tools_path / "AppCompatCacheParser.exe",
        }

    def verify_tools(self) -> dict:
        """Verify which EZ Tools are available on the system."""
        availability = {}
        for name, path in self.tools.items():
            availability[name] = path.exists()
        return availability

    def run_tool(self, tool_name: str, args: list) -> dict:
        """Execute an EZ Tool with given arguments."""
        tool_path = self.tools.get(tool_name)
        if not tool_path or not tool_path.exists():
            return {"status": "error", "message": f"{tool_name} not found at {tool_path}"}

        cmd = [str(tool_path)] + args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            return {
                "status": "success" if result.returncode == 0 else "error",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "message": f"{tool_name} timed out after 300 seconds"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def process_mft(self, mft_path: str = None) -> dict:
        """Parse the $MFT file with MFTECmd."""
        if mft_path is None:
            mft_candidates = list(self.evidence_path.rglob("$MFT"))
            if not mft_candidates:
                return {"status": "skipped", "message": "$MFT not found"}
            mft_path = str(mft_candidates[0])

        output_file = "MFT_output.csv"
        args = ["-f", mft_path, "--csv", str(self.output_path), "--csvf", output_file]
        result = self.run_tool("MFTECmd", args)
        result["output_file"] = str(self.output_path / output_file)
        self.results["MFT"] = result
        return result

    def process_usn_journal(self, journal_path: str = None) -> dict:
        """Parse the USN Journal ($J) with MFTECmd."""
        if journal_path is None:
            j_candidates = list(self.evidence_path.rglob("$J"))
            if not j_candidates:
                return {"status": "skipped", "message": "$J not found"}
            journal_path = str(j_candidates[0])

        output_file = "USNJournal_output.csv"
        args = ["-f", journal_path, "--csv", str(self.output_path), "--csvf", output_file]
        result = self.run_tool("MFTECmd", args)
        result["output_file"] = str(self.output_path / output_file)
        self.results["USNJournal"] = result
        return result

    def process_prefetch(self, prefetch_dir: str = None) -> dict:
        """Parse Prefetch files with PECmd."""
        if prefetch_dir is None:
            pf_candidates = list(self.evidence_path.rglob("Prefetch"))
            if not pf_candidates:
                return {"status": "skipped", "message": "Prefetch directory not found"}
            prefetch_dir = str(pf_candidates[0])

        output_file = "Prefetch_output.csv"
        args = ["-d", prefetch_dir, "--csv", str(self.output_path), "--csvf", output_file]
        result = self.run_tool("PECmd", args)
        result["output_file"] = str(self.output_path / output_file)
        self.results["Prefetch"] = result
        return result

    def process_lnk_files(self, lnk_dir: str = None) -> dict:
        """Parse LNK shortcut files with LECmd."""
        if lnk_dir is None:
            recent_candidates = list(self.evidence_path.rglob("Recent"))
            if not recent_candidates:
                return {"status": "skipped", "message": "Recent directory not found"}
            lnk_dir = str(recent_candidates[0])

        output_file = "LNK_output.csv"
        args = ["-d", lnk_dir, "--csv", str(self.output_path), "--csvf", output_file]
        result = self.run_tool("LECmd", args)
        result["output_file"] = str(self.output_path / output_file)
        self.results["LNK"] = result
        return result

    def process_jump_lists(self, jl_dir: str = None) -> dict:
        """Parse Jump List files with JLECmd."""
        if jl_dir is None:
            auto_dest = list(self.evidence_path.rglob("AutomaticDestinations"))
            if not auto_dest:
                return {"status": "skipped", "message": "AutomaticDestinations not found"}
            jl_dir = str(auto_dest[0])

        output_file = "JumpLists_output.csv"
        args = ["-d", jl_dir, "--csv", str(self.output_path), "--csvf", output_file]
        result = self.run_tool("JLECmd", args)
        result["output_file"] = str(self.output_path / output_file)
        self.results["JumpLists"] = result
        return result

    def process_event_logs(self, evtx_dir: str = None) -> dict:
        """Parse Windows Event Logs with EvtxECmd."""
        if evtx_dir is None:
            logs_candidates = list(self.evidence_path.rglob("winevt"))
            if logs_candidates:
                evtx_dir = str(logs_candidates[0] / "Logs")
            else:
                evtx_files = list(self.evidence_path.rglob("*.evtx"))
                if not evtx_files:
                    return {"status": "skipped", "message": "Event logs not found"}
                evtx_dir = str(evtx_files[0].parent)

        output_file = "EventLogs_output.csv"
        args = ["-d", evtx_dir, "--csv", str(self.output_path), "--csvf", output_file]
        result = self.run_tool("EvtxECmd", args)
        result["output_file"] = str(self.output_path / output_file)
        self.results["EventLogs"] = result
        return result

    def process_shellbags(self, registry_dir: str = None) -> dict:
        """Parse Shellbag artifacts with SBECmd."""
        if registry_dir is None:
            registry_dir = str(self.evidence_path)

        output_file = "Shellbags_output.csv"
        args = ["-d", registry_dir, "--csv", str(self.output_path), "--csvf", output_file]
        result = self.run_tool("SBECmd", args)
        result["output_file"] = str(self.output_path / output_file)
        self.results["Shellbags"] = result
        return result

    def process_recycle_bin(self, recycle_dir: str = None) -> dict:
        """Parse Recycle Bin artifacts with RBCmd."""
        if recycle_dir is None:
            rb_candidates = list(self.evidence_path.rglob("$Recycle.Bin"))
            if not rb_candidates:
                return {"status": "skipped", "message": "$Recycle.Bin not found"}
            recycle_dir = str(rb_candidates[0])

        output_file = "RecycleBin_output.csv"
        args = ["-d", recycle_dir, "--csv", str(self.output_path), "--csvf", output_file]
        result = self.run_tool("RBCmd", args)
        result["output_file"] = str(self.output_path / output_file)
        self.results["RecycleBin"] = result
        return result

    def detect_timestomping(self, mft_csv_path: str) -> list:
        """Analyze MFT CSV output to detect timestomping indicators."""
        timestomped = []
        try:
            with open(mft_csv_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    si_created = row.get("Created0x10", "")
                    fn_created = row.get("Created0x30", "")
                    if si_created and fn_created:
                        try:
                            si_dt = datetime.fromisoformat(si_created.replace("Z", "+00:00"))
                            fn_dt = datetime.fromisoformat(fn_created.replace("Z", "+00:00"))
                            if si_dt < fn_dt:
                                timestomped.append({
                                    "file": row.get("FileName", "Unknown"),
                                    "entry_number": row.get("EntryNumber", ""),
                                    "si_created": si_created,
                                    "fn_created": fn_created,
                                    "indicator": "$SI Created before $FN Created"
                                })
                        except (ValueError, TypeError):
                            continue
        except FileNotFoundError:
            return [{"error": f"MFT CSV not found: {mft_csv_path}"}]
        return timestomped

    def process_all(self) -> dict:
        """Run all available EZ Tools processors against evidence."""
        print("[*] Starting comprehensive EZ Tools processing...")
        print(f"[*] Evidence path: {self.evidence_path}")
        print(f"[*] Output path: {self.output_path}")

        available = self.verify_tools()
        print(f"[*] Available tools: {sum(v for v in available.values())}/{len(available)}")

        processors = [
            ("MFT", self.process_mft),
            ("USN Journal", self.process_usn_journal),
            ("Prefetch", self.process_prefetch),
            ("LNK Files", self.process_lnk_files),
            ("Jump Lists", self.process_jump_lists),
            ("Event Logs", self.process_event_logs),
            ("Shellbags", self.process_shellbags),
            ("Recycle Bin", self.process_recycle_bin),
        ]

        for name, processor in processors:
            print(f"[*] Processing {name}...")
            result = processor()
            status = result.get("status", "unknown")
            print(f"    [{status.upper()}] {name}")

        return self.results

    def generate_report(self) -> str:
        """Generate a summary report of all processing results."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "evidence_path": str(self.evidence_path),
            "output_path": str(self.output_path),
            "results": {}
        }

        for artifact, result in self.results.items():
            report["results"][artifact] = {
                "status": result.get("status", "unknown"),
                "output_file": result.get("output_file", ""),
            }
            output_file = result.get("output_file", "")
            if output_file and os.path.exists(output_file):
                file_size = os.path.getsize(output_file)
                report["results"][artifact]["output_size_bytes"] = file_size
                with open(output_file, "rb") as f:
                    report["results"][artifact]["sha256"] = hashlib.sha256(f.read()).hexdigest()

        report_path = self.output_path / "processing_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n[*] Report saved to: {report_path}")
        return str(report_path)


def main():
    if len(sys.argv) < 4:
        print("Usage: python process.py <ez_tools_path> <evidence_path> <output_path>")
        print("Example: python process.py C:\\Tools\\EZTools C:\\Cases\\Evidence C:\\Cases\\Output")
        sys.exit(1)

    ez_tools_path = sys.argv[1]
    evidence_path = sys.argv[2]
    output_path = sys.argv[3]

    processor = EZToolsProcessor(ez_tools_path, evidence_path, output_path)
    processor.process_all()
    processor.generate_report()


if __name__ == "__main__":
    main()
