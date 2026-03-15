#!/usr/bin/env python3
"""Agent for Windows artifact analysis with Eric Zimmerman tools.

Runs EZ tools (MFTECmd, PECmd, LECmd, JLECmd, ShellBags Explorer CLI)
via subprocess, parses CSV output, and builds a forensic timeline
from Windows filesystem and registry artifacts.
"""

import subprocess
import json
import sys
import csv
import io
from datetime import datetime
from pathlib import Path


class EZToolsAgent:
    """Analyzes Windows forensic artifacts using Eric Zimmerman tools."""

    def __init__(self, output_dir="./ez_analysis"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeline = []

    def _run_tool(self, tool, args, timeout=300):
        cmd = [tool] + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return {"return_code": result.returncode,
                    "stdout_lines": len(result.stdout.splitlines()),
                    "stderr": result.stderr[:300] if result.stderr else ""}
        except FileNotFoundError:
            return {"error": f"{tool} not found. Download from https://ericzimmerman.github.io/"}
        except subprocess.TimeoutExpired:
            return {"error": f"{tool} timed out"}

    def parse_mft(self, mft_path):
        """Parse $MFT using MFTECmd and extract file creation/modification."""
        csv_out = self.output_dir / "mft_output.csv"
        result = self._run_tool("MFTECmd.exe", ["-f", mft_path,
                                                  "--csv", str(self.output_dir),
                                                  "--csvf", "mft_output.csv"])
        if "error" in result:
            return result
        return self._parse_csv(csv_out, "MFT",
                               time_cols=["Created0x10", "LastModified0x10"])

    def parse_prefetch(self, prefetch_dir):
        """Parse Prefetch files using PECmd for program execution evidence."""
        csv_out = self.output_dir / "prefetch_output.csv"
        result = self._run_tool("PECmd.exe", ["-d", prefetch_dir,
                                               "--csv", str(self.output_dir),
                                               "--csvf", "prefetch_output.csv"])
        if "error" in result:
            return result
        return self._parse_csv(csv_out, "Prefetch",
                               time_cols=["LastRun", "PreviousRun0"])

    def parse_lnk_files(self, lnk_dir):
        """Parse LNK shortcut files using LECmd."""
        csv_out = self.output_dir / "lnk_output.csv"
        result = self._run_tool("LECmd.exe", ["-d", lnk_dir,
                                               "--csv", str(self.output_dir),
                                               "--csvf", "lnk_output.csv"])
        if "error" in result:
            return result
        return self._parse_csv(csv_out, "LNK",
                               time_cols=["TargetCreated", "TargetModified"])

    def parse_jump_lists(self, jl_dir):
        """Parse Jump Lists using JLECmd for recent file access."""
        csv_out = self.output_dir / "jumplist_output.csv"
        result = self._run_tool("JLECmd.exe", ["-d", jl_dir,
                                                "--csv", str(self.output_dir),
                                                "--csvf", "jumplist_output.csv"])
        if "error" in result:
            return result
        return self._parse_csv(csv_out, "JumpList",
                               time_cols=["TargetCreated", "TargetModified"])

    def parse_shellbags(self, registry_hive):
        """Parse ShellBags from NTUSER.DAT/UsrClass.dat."""
        csv_out = self.output_dir / "shellbags_output.csv"
        result = self._run_tool("SBECmd.exe", ["-d", registry_hive,
                                                "--csv", str(self.output_dir),
                                                "--csvf", "shellbags_output.csv"])
        if "error" in result:
            return result
        return self._parse_csv(csv_out, "ShellBag",
                               time_cols=["LastWriteTime", "FirstExplored"])

    def _parse_csv(self, csv_path, artifact_type, time_cols=None):
        """Parse EZ tool CSV output into timeline entries."""
        if not csv_path.exists():
            return {"error": f"CSV not found: {csv_path}"}
        entries = []
        try:
            with open(csv_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    entry = {"artifact_type": artifact_type}
                    for key, val in row.items():
                        if val:
                            entry[key] = val
                    if time_cols:
                        for tc in time_cols:
                            ts = row.get(tc, "")
                            if ts:
                                entry["timestamp"] = ts
                                self.timeline.append({
                                    "timestamp": ts,
                                    "artifact": artifact_type,
                                    "source": csv_path.name,
                                    "details": {k: v for k, v in row.items()
                                                if v and k != tc}
                                })
                                break
                    entries.append(entry)
        except (csv.Error, UnicodeDecodeError) as exc:
            return {"error": str(exc)}
        return {"artifact": artifact_type, "entries": len(entries)}

    def build_timeline(self):
        """Sort all collected entries into a unified forensic timeline."""
        self.timeline.sort(key=lambda x: x.get("timestamp", ""))
        return self.timeline

    def generate_report(self):
        self.build_timeline()
        report = {
            "report_date": datetime.utcnow().isoformat(),
            "total_timeline_entries": len(self.timeline),
            "timeline_sample": self.timeline[:50],
        }
        report_path = self.output_dir / "ez_tools_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    if len(sys.argv) < 3:
        print("Usage: agent.py <artifact_type> <path>")
        print("  artifact_type: mft|prefetch|lnk|jumplist|shellbag")
        sys.exit(1)
    agent = EZToolsAgent()
    atype = sys.argv[1]
    path = sys.argv[2]
    dispatch = {"mft": agent.parse_mft, "prefetch": agent.parse_prefetch,
                "lnk": agent.parse_lnk_files, "jumplist": agent.parse_jump_lists,
                "shellbag": agent.parse_shellbags}
    fn = dispatch.get(atype)
    if fn:
        fn(path)
    agent.generate_report()


if __name__ == "__main__":
    main()
