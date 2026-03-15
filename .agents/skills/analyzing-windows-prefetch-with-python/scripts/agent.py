#!/usr/bin/env python3
"""Agent for analyzing Windows Prefetch files with Python.

Parses Prefetch (.pf) files to reconstruct execution history,
detect renamed/masquerading binaries, and identify suspicious
tool execution using the windowsprefetch library.
"""

import argparse
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

try:
    import windowsprefetch
except ImportError:
    windowsprefetch = None

SUSPICIOUS_EXECUTABLES = {
    "mimikatz", "psexec", "psexesvc", "procdump", "lazagne",
    "rubeus", "sharphound", "bloodhound", "cobalt", "beacon",
    "meterpreter", "powersploit", "empire", "covenant",
    "secretsdump", "wce", "fgdump", "pwdump", "gsecdump",
    "certutil", "bitsadmin", "mshta", "regsvr32", "rundll32",
    "wscript", "cscript", "msiexec", "installutil",
}

LOLBINS = {
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "wscript.exe", "cscript.exe", "msiexec.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe", "msconfig.exe",
    "esentutl.exe", "expand.exe", "extrac32.exe", "findstr.exe",
    "hh.exe", "ie4uinit.exe", "makecab.exe", "replace.exe",
}


class PrefetchAnalyzer:
    """Analyzes Windows Prefetch files for forensic investigation."""

    def __init__(self, output_dir="./prefetch_analysis"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []
        self.executions = []

    def parse_prefetch_file(self, pf_path):
        """Parse a single Prefetch file and extract execution data."""
        if windowsprefetch is None:
            raise RuntimeError("windowsprefetch not installed: pip install windowsprefetch")
        try:
            pf = windowsprefetch.Prefetch(pf_path)
        except Exception:
            return None

        timestamps = []
        if hasattr(pf, "lastRunTime"):
            timestamps.append(str(pf.lastRunTime))
        if hasattr(pf, "timestamps"):
            timestamps.extend([str(t) for t in pf.timestamps])

        resources = []
        if hasattr(pf, "resources"):
            resources = pf.resources if isinstance(pf.resources, list) else []
        elif hasattr(pf, "filenames"):
            resources = pf.filenames if isinstance(pf.filenames, list) else []

        volumes = []
        if hasattr(pf, "volumes"):
            for v in pf.volumes:
                volumes.append({
                    "name": getattr(v, "name", str(v)),
                    "serial": getattr(v, "serialNumber", ""),
                })

        entry = {
            "file": str(pf_path),
            "executable": pf.executableName if hasattr(pf, "executableName") else Path(pf_path).stem,
            "run_count": pf.runCount if hasattr(pf, "runCount") else 0,
            "last_run_time": timestamps[0] if timestamps else "",
            "all_timestamps": timestamps,
            "pf_hash": Path(pf_path).stem.split("-")[-1] if "-" in Path(pf_path).stem else "",
            "resources_count": len(resources),
            "volumes": volumes,
            "file_size": os.path.getsize(pf_path),
            "file_sha256": self._hash_file(pf_path),
        }
        self.executions.append(entry)
        return entry

    def _hash_file(self, path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def parse_directory(self, prefetch_dir):
        """Parse all .pf files in a directory."""
        pf_dir = Path(prefetch_dir)
        pf_files = sorted(pf_dir.glob("*.pf"), key=lambda p: p.stat().st_mtime, reverse=True)
        for pf_file in pf_files:
            self.parse_prefetch_file(str(pf_file))
        return len(pf_files)

    def detect_suspicious(self):
        """Flag known attack tools and LOLBins."""
        for entry in self.executions:
            exe = entry["executable"].lower()
            exe_base = exe.replace(".exe", "")
            if exe_base in SUSPICIOUS_EXECUTABLES:
                self.findings.append({
                    "severity": "critical", "type": "Attack Tool Executed",
                    "detail": f"{entry['executable']} run {entry['run_count']} times, "
                              f"last: {entry['last_run_time']}",
                })
            elif exe in LOLBINS:
                if entry["run_count"] > 10:
                    self.findings.append({
                        "severity": "medium", "type": "LOLBin High Usage",
                        "detail": f"{entry['executable']} run {entry['run_count']} times",
                    })

    def detect_renamed_binaries(self):
        """Detect potential binary renaming/masquerading."""
        for entry in self.executions:
            exe = entry["executable"].upper()
            pf_name = Path(entry["file"]).stem.upper()
            expected_prefix = exe.replace(".EXE", "")
            if not pf_name.startswith(expected_prefix):
                self.findings.append({
                    "severity": "high", "type": "Possible Renamed Binary",
                    "detail": f"PF name '{pf_name}' does not match executable '{exe}'",
                })

    def build_timeline(self):
        """Build chronological execution timeline."""
        timeline = []
        for entry in self.executions:
            for ts in entry["all_timestamps"]:
                if ts:
                    timeline.append({
                        "timestamp": ts,
                        "executable": entry["executable"],
                        "run_count": entry["run_count"],
                    })
        timeline.sort(key=lambda x: x["timestamp"], reverse=True)
        return timeline[:100]

    def generate_report(self, prefetch_dir):
        count = self.parse_directory(prefetch_dir)
        self.detect_suspicious()
        self.detect_renamed_binaries()
        timeline = self.build_timeline()

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "prefetch_dir": str(prefetch_dir),
            "total_prefetch_files": count,
            "total_unique_executables": len(self.executions),
            "execution_history": self.executions,
            "execution_timeline": timeline[:50],
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "prefetch_analysis_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Windows Prefetch files for execution forensics"
    )
    parser.add_argument("prefetch_dir", help="Path to directory containing .pf files")
    parser.add_argument("--output-dir", default="./prefetch_analysis")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    analyzer = PrefetchAnalyzer(output_dir=args.output_dir)
    analyzer.generate_report(args.prefetch_dir)


if __name__ == "__main__":
    main()
