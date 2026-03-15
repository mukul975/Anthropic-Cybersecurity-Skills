#!/usr/bin/env python3
"""Forensic timeline reconstruction agent using Plaso subprocess wrappers."""

import subprocess
import os
import sys
import csv
import json
from datetime import datetime
from collections import defaultdict
from pathlib import Path


def verify_plaso_installed():
    """Check that log2timeline.py and psort.py are available."""
    tools = {}
    for tool in ["log2timeline.py", "psort.py"]:
        result = subprocess.run(
            [tool, "--version"], capture_output=True, text=True
        )
        tools[tool] = result.stdout.strip() if result.returncode == 0 else None
    return tools


def run_log2timeline(image_path, storage_file, parsers=None, filter_file=None):
    """Execute log2timeline.py to generate Plaso storage file."""
    cmd = ["log2timeline.py", "--storage-file", storage_file]
    if parsers:
        cmd.extend(["--parsers", parsers])
    if filter_file:
        cmd.extend(["--filter-file", filter_file])
    cmd.append(image_path)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
    return {
        "command": " ".join(cmd),
        "returncode": result.returncode,
        "stdout": result.stdout[-500:] if result.stdout else "",
        "stderr": result.stderr[-500:] if result.stderr else "",
    }


def run_psort_export(storage_file, output_file, output_format="l2tcsv",
                     date_filter=None):
    """Export timeline from Plaso storage using psort.py."""
    cmd = ["psort.py", "-o", output_format, "-w", output_file, storage_file]
    if date_filter:
        cmd.append(date_filter)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    return {
        "command": " ".join(cmd),
        "returncode": result.returncode,
        "output_file": output_file,
        "stdout": result.stdout[-500:] if result.stdout else "",
    }


def create_filter_file(filter_path, paths=None):
    """Create a Plaso filter file for targeted parsing."""
    if paths is None:
        paths = [
            "/Windows/System32/winevt/Logs",
            "/Windows/Prefetch",
            "/Users/*/NTUSER.DAT",
            "/Users/*/AppData/Local/Google/Chrome",
            "/Users/*/AppData/Roaming/Mozilla/Firefox",
            "/$MFT",
            "/$UsnJrnl:$J",
            "/Windows/System32/config",
        ]
    with open(filter_path, "w") as f:
        f.write("\n".join(paths) + "\n")
    return filter_path


def analyze_timeline_csv(csv_path, max_rows=500000):
    """Analyze exported timeline CSV for patterns and anomalies."""
    events_by_hour = defaultdict(int)
    source_counts = defaultdict(int)
    total = 0
    with open(csv_path, "r", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if total >= max_rows:
                break
            total += 1
            source = row.get("source_short", row.get("source", "Unknown"))
            source_counts[source] += 1
            timestamp = row.get("datetime", row.get("date", ""))
            try:
                dt = datetime.strptime(timestamp[:19], "%Y-%m-%dT%H:%M:%S")
                hour_key = dt.strftime("%Y-%m-%d %H:00")
                events_by_hour[hour_key] += 1
            except (ValueError, TypeError):
                pass
    avg_per_hour = total / max(len(events_by_hour), 1)
    spikes = {
        h: c for h, c in events_by_hour.items() if c > avg_per_hour * 3
    }
    return {
        "total_events": total,
        "source_counts": dict(sorted(source_counts.items(), key=lambda x: -x[1])),
        "spike_hours": dict(sorted(spikes.items())),
        "unique_hours": len(events_by_hour),
        "avg_events_per_hour": round(avg_per_hour, 1),
    }


def generate_incident_window(storage_file, output_dir, start_date, end_date):
    """Export events within a specific incident time window."""
    output_file = os.path.join(output_dir, "incident_window.csv")
    date_filter = f"date > '{start_date}' AND date < '{end_date}'"
    return run_psort_export(storage_file, output_file, date_filter=date_filter)


def full_pipeline(image_path, output_dir, parsers=None, start_date=None, end_date=None):
    """Run the full timeline reconstruction pipeline."""
    os.makedirs(output_dir, exist_ok=True)
    storage_file = os.path.join(output_dir, "evidence.plaso")
    if parsers is None:
        parsers = "winevtx,prefetch,mft,usnjrnl,lnk,recycle_bin,chrome_history,firefox_history,winreg"
    filter_path = os.path.join(output_dir, "filter.txt")
    create_filter_file(filter_path)
    results = {"steps": []}
    l2t_result = run_log2timeline(image_path, storage_file, parsers=parsers, filter_file=filter_path)
    results["steps"].append({"step": "log2timeline", **l2t_result})
    if l2t_result["returncode"] != 0:
        results["error"] = "log2timeline failed"
        return results
    full_csv = os.path.join(output_dir, "full_timeline.csv")
    export_result = run_psort_export(storage_file, full_csv)
    results["steps"].append({"step": "psort_export", **export_result})
    if os.path.exists(full_csv):
        results["analysis"] = analyze_timeline_csv(full_csv)
    if start_date and end_date:
        window_result = generate_incident_window(storage_file, output_dir, start_date, end_date)
        results["steps"].append({"step": "incident_window", **window_result})
        window_csv = os.path.join(output_dir, "incident_window.csv")
        if os.path.exists(window_csv):
            results["incident_analysis"] = analyze_timeline_csv(window_csv)
    jsonl_output = os.path.join(output_dir, "timeline.jsonl")
    run_psort_export(storage_file, jsonl_output, output_format="json_line")
    return results


def print_report(results):
    print("Timeline Reconstruction Report")
    print("=" * 50)
    for step in results.get("steps", []):
        status = "OK" if step.get("returncode") == 0 else "FAILED"
        print(f"  [{status}] {step['step']}: {step.get('command', '')[:80]}")
    if "analysis" in results:
        a = results["analysis"]
        print(f"\nTotal Events: {a['total_events']}")
        print(f"Avg/Hour: {a['avg_events_per_hour']}")
        print("\nSource Breakdown:")
        for src, cnt in list(a["source_counts"].items())[:10]:
            print(f"  {src:15s}: {cnt:>8}")
        if a["spike_hours"]:
            print("\nActivity Spikes:")
            for hour, cnt in a["spike_hours"].items():
                print(f"  {hour}: {cnt} events")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python agent.py <disk_image> <output_dir> [start_date] [end_date]")
        sys.exit(1)
    image = sys.argv[1]
    out_dir = sys.argv[2]
    start = sys.argv[3] if len(sys.argv) > 3 else None
    end = sys.argv[4] if len(sys.argv) > 4 else None
    result = full_pipeline(image, out_dir, start_date=start, end_date=end)
    print_report(result)
