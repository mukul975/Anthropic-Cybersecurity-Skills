#!/usr/bin/env python3
"""
AFL++ Fuzzing Results Analyzer

Parses AFL++ output directories and generates reports on
crash findings, corpus growth, and coverage statistics.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from collections import defaultdict


def parse_fuzzer_stats(stats_file: str) -> dict:
    stats = {}
    if not os.path.exists(stats_file):
        return stats
    with open(stats_file) as f:
        for line in f:
            line = line.strip()
            if ":" in line:
                key, value = line.split(":", 1)
                stats[key.strip()] = value.strip()
    return stats


def count_files_in_dir(directory: str) -> int:
    if not os.path.isdir(directory):
        return 0
    return len([f for f in os.listdir(directory) if f != "README.txt" and os.path.isfile(os.path.join(directory, f))])


def analyze_fuzzer_instance(instance_dir: str) -> dict:
    name = os.path.basename(instance_dir)
    stats = parse_fuzzer_stats(os.path.join(instance_dir, "fuzzer_stats"))

    return {
        "name": name,
        "start_time": stats.get("start_time", ""),
        "last_update": stats.get("last_update", ""),
        "execs_done": int(stats.get("execs_done", 0)),
        "execs_per_sec": float(stats.get("execs_per_sec", 0)),
        "corpus_count": count_files_in_dir(os.path.join(instance_dir, "queue")),
        "crashes_total": count_files_in_dir(os.path.join(instance_dir, "crashes")),
        "hangs_total": count_files_in_dir(os.path.join(instance_dir, "hangs")),
        "paths_total": int(stats.get("paths_total", 0)),
        "paths_found": int(stats.get("paths_found", 0)),
        "stability": stats.get("stability", ""),
        "cycles_done": int(stats.get("cycles_done", 0)),
        "bitmap_cvg": stats.get("bitmap_cvg", ""),
        "command_line": stats.get("command_line", ""),
    }


def collect_crash_info(instance_dir: str) -> list:
    crashes_dir = os.path.join(instance_dir, "crashes")
    crashes = []
    if not os.path.isdir(crashes_dir):
        return crashes
    for fname in sorted(os.listdir(crashes_dir)):
        if fname == "README.txt":
            continue
        fpath = os.path.join(crashes_dir, fname)
        if os.path.isfile(fpath):
            crashes.append({
                "file": fname,
                "path": fpath,
                "size": os.path.getsize(fpath),
                "instance": os.path.basename(instance_dir),
            })
    return crashes


def analyze_campaign(findings_dir: str) -> dict:
    report = {
        "findings_dir": findings_dir,
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
        "instances": [],
        "total_execs": 0,
        "total_crashes": 0,
        "total_hangs": 0,
        "total_corpus": 0,
        "all_crashes": [],
        "avg_execs_per_sec": 0,
    }

    instance_dirs = []
    for entry in sorted(os.listdir(findings_dir)):
        full_path = os.path.join(findings_dir, entry)
        if os.path.isdir(full_path) and os.path.exists(os.path.join(full_path, "fuzzer_stats")):
            instance_dirs.append(full_path)

    if not instance_dirs:
        print(f"No fuzzer instances found in {findings_dir}")
        return report

    exec_speeds = []
    for inst_dir in instance_dirs:
        inst = analyze_fuzzer_instance(inst_dir)
        report["instances"].append(inst)
        report["total_execs"] += inst["execs_done"]
        report["total_crashes"] += inst["crashes_total"]
        report["total_hangs"] += inst["hangs_total"]
        report["total_corpus"] += inst["corpus_count"]
        if inst["execs_per_sec"] > 0:
            exec_speeds.append(inst["execs_per_sec"])

        crashes = collect_crash_info(inst_dir)
        report["all_crashes"].extend(crashes)

    if exec_speeds:
        report["avg_execs_per_sec"] = round(sum(exec_speeds) / len(exec_speeds), 1)

    return report


def print_report(report: dict) -> None:
    print(f"\n{'='*60}")
    print(f"AFL++ Fuzzing Campaign Report")
    print(f"{'='*60}")
    print(f"Findings directory: {report['findings_dir']}")
    print(f"Analyzed at: {report['analyzed_at']}")
    print(f"Fuzzer instances: {len(report['instances'])}")
    print(f"\nAggregate Statistics:")
    print(f"  Total executions: {report['total_execs']:,}")
    print(f"  Avg exec/sec: {report['avg_execs_per_sec']:,.1f}")
    print(f"  Total corpus entries: {report['total_corpus']}")
    print(f"  Total unique crashes: {report['total_crashes']}")
    print(f"  Total hangs: {report['total_hangs']}")

    print(f"\nInstance Details:")
    for inst in report["instances"]:
        print(f"  {inst['name']:20s} | Execs: {inst['execs_done']:>12,} | "
              f"Speed: {inst['execs_per_sec']:>8.1f}/s | "
              f"Crashes: {inst['crashes_total']:3d} | "
              f"Corpus: {inst['corpus_count']:5d} | "
              f"Cycles: {inst['cycles_done']}")

    if report["all_crashes"]:
        print(f"\nCrash Files ({len(report['all_crashes'])} total):")
        for crash in report["all_crashes"][:20]:
            print(f"  [{crash['instance']}] {crash['file']} ({crash['size']} bytes)")
        if len(report["all_crashes"]) > 20:
            print(f"  ... and {len(report['all_crashes']) - 20} more")

    verdict = "PASS" if report["total_crashes"] == 0 else "FAIL"
    print(f"\nCI Verdict: {verdict}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python process.py <findings_directory>")
        sys.exit(1)

    findings_dir = sys.argv[1]
    if not os.path.isdir(findings_dir):
        print(f"Directory not found: {findings_dir}")
        sys.exit(1)

    report = analyze_campaign(findings_dir)
    print_report(report)

    output = os.path.join(findings_dir, "campaign_report.json")
    with open(output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\nReport saved to: {output}")

    sys.exit(1 if report["total_crashes"] > 0 else 0)


if __name__ == "__main__":
    main()
