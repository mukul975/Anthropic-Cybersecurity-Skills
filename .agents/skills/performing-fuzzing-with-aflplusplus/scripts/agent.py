#!/usr/bin/env python3
# For authorized testing only
"""AFL++ fuzzing campaign management and crash triage agent."""

import json
import sys
import argparse
import os
import subprocess
import glob
from datetime import datetime


def instrument_target(source_path, output_path, compiler="afl-clang-fast",
                      sanitizer=None):
    """Compile target with AFL++ instrumentation."""
    cmd = [compiler, "-o", output_path, source_path]
    if sanitizer == "asan":
        cmd.insert(1, "-fsanitize=address")
    elif sanitizer == "ubsan":
        cmd.insert(1, "-fsanitize=undefined")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return {
        "compiler": compiler,
        "source": source_path,
        "output": output_path,
        "sanitizer": sanitizer,
        "success": result.returncode == 0,
        "stderr": result.stderr[:500] if result.stderr else "",
    }


def minimize_corpus(afl_cmin_path, target_binary, input_dir, output_dir):
    """Minimize seed corpus using afl-cmin."""
    cmd = [afl_cmin_path or "afl-cmin", "-i", input_dir, "-o", output_dir,
           "--", target_binary]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    before = len(os.listdir(input_dir)) if os.path.isdir(input_dir) else 0
    after = len(os.listdir(output_dir)) if os.path.isdir(output_dir) else 0
    return {
        "before": before,
        "after": after,
        "reduction_pct": round((1 - after / max(before, 1)) * 100, 1),
        "success": result.returncode == 0,
    }


def parse_fuzzer_stats(output_dir):
    """Parse afl-fuzz fuzzer_stats file for campaign metrics."""
    stats_path = os.path.join(output_dir, "default", "fuzzer_stats")
    if not os.path.exists(stats_path):
        stats_path = os.path.join(output_dir, "fuzzer_stats")
    if not os.path.exists(stats_path):
        return {"error": f"fuzzer_stats not found in {output_dir}"}

    stats = {}
    with open(stats_path, "r") as f:
        for line in f:
            if ":" in line:
                key, val = line.split(":", 1)
                stats[key.strip()] = val.strip()

    return {
        "start_time": stats.get("start_time", ""),
        "last_update": stats.get("last_update", ""),
        "execs_done": int(stats.get("execs_done", 0)),
        "execs_per_sec": float(stats.get("execs_per_sec", 0)),
        "paths_total": int(stats.get("corpus_count", stats.get("paths_total", 0))),
        "paths_found": int(stats.get("paths_found", 0)),
        "unique_crashes": int(stats.get("saved_crashes", stats.get("unique_crashes", 0))),
        "unique_hangs": int(stats.get("saved_hangs", stats.get("unique_hangs", 0))),
        "stability": stats.get("stability", ""),
        "bitmap_cvg": stats.get("bitmap_cvg", ""),
        "command_line": stats.get("command_line", ""),
    }


def triage_crashes(output_dir):
    """Enumerate and classify crash files from AFL++ output."""
    crash_dirs = [
        os.path.join(output_dir, "default", "crashes"),
        os.path.join(output_dir, "crashes"),
    ]
    crash_dir = None
    for d in crash_dirs:
        if os.path.isdir(d):
            crash_dir = d
            break
    if not crash_dir:
        return {"crashes": [], "total": 0}

    crashes = []
    for filename in sorted(os.listdir(crash_dir)):
        if filename.startswith("README") or filename == ".state":
            continue
        filepath = os.path.join(crash_dir, filename)
        size = os.path.getsize(filepath)
        sig_parts = filename.split(",")
        signal = ""
        for part in sig_parts:
            if part.startswith("sig:"):
                signal = part.split(":")[1]
        crashes.append({
            "filename": filename,
            "size_bytes": size,
            "signal": signal,
            "path": filepath,
        })
    return {"crashes": crashes, "total": len(crashes)}


def minimize_crash(afl_tmin_path, target_binary, crash_file, output_file):
    """Minimize a crash test case with afl-tmin."""
    cmd = [afl_tmin_path or "afl-tmin", "-i", crash_file, "-o", output_file,
           "--", target_binary]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    orig_size = os.path.getsize(crash_file) if os.path.exists(crash_file) else 0
    min_size = os.path.getsize(output_file) if os.path.exists(output_file) else 0
    return {
        "original_size": orig_size,
        "minimized_size": min_size,
        "reduction_pct": round((1 - min_size / max(orig_size, 1)) * 100, 1),
        "success": result.returncode == 0,
    }


def run_whatsup(output_dir):
    """Run afl-whatsup to get multi-instance campaign summary."""
    cmd = ["afl-whatsup", "-s", output_dir]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return {"output": result.stdout[:2000] if result.stdout else result.stderr[:500]}


def run_audit(args):
    """Execute AFL++ fuzzing campaign audit."""
    print(f"\n{'='*60}")
    print(f"  AFL++ FUZZING CAMPAIGN AUDIT")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    report = {}

    if args.output_dir:
        stats = parse_fuzzer_stats(args.output_dir)
        report["fuzzer_stats"] = stats
        print(f"--- FUZZER STATS ---")
        print(f"  Executions: {stats.get('execs_done', 0):,}")
        print(f"  Exec/sec: {stats.get('execs_per_sec', 0)}")
        print(f"  Paths: {stats.get('paths_total', 0)}")
        print(f"  Crashes: {stats.get('unique_crashes', 0)}")
        print(f"  Hangs: {stats.get('unique_hangs', 0)}")
        print(f"  Stability: {stats.get('stability', '')}")
        print(f"  Coverage: {stats.get('bitmap_cvg', '')}")

        crash_data = triage_crashes(args.output_dir)
        report["crash_triage"] = crash_data
        print(f"\n--- CRASH TRIAGE ({crash_data['total']} crashes) ---")
        for c in crash_data["crashes"][:20]:
            print(f"  {c['filename']} ({c['size_bytes']}B) signal={c['signal']}")

    if args.instrument_src and args.instrument_out:
        inst = instrument_target(args.instrument_src, args.instrument_out,
                                  sanitizer=args.sanitizer)
        report["instrumentation"] = inst
        print(f"\n--- INSTRUMENTATION ---")
        print(f"  {'SUCCESS' if inst['success'] else 'FAILED'}: {inst['source']}")

    return report


def main():
    parser = argparse.ArgumentParser(description="AFL++ Fuzzing Campaign Agent")
    parser.add_argument("--output-dir", help="AFL++ output directory to analyze")
    parser.add_argument("--instrument-src", help="Source file to instrument")
    parser.add_argument("--instrument-out", help="Output path for instrumented binary")
    parser.add_argument("--sanitizer", choices=["asan", "ubsan"],
                        help="Address or undefined behavior sanitizer")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
