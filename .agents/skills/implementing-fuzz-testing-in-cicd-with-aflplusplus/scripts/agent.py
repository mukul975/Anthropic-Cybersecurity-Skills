#!/usr/bin/env python3
"""Agent for implementing AFL++ fuzz testing in CI/CD pipelines."""

import json
import argparse
import subprocess
import os
import shutil
from datetime import datetime
from pathlib import Path


def compile_target(source_file, output_binary, compiler="afl-clang-fast"):
    """Compile target binary with AFL++ instrumentation."""
    cmd = [compiler, "-g", "-O1", "-fno-omit-frame-pointer", "-o", output_binary, source_file]
    env = os.environ.copy()
    env["AFL_HARDEN"] = "1"
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
    return {
        "source": source_file,
        "binary": output_binary,
        "compiler": compiler,
        "returncode": result.returncode,
        "stdout": result.stdout[:500],
        "stderr": result.stderr[:500],
        "instrumented": result.returncode == 0,
    }


def prepare_corpus(seed_dir, corpus_dir):
    """Prepare and minimize seed corpus using afl-cmin."""
    Path(corpus_dir).mkdir(parents=True, exist_ok=True)
    seeds = list(Path(seed_dir).glob("*"))
    if not seeds:
        # Create a minimal seed if none provided
        minimal = Path(seed_dir) / "seed_minimal"
        minimal.write_bytes(b"AAAA")
        seeds = [minimal]
    return {
        "seed_dir": str(seed_dir),
        "corpus_dir": str(corpus_dir),
        "seed_count": len(seeds),
        "seeds": [str(s) for s in seeds[:50]],
    }


def minimize_corpus(binary, input_dir, output_dir, timeout=60):
    """Minimize seed corpus using afl-cmin."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    cmd = ["afl-cmin", "-i", input_dir, "-o", output_dir, "-t", str(timeout * 1000), "--", binary]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    minimized = list(Path(output_dir).glob("*"))
    return {
        "input_count": len(list(Path(input_dir).glob("*"))),
        "output_count": len(minimized),
        "returncode": result.returncode,
    }


def run_fuzzer(binary, input_dir, output_dir, duration_seconds=300, memory_limit="512"):
    """Run AFL++ fuzzer for a specified duration."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["AFL_SKIP_CPUFREQ"] = "1"
    env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
    env["AFL_NO_UI"] = "1"
    cmd = [
        "afl-fuzz",
        "-i", input_dir,
        "-o", output_dir,
        "-m", memory_limit,
        "-V", str(duration_seconds),
        "--", binary,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=duration_seconds + 60)
    stats = parse_fuzzer_stats(os.path.join(output_dir, "default", "fuzzer_stats"))
    crashes_dir = os.path.join(output_dir, "default", "crashes")
    crash_files = list(Path(crashes_dir).glob("id:*")) if os.path.isdir(crashes_dir) else []
    return {
        "binary": binary,
        "duration_seconds": duration_seconds,
        "returncode": result.returncode,
        "stats": stats,
        "crashes_found": len(crash_files),
        "crash_files": [str(f) for f in crash_files[:50]],
    }


def parse_fuzzer_stats(stats_file):
    """Parse AFL++ fuzzer_stats file into a dict."""
    stats = {}
    try:
        with open(stats_file, "r") as f:
            for line in f:
                if ":" in line:
                    key, _, value = line.partition(":")
                    stats[key.strip()] = value.strip()
    except FileNotFoundError:
        return {"error": "fuzzer_stats not found"}
    return {
        "execs_done": stats.get("execs_done", "0"),
        "execs_per_sec": stats.get("execs_per_sec", "0"),
        "paths_total": stats.get("paths_total", "0"),
        "paths_found": stats.get("paths_found", "0"),
        "unique_crashes": stats.get("saved_crashes", "0"),
        "unique_hangs": stats.get("saved_hangs", "0"),
        "stability": stats.get("stability", "unknown"),
        "bitmap_cvg": stats.get("bitmap_cvg", "unknown"),
    }


def triage_crashes(binary, crashes_dir):
    """Triage crash inputs to deduplicate and classify."""
    crash_files = sorted(Path(crashes_dir).glob("id:*"))
    results = []
    for crash_file in crash_files[:100]:
        cmd = [binary]
        try:
            proc = subprocess.run(
                cmd, input=crash_file.read_bytes(),
                capture_output=True, timeout=5
            )
            results.append({
                "file": str(crash_file),
                "returncode": proc.returncode,
                "signal": -proc.returncode if proc.returncode < 0 else None,
                "stderr_snippet": proc.stderr[:200].decode("utf-8", errors="replace"),
                "crash_type": _classify_signal(proc.returncode),
            })
        except subprocess.TimeoutExpired:
            results.append({"file": str(crash_file), "crash_type": "hang/timeout"})
    return {
        "total_crashes": len(crash_files),
        "triaged": len(results),
        "by_type": _count_by(results, "crash_type"),
        "results": results,
    }


def _classify_signal(returncode):
    signal_map = {-6: "SIGABRT", -11: "SIGSEGV", -8: "SIGFPE", -4: "SIGILL", -7: "SIGBUS"}
    return signal_map.get(returncode, f"exit({returncode})")


def _count_by(items, key):
    counts = {}
    for item in items:
        val = item.get(key, "unknown")
        counts[val] = counts.get(val, 0) + 1
    return counts


def main():
    parser = argparse.ArgumentParser(description="AFL++ Fuzz Testing CI/CD Agent")
    sub = parser.add_subparsers(dest="command")
    c = sub.add_parser("compile", help="Compile target with AFL++ instrumentation")
    c.add_argument("--source", required=True)
    c.add_argument("--output", required=True)
    c.add_argument("--compiler", default="afl-clang-fast")
    f = sub.add_parser("fuzz", help="Run AFL++ fuzzer")
    f.add_argument("--binary", required=True)
    f.add_argument("--input", required=True)
    f.add_argument("--output", required=True)
    f.add_argument("--duration", type=int, default=300, help="Duration in seconds")
    f.add_argument("--memory", default="512", help="Memory limit in MB")
    t = sub.add_parser("triage", help="Triage crash inputs")
    t.add_argument("--binary", required=True)
    t.add_argument("--crashes-dir", required=True)
    s = sub.add_parser("stats", help="Parse fuzzer stats")
    s.add_argument("--stats-file", required=True)
    args = parser.parse_args()
    if args.command == "compile":
        result = compile_target(args.source, args.output, args.compiler)
    elif args.command == "fuzz":
        result = run_fuzzer(args.binary, args.input, args.output, args.duration, args.memory)
    elif args.command == "triage":
        result = triage_crashes(args.binary, args.crashes_dir)
    elif args.command == "stats":
        result = parse_fuzzer_stats(args.stats_file)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
