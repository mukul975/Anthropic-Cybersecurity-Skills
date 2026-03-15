#!/usr/bin/env python3
"""
Memory Forensics Automation with Volatility3

Requirements:
    pip install volatility3

Usage:
    python process.py --dump memory.raw --triage
    python process.py --dump memory.raw --plugin windows.malfind
"""

import argparse
import json
import subprocess
import sys


def run_vol3(dump_path, plugin, extra_args=None, vol3_cmd="vol"):
    cmd = [vol3_cmd, "-f", dump_path, "-r", "json", plugin]
    if extra_args:
        cmd.extend(extra_args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
    except Exception as e:
        print(f"[-] {plugin}: {e}")
    return None


def triage(dump_path):
    plugins = [
        "windows.pslist",
        "windows.psscan",
        "windows.malfind",
        "windows.netscan",
        "windows.cmdline",
    ]
    report = {}
    for plugin in plugins:
        print(f"[+] Running {plugin}...")
        report[plugin] = run_vol3(dump_path, plugin)
    return report


def main():
    parser = argparse.ArgumentParser(description="Volatility3 Automation")
    parser.add_argument("--dump", required=True, help="Memory dump file")
    parser.add_argument("--triage", action="store_true")
    parser.add_argument("--plugin", help="Specific plugin to run")
    parser.add_argument("--output", help="Output JSON file")

    args = parser.parse_args()

    if args.triage:
        report = triage(args.dump)
    elif args.plugin:
        report = {args.plugin: run_vol3(args.dump, args.plugin)}
    else:
        parser.print_help()
        return

    print(json.dumps(report, indent=2, default=str))
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)


if __name__ == "__main__":
    main()
