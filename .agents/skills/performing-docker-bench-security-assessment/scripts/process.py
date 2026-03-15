#!/usr/bin/env python3
"""Docker Bench Security Assessment Runner and Parser."""

import subprocess
import json
import sys
import re

def run_docker_bench():
    """Run Docker Bench Security and parse results."""
    cmd = [
        "docker", "run", "--rm", "--net", "host", "--pid", "host",
        "--userns", "host", "--cap-add", "audit_control",
        "-v", "/etc:/etc:ro", "-v", "/var/lib:/var/lib:ro",
        "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
        "docker/docker-bench-security"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout + result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[!] Failed to run Docker Bench: {e}")
        sys.exit(1)

    results = {"PASS": [], "FAIL": [], "WARN": [], "INFO": []}
    for line in output.split("\n"):
        for status in ["PASS", "FAIL", "WARN", "INFO"]:
            if f"[{status}]" in line:
                check = line.strip()
                results[status].append(check)
                break

    print(f"\n{'='*60}")
    print("DOCKER BENCH SECURITY RESULTS")
    print(f"{'='*60}")
    print(f"PASS: {len(results['PASS'])}")
    print(f"FAIL: {len(results['FAIL'])}")
    print(f"WARN: {len(results['WARN'])}")
    print(f"INFO: {len(results['INFO'])}")

    total = len(results['PASS']) + len(results['FAIL'])
    if total > 0:
        score = (len(results['PASS']) / total) * 100
        print(f"Score: {score:.1f}%")

    if results["FAIL"]:
        print(f"\nFAILED CHECKS:")
        for f in results["FAIL"]:
            print(f"  {f}")

    with open("docker_bench_results.json", "w") as fh:
        json.dump(results, fh, indent=2)
    print(f"\n[*] Results saved to docker_bench_results.json")

if __name__ == "__main__":
    run_docker_bench()
