#!/usr/bin/env python3
"""Volatile evidence collection agent for compromised hosts.

Collects volatile forensic artifacts following RFC 3227 order of volatility:
registers, memory, network state, running processes, disk, and logs.
Uses platform-native tools for live response evidence gathering.
"""

import sys
import json
import os
import datetime
import subprocess
import platform
import hashlib


VOLATILITY_ORDER = [
    {"priority": 1, "source": "memory", "description": "Physical memory (RAM) dump",
     "tool_linux": "avml", "tool_windows": "winpmem_mini_x64.exe"},
    {"priority": 2, "source": "network_connections", "description": "Active network connections",
     "tool_linux": "ss -tunap", "tool_windows": "netstat -anob"},
    {"priority": 3, "source": "running_processes", "description": "Running process list with details",
     "tool_linux": "ps auxwwf", "tool_windows": "tasklist /V /FO CSV"},
    {"priority": 4, "source": "open_files", "description": "Open file handles",
     "tool_linux": "lsof -nP", "tool_windows": "handle64.exe -a"},
    {"priority": 5, "source": "network_config", "description": "Network interface configuration",
     "tool_linux": "ip addr show", "tool_windows": "ipconfig /all"},
    {"priority": 6, "source": "routing_table", "description": "Network routing table",
     "tool_linux": "ip route show", "tool_windows": "route print"},
    {"priority": 7, "source": "arp_cache", "description": "ARP cache entries",
     "tool_linux": "ip neigh show", "tool_windows": "arp -a"},
    {"priority": 8, "source": "dns_cache", "description": "DNS resolver cache",
     "tool_linux": "cat /etc/resolv.conf", "tool_windows": "ipconfig /displaydns"},
    {"priority": 9, "source": "logged_users", "description": "Currently logged-in users",
     "tool_linux": "w", "tool_windows": "query user"},
    {"priority": 10, "source": "scheduled_tasks", "description": "Scheduled tasks and cron jobs",
     "tool_linux": "crontab -l; ls /etc/cron.d/", "tool_windows": "schtasks /query /FO CSV /V"},
]


def collect_artifact(source_config, output_dir):
    """Collect a single volatile artifact."""
    is_windows = platform.system() == "Windows"
    cmd = source_config["tool_windows"] if is_windows else source_config["tool_linux"]
    source_name = source_config["source"]
    output_file = os.path.join(output_dir, source_name + ".txt")

    result = {
        "source": source_name,
        "priority": source_config["priority"],
        "command": cmd,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "status": "pending",
    }

    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=60
        )
        result["status"] = "collected"
        result["output_lines"] = len(proc.stdout.splitlines())
        result["output_file"] = output_file
        result["exit_code"] = proc.returncode

        with open(output_file, "w", encoding="utf-8") as f:
            f.write("# Collected: {}\n".format(result["timestamp"]))
            f.write("# Command: {}\n".format(cmd))
            f.write("# Exit code: {}\n\n".format(proc.returncode))
            f.write(proc.stdout)
            if proc.stderr:
                f.write("\n# STDERR:\n" + proc.stderr)

        sha256 = hashlib.sha256(proc.stdout.encode()).hexdigest()
        result["sha256"] = sha256
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


def run_collection(output_dir, sources=None):
    """Run full volatile evidence collection."""
    os.makedirs(output_dir, exist_ok=True)
    if sources is None:
        sources = VOLATILITY_ORDER

    manifest = {
        "collection_start": datetime.datetime.utcnow().isoformat() + "Z",
        "hostname": platform.node(),
        "platform": platform.system(),
        "output_dir": output_dir,
        "artifacts": [],
    }

    for source_config in sorted(sources, key=lambda x: x["priority"]):
        if source_config["source"] == "memory":
            manifest["artifacts"].append({
                "source": "memory",
                "priority": 1,
                "status": "skipped",
                "note": "Memory dump requires elevated privileges and dedicated tool",
            })
            continue

        result = collect_artifact(source_config, output_dir)
        manifest["artifacts"].append(result)

    manifest["collection_end"] = datetime.datetime.utcnow().isoformat() + "Z"
    manifest["total_collected"] = sum(1 for a in manifest["artifacts"] if a["status"] == "collected")

    manifest_path = os.path.join(output_dir, "collection_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    manifest["manifest_file"] = manifest_path

    return manifest


if __name__ == "__main__":
    print("=" * 60)
    print("Volatile Evidence Collection Agent")
    print("RFC 3227 order of volatility, live response artifacts")
    print("=" * 60)
    print("  Platform: {}".format(platform.system()))
    print("  Hostname: {}".format(platform.node()))

    output_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.expanduser("~"), "volatile_evidence_" + datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    )

    print("\n--- RFC 3227 Volatility Order ---")
    for v in VOLATILITY_ORDER:
        tool = v["tool_windows"] if platform.system() == "Windows" else v["tool_linux"]
        print("  P{}: {:25s} [{}]".format(v["priority"], v["source"], tool))

    print("\n[*] Collecting volatile evidence to: {}".format(output_dir))
    manifest = run_collection(output_dir)

    print("\n--- Collection Results ---")
    for a in manifest["artifacts"]:
        status_marker = "+" if a["status"] == "collected" else "-"
        print("  [{}] P{}: {} -> {}".format(
            status_marker, a["priority"], a["source"], a["status"]))

    print("\nTotal collected: {}/{}".format(
        manifest["total_collected"], len(manifest["artifacts"])))
    print("Manifest: {}".format(manifest.get("manifest_file", "")))

    print("\n" + json.dumps({"artifacts_collected": manifest["total_collected"]}, indent=2))
