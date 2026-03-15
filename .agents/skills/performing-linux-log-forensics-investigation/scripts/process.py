#!/usr/bin/env python3
"""Linux Log Forensic Analyzer - Parses auth.log for forensic investigation."""
import re, json, os, sys
from datetime import datetime
from collections import defaultdict

def parse_auth_log(path: str, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    successful, failed, sudo_cmds = [], [], []
    ssh_ok = re.compile(r'(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+([\d.]+)')
    ssh_fail = re.compile(r'(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Failed\s+password\s+for\s+(\S*)\s+from\s+([\d.]+)')
    sudo_re = re.compile(r'(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sudo:\s+(\S+)\s+:.*COMMAND=(.*)')
    with open(path, "r", errors="replace") as f:
        for line in f:
            m = ssh_ok.search(line)
            if m:
                successful.append({"time": m.group(1), "method": m.group(2), "user": m.group(3), "ip": m.group(4)})
                continue
            m = ssh_fail.search(line)
            if m:
                failed.append({"time": m.group(1), "user": m.group(2), "ip": m.group(3)})
                continue
            m = sudo_re.search(line)
            if m:
                sudo_cmds.append({"time": m.group(1), "user": m.group(2), "command": m.group(3).strip()})
    # Brute force detection
    ip_counts = defaultdict(int)
    for e in failed:
        ip_counts[e["ip"]] += 1
    brute_force = [{"ip": k, "attempts": v} for k, v in ip_counts.items() if v >= 10]
    report = {"successful_logins": len(successful), "failed_logins": len(failed),
              "sudo_commands": len(sudo_cmds), "brute_force_ips": brute_force,
              "top_successful": successful[:50], "top_failed": failed[:50], "top_sudo": sudo_cmds[:50]}
    out = os.path.join(output_dir, "linux_auth_forensics.json")
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] OK:{len(successful)} FAIL:{len(failed)} SUDO:{len(sudo_cmds)} BruteForce:{len(brute_force)}")
    return out

if __name__ == "__main__":
    if len(sys.argv) < 3: print("Usage: process.py <auth.log> <output_dir>"); sys.exit(1)
    parse_auth_log(sys.argv[1], sys.argv[2])
