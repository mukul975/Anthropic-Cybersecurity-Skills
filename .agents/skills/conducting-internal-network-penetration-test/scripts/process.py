#!/usr/bin/env python3
"""
Internal Network Penetration Test — Automation Process

Automates network discovery, AD enumeration, and reporting for internal pentests.
Requires: nmap, netexec, ldap3, bloodhound-python.

Usage:
    python process.py --subnet 10.0.0.0/24 --domain corp.local --dc-ip 10.0.0.5 --output ./results
"""

import subprocess
import json
import os
import sys
import argparse
import socket
import datetime
from pathlib import Path
from typing import Optional


def run_command(cmd: list[str], timeout: int = 300) -> tuple[str, str, int]:
    """Execute a shell command and return stdout, stderr, return code."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", -1


def discover_hosts(subnet: str, output_dir: Path) -> list[str]:
    """Discover live hosts on the internal network."""
    print(f"[*] Discovering live hosts on {subnet}...")
    output_file = output_dir / "host_discovery"

    stdout, stderr, rc = run_command(
        ["nmap", "-sn", subnet, "-oA", str(output_file)], timeout=600
    )

    live_hosts = []
    gnmap = f"{output_file}.gnmap"
    if os.path.exists(gnmap):
        with open(gnmap) as f:
            for line in f:
                if "Status: Up" in line:
                    ip = line.split(" ")[1]
                    live_hosts.append(ip)

    hosts_file = output_dir / "live_hosts.txt"
    with open(hosts_file, "w") as f:
        f.write("\n".join(live_hosts))

    print(f"[+] Found {len(live_hosts)} live hosts")
    return live_hosts


def port_scan(hosts_file: str, output_dir: Path) -> dict:
    """Run port scan against discovered hosts."""
    print("[*] Running port scan on live hosts...")
    output_prefix = str(output_dir / "port_scan")

    stdout, stderr, rc = run_command(
        ["nmap", "-sS", "-sV", "-T4", "--top-ports", "1000",
         "-iL", hosts_file, "-oA", output_prefix],
        timeout=3600
    )

    return {"output_prefix": output_prefix, "return_code": rc}


def enumerate_smb_shares(hosts: list[str], username: str, password: str,
                          domain: str, output_dir: Path) -> list[dict]:
    """Enumerate SMB shares across internal hosts."""
    print("[*] Enumerating SMB shares...")
    results = []

    for host in hosts:
        stdout, stderr, rc = run_command(
            ["netexec", "smb", host, "-u", username, "-p", password,
             "-d", domain, "--shares"],
            timeout=30
        )
        if rc == 0 and stdout:
            results.append({"host": host, "output": stdout})

    output_file = output_dir / "smb_shares.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[+] Enumerated shares on {len(results)} hosts")
    return results


def check_smb_signing(hosts: list[str], output_dir: Path) -> list[dict]:
    """Check SMB signing status on discovered hosts."""
    print("[*] Checking SMB signing status...")
    results = []

    for host in hosts:
        stdout, stderr, rc = run_command(
            ["netexec", "smb", host, "--gen-relay-list",
             str(output_dir / "relay_targets.txt")],
            timeout=30
        )
        if "signing:False" in stdout:
            results.append({"host": host, "smb_signing": False})
        elif "signing:True" in stdout:
            results.append({"host": host, "smb_signing": True})

    output_file = output_dir / "smb_signing.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    unsigned = [r for r in results if not r.get("smb_signing")]
    print(f"[+] Found {len(unsigned)} hosts without SMB signing")
    return results


def run_bloodhound_collection(username: str, password: str,
                                domain: str, dc_ip: str,
                                output_dir: Path) -> str:
    """Run BloodHound data collection."""
    print("[*] Running BloodHound collection...")
    stdout, stderr, rc = run_command(
        ["bloodhound-python", "-u", username, "-p", password,
         "-d", domain, "-ns", dc_ip, "-c", "all",
         "--output-prefix", str(output_dir / "bloodhound")],
        timeout=600
    )

    if rc == 0:
        print("[+] BloodHound data collected successfully")
    else:
        print(f"[-] BloodHound collection issue: {stderr[:200]}")

    return str(output_dir)


def check_password_policy(domain: str, dc_ip: str, username: str,
                           password: str) -> dict:
    """Retrieve domain password policy."""
    print("[*] Retrieving domain password policy...")
    stdout, stderr, rc = run_command(
        ["netexec", "smb", dc_ip, "-u", username, "-p", password,
         "-d", domain, "--pass-pol"],
        timeout=30
    )

    return {"output": stdout, "return_code": rc}


def generate_report(live_hosts: list[str], smb_results: list[dict],
                     signing_results: list[dict], output_dir: Path) -> str:
    """Generate internal pentest summary report."""
    print("[*] Generating report...")
    report_file = output_dir / "internal_pentest_report.md"
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    with open(report_file, "w") as f:
        f.write("# Internal Network Penetration Test Report\n\n")
        f.write(f"**Generated:** {timestamp}\n\n---\n\n")

        f.write("## Network Discovery\n\n")
        f.write(f"Total live hosts: **{len(live_hosts)}**\n\n")

        f.write("## SMB Share Analysis\n\n")
        f.write(f"Hosts with accessible shares: **{len(smb_results)}**\n\n")

        f.write("## SMB Signing Status\n\n")
        unsigned = [r for r in signing_results if not r.get("smb_signing")]
        f.write(f"Hosts without SMB signing: **{len(unsigned)}** (vulnerable to relay)\n\n")
        if unsigned:
            f.write("| Host | SMB Signing |\n|------|------------|\n")
            for r in unsigned:
                f.write(f"| {r['host']} | Disabled |\n")
            f.write("\n")

        f.write("## Recommendations\n\n")
        f.write("1. Enable SMB signing on all domain-joined systems via GPO\n")
        f.write("2. Disable LLMNR and NBT-NS across the domain\n")
        f.write("3. Implement LAPS for unique local admin passwords\n")
        f.write("4. Deploy tiered admin model for Active Directory\n")
        f.write("5. Enforce strong password policy (14+ characters)\n")
        f.write("6. Use Group Managed Service Accounts (gMSA)\n\n")

    print(f"[+] Report generated: {report_file}")
    return str(report_file)


def main():
    parser = argparse.ArgumentParser(description="Internal Network Pentest Automation")
    parser.add_argument("--subnet", required=True, help="Target subnet (CIDR)")
    parser.add_argument("--domain", required=True, help="AD domain name")
    parser.add_argument("--dc-ip", required=True, help="Domain controller IP")
    parser.add_argument("--username", default="", help="Domain username")
    parser.add_argument("--password", default="", help="Domain password")
    parser.add_argument("--output", default="./results", help="Output directory")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print(" Internal Network Penetration Test")
    print(f" Subnet: {args.subnet}")
    print(f" Domain: {args.domain}")
    print("=" * 60)

    live_hosts = discover_hosts(args.subnet, output_dir)
    port_scan(str(output_dir / "live_hosts.txt"), output_dir)

    smb_results = []
    signing_results = check_smb_signing(live_hosts[:50], output_dir)

    if args.username and args.password:
        smb_results = enumerate_smb_shares(
            live_hosts[:50], args.username, args.password, args.domain, output_dir
        )
        run_bloodhound_collection(
            args.username, args.password, args.domain, args.dc_ip, output_dir
        )
        check_password_policy(args.domain, args.dc_ip, args.username, args.password)

    generate_report(live_hosts, smb_results, signing_results, output_dir)
    print("\n[+] Internal pentest automation complete")


if __name__ == "__main__":
    main()
