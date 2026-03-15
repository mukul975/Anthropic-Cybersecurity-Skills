#!/usr/bin/env python3
"""
External Network Penetration Test — Automation Process

Automates reconnaissance, scanning, and reporting phases of an external
network penetration test. Requires: nmap, subfinder, nuclei, python-nmap.

Usage:
    python process.py --target target.com --ip-range 203.0.113.0/24 --output ./results
"""

import subprocess
import json
import csv
import os
import sys
import argparse
import socket
import ssl
import datetime
import ipaddress
from pathlib import Path
from typing import Optional


def run_command(cmd: list[str], timeout: int = 300) -> tuple[str, str, int]:
    """Execute a shell command and return stdout, stderr, return code."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", -1


def enumerate_subdomains(domain: str, output_dir: Path) -> list[str]:
    """Enumerate subdomains using subfinder."""
    print(f"[*] Enumerating subdomains for {domain}...")
    subfinder_out = output_dir / "subdomains_subfinder.txt"

    stdout, stderr, rc = run_command(
        ["subfinder", "-d", domain, "-silent", "-o", str(subfinder_out)],
        timeout=600
    )

    subdomains = set()
    if subfinder_out.exists():
        with open(subfinder_out) as f:
            subdomains.update(line.strip() for line in f if line.strip())

    print(f"[+] Found {len(subdomains)} subdomains")
    return sorted(subdomains)


def resolve_domains(subdomains: list[str], output_dir: Path) -> dict[str, list[str]]:
    """Resolve subdomains to IP addresses."""
    print(f"[*] Resolving {len(subdomains)} subdomains...")
    resolved = {}
    for sub in subdomains:
        try:
            ips = [r[4][0] for r in socket.getaddrinfo(sub, None, socket.AF_INET)]
            resolved[sub] = list(set(ips))
        except socket.gaierror:
            continue

    output_file = output_dir / "resolved_domains.json"
    with open(output_file, "w") as f:
        json.dump(resolved, f, indent=2)

    unique_ips = set()
    for ips in resolved.values():
        unique_ips.update(ips)
    print(f"[+] Resolved to {len(unique_ips)} unique IPs")
    return resolved


def nmap_scan(targets: str, output_dir: Path, scan_type: str = "quick") -> dict:
    """Run nmap scan on target range."""
    print(f"[*] Running nmap {scan_type} scan on {targets}...")
    output_prefix = str(output_dir / f"nmap_{scan_type}")

    if scan_type == "quick":
        cmd = ["nmap", "-sS", "-sV", "--top-ports", "1000", "-T4",
               "-oA", output_prefix, targets]
    elif scan_type == "full":
        cmd = ["nmap", "-sS", "-sV", "-p-", "-T4", "--min-rate", "1000",
               "-oA", output_prefix, targets]
    elif scan_type == "udp":
        cmd = ["nmap", "-sU", "--top-ports", "100", "-T4",
               "-oA", output_prefix, targets]
    elif scan_type == "scripts":
        cmd = ["nmap", "-sV", "-sC", "--script=vuln,exploit",
               "-oA", output_prefix, targets]
    else:
        cmd = ["nmap", "-sS", "-sV", "-T4",
               "-oA", output_prefix, targets]

    stdout, stderr, rc = run_command(cmd, timeout=3600)

    results = {
        "scan_type": scan_type,
        "targets": targets,
        "return_code": rc,
        "output_files": {
            "nmap": f"{output_prefix}.nmap",
            "xml": f"{output_prefix}.xml",
            "gnmap": f"{output_prefix}.gnmap",
        }
    }

    if rc == 0:
        print(f"[+] Nmap {scan_type} scan completed successfully")
    else:
        print(f"[-] Nmap scan returned code {rc}: {stderr[:200]}")

    return results


def check_ssl_tls(host: str, port: int = 443) -> dict:
    """Check SSL/TLS configuration for a host."""
    result = {
        "host": host,
        "port": port,
        "ssl_version": None,
        "cipher": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_expiry": None,
        "issues": []
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                result["ssl_version"] = ssock.version()
                result["cipher"] = ssock.cipher()
                cert = ssock.getpeercert()
                if cert:
                    result["cert_subject"] = dict(x[0] for x in cert.get("subject", []))
                    result["cert_issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    result["cert_expiry"] = cert.get("notAfter")

                    # Check expiry
                    expiry = datetime.datetime.strptime(
                        cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                    )
                    if expiry < datetime.datetime.now():
                        result["issues"].append("Certificate expired")
                    elif expiry < datetime.datetime.now() + datetime.timedelta(days=30):
                        result["issues"].append("Certificate expires within 30 days")

    except ssl.SSLCertVerificationError as e:
        result["issues"].append(f"Certificate verification failed: {e}")
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["issues"].append(f"Connection failed: {e}")

    return result


def run_nuclei_scan(targets_file: str, output_dir: Path) -> str:
    """Run nuclei vulnerability scanner."""
    print("[*] Running nuclei vulnerability scan...")
    output_file = output_dir / "nuclei_results.json"

    cmd = [
        "nuclei", "-l", targets_file,
        "-severity", "critical,high,medium",
        "-json", "-o", str(output_file),
        "-rate-limit", "50",
        "-bulk-size", "25",
        "-concurrency", "10"
    ]

    stdout, stderr, rc = run_command(cmd, timeout=3600)

    if rc == 0:
        print(f"[+] Nuclei scan completed. Results: {output_file}")
    else:
        print(f"[-] Nuclei scan issue: {stderr[:200]}")

    return str(output_file)


def parse_nmap_gnmap(gnmap_file: str) -> list[dict]:
    """Parse nmap gnmap output to extract open ports."""
    hosts = []
    try:
        with open(gnmap_file) as f:
            for line in f:
                if "Ports:" not in line:
                    continue
                parts = line.split("\t")
                host_part = parts[0]
                ip = host_part.split(" ")[1]
                ports_part = [p for p in parts if p.startswith("Ports:")]
                if not ports_part:
                    continue
                port_entries = ports_part[0].replace("Ports: ", "").split(", ")
                open_ports = []
                for entry in port_entries:
                    fields = entry.strip().split("/")
                    if len(fields) >= 5 and fields[1] == "open":
                        open_ports.append({
                            "port": int(fields[0]),
                            "protocol": fields[2],
                            "service": fields[4],
                            "version": fields[6] if len(fields) > 6 else ""
                        })
                if open_ports:
                    hosts.append({"ip": ip, "open_ports": open_ports})
    except FileNotFoundError:
        print(f"[-] File not found: {gnmap_file}")

    return hosts


def generate_report(
    scan_results: dict,
    resolved: dict,
    ssl_results: list[dict],
    output_dir: Path
) -> str:
    """Generate a summary report in markdown format."""
    print("[*] Generating report...")
    report_file = output_dir / "pentest_report.md"
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    with open(report_file, "w") as f:
        f.write(f"# External Network Penetration Test Report\n\n")
        f.write(f"**Generated:** {timestamp}\n\n")
        f.write("---\n\n")

        # Subdomain summary
        f.write("## Subdomain Enumeration\n\n")
        f.write(f"Total subdomains discovered: **{len(resolved)}**\n\n")
        unique_ips = set()
        for ips in resolved.values():
            unique_ips.update(ips)
        f.write(f"Unique IP addresses: **{len(unique_ips)}**\n\n")

        if resolved:
            f.write("| Subdomain | IP Address(es) |\n")
            f.write("|-----------|---------------|\n")
            for sub, ips in sorted(resolved.items()):
                f.write(f"| {sub} | {', '.join(ips)} |\n")
            f.write("\n")

        # Port scan summary
        f.write("## Port Scan Results\n\n")
        for scan_type, result in scan_results.items():
            f.write(f"### {scan_type.title()} Scan\n\n")
            gnmap = result.get("output_files", {}).get("gnmap")
            if gnmap and os.path.exists(gnmap):
                hosts = parse_nmap_gnmap(gnmap)
                if hosts:
                    for host in hosts:
                        f.write(f"**{host['ip']}**\n\n")
                        f.write("| Port | Protocol | Service | Version |\n")
                        f.write("|------|----------|---------|----------|\n")
                        for port in host["open_ports"]:
                            f.write(
                                f"| {port['port']} | {port['protocol']} "
                                f"| {port['service']} | {port['version']} |\n"
                            )
                        f.write("\n")
                else:
                    f.write("No open ports discovered in this scan.\n\n")
            else:
                f.write(f"Scan output not available (return code: {result.get('return_code')})\n\n")

        # SSL/TLS results
        f.write("## SSL/TLS Assessment\n\n")
        if ssl_results:
            f.write("| Host | SSL Version | Cipher | Expiry | Issues |\n")
            f.write("|------|-------------|--------|--------|--------|\n")
            for sr in ssl_results:
                issues = "; ".join(sr["issues"]) if sr["issues"] else "None"
                f.write(
                    f"| {sr['host']} | {sr.get('ssl_version', 'N/A')} "
                    f"| {sr.get('cipher', ('N/A',))[0] if sr.get('cipher') else 'N/A'} "
                    f"| {sr.get('cert_expiry', 'N/A')} | {issues} |\n"
                )
            f.write("\n")

        # Recommendations
        f.write("## Recommendations\n\n")
        f.write("1. Remediate all critical and high severity findings within 48 hours\n")
        f.write("2. Patch all identified CVEs on internet-facing services\n")
        f.write("3. Implement network segmentation for exposed services\n")
        f.write("4. Enable MFA on all externally accessible portals\n")
        f.write("5. Deploy WAF for web-facing applications\n")
        f.write("6. Review and harden TLS configurations\n")
        f.write("7. Remove unnecessary open ports and services\n")
        f.write("8. Implement rate limiting and account lockout policies\n\n")

        f.write("---\n")
        f.write(f"*Report generated by external pentest automation tool*\n")

    print(f"[+] Report generated: {report_file}")
    return str(report_file)


def main():
    parser = argparse.ArgumentParser(
        description="External Network Penetration Test Automation"
    )
    parser.add_argument("--target", required=True, help="Target domain (e.g., target.com)")
    parser.add_argument("--ip-range", help="Target IP range in CIDR notation")
    parser.add_argument("--output", default="./results", help="Output directory")
    parser.add_argument("--skip-recon", action="store_true", help="Skip reconnaissance phase")
    parser.add_argument("--skip-scan", action="store_true", help="Skip scanning phase")
    parser.add_argument("--scan-type", default="quick",
                        choices=["quick", "full", "udp", "scripts"],
                        help="Nmap scan type")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "evidence").mkdir(exist_ok=True)
    (output_dir / "scans").mkdir(exist_ok=True)

    print("=" * 60)
    print(" External Network Penetration Test")
    print(f" Target: {args.target}")
    print(f" Output: {output_dir.absolute()}")
    print(f" Started: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print("=" * 60)

    # Phase 1: Reconnaissance
    resolved = {}
    if not args.skip_recon:
        subdomains = enumerate_subdomains(args.target, output_dir)
        resolved = resolve_domains(subdomains, output_dir)
    else:
        print("[*] Skipping reconnaissance phase")

    # Phase 2: Scanning
    scan_results = {}
    ssl_results = []
    if not args.skip_scan:
        scan_target = args.ip_range or args.target
        scan_results[args.scan_type] = nmap_scan(
            scan_target, output_dir / "scans", args.scan_type
        )

        # SSL/TLS checks on discovered web services
        ssl_hosts = [args.target]
        if resolved:
            ssl_hosts.extend(list(resolved.keys())[:20])
        for host in ssl_hosts:
            ssl_result = check_ssl_tls(host)
            if ssl_result["ssl_version"] or ssl_result["issues"]:
                ssl_results.append(ssl_result)
    else:
        print("[*] Skipping scanning phase")

    # Phase 3: Nuclei scan
    targets_file = output_dir / "targets.txt"
    with open(targets_file, "w") as f:
        f.write(f"https://{args.target}\n")
        for sub in resolved:
            f.write(f"https://{sub}\n")
    run_nuclei_scan(str(targets_file), output_dir)

    # Phase 4: Report generation
    report_path = generate_report(scan_results, resolved, ssl_results, output_dir)

    print("\n" + "=" * 60)
    print(" Penetration Test Automation Complete")
    print(f" Report: {report_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
