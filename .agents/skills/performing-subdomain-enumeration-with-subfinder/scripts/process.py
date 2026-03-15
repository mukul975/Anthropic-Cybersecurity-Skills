#!/usr/bin/env python3
"""
Subdomain Enumeration Pipeline with Subfinder
Automates subdomain discovery, validation, and reporting.
"""

import subprocess
import json
import csv
import sys
import os
from datetime import datetime
from pathlib import Path


def run_subfinder(domain: str, output_dir: str, use_all_sources: bool = False) -> list:
    """Run subfinder against a target domain and return discovered subdomains."""
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{domain}_subdomains.txt")

    cmd = ["subfinder", "-d", domain, "-silent"]
    if use_all_sources:
        cmd.append("-all")

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    subdomains = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]

    with open(output_file, "w") as f:
        f.write("\n".join(subdomains))

    print(f"[+] Found {len(subdomains)} subdomains for {domain}")
    return subdomains


def validate_with_httpx(subdomains: list, output_dir: str) -> list:
    """Validate discovered subdomains using httpx."""
    input_data = "\n".join(subdomains)
    cmd = [
        "httpx", "-silent", "-status-code", "-title",
        "-tech-detect", "-json", "-no-color"
    ]

    result = subprocess.run(
        cmd, input=input_data, capture_output=True, text=True, timeout=600
    )

    live_hosts = []
    for line in result.stdout.strip().split("\n"):
        if line.strip():
            try:
                host_data = json.loads(line)
                live_hosts.append(host_data)
            except json.JSONDecodeError:
                continue

    output_file = os.path.join(output_dir, "live_hosts.json")
    with open(output_file, "w") as f:
        json.dump(live_hosts, f, indent=2)

    print(f"[+] Validated {len(live_hosts)} live hosts")
    return live_hosts


def detect_takeover_candidates(subdomains: list) -> list:
    """Identify subdomains with CNAME records pointing to potentially claimable services."""
    takeover_services = [
        "amazonaws.com", "azurewebsites.net", "cloudfront.net",
        "herokuapp.com", "github.io", "gitlab.io", "pantheon.io",
        "shopify.com", "surge.sh", "fastly.net", "ghost.io",
        "myshopify.com", "zendesk.com", "readme.io", "bitbucket.io"
    ]

    candidates = []
    for subdomain in subdomains:
        try:
            result = subprocess.run(
                ["dig", "+short", "CNAME", subdomain],
                capture_output=True, text=True, timeout=10
            )
            cname = result.stdout.strip()
            if cname:
                for service in takeover_services:
                    if service in cname:
                        candidates.append({
                            "subdomain": subdomain,
                            "cname": cname,
                            "service": service
                        })
                        break
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

    return candidates


def generate_report(domain: str, subdomains: list, live_hosts: list,
                    takeover_candidates: list, output_dir: str) -> str:
    """Generate a markdown report of enumeration results."""
    report_path = os.path.join(output_dir, f"{domain}_report.md")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(report_path, "w") as f:
        f.write(f"# Subdomain Enumeration Report: {domain}\n\n")
        f.write(f"**Date**: {timestamp}\n\n")
        f.write(f"## Summary\n")
        f.write(f"- **Total Subdomains Discovered**: {len(subdomains)}\n")
        f.write(f"- **Live Hosts**: {len(live_hosts)}\n")
        f.write(f"- **Takeover Candidates**: {len(takeover_candidates)}\n\n")

        f.write("## Live Hosts\n\n")
        f.write("| URL | Status | Title | Technologies |\n")
        f.write("|-----|--------|-------|--------------|\n")
        for host in live_hosts:
            url = host.get("url", "N/A")
            status = host.get("status_code", "N/A")
            title = host.get("title", "N/A")
            techs = ", ".join(host.get("tech", [])) if host.get("tech") else "N/A"
            f.write(f"| {url} | {status} | {title} | {techs} |\n")

        if takeover_candidates:
            f.write("\n## Potential Subdomain Takeover Candidates\n\n")
            f.write("| Subdomain | CNAME | Service |\n")
            f.write("|-----------|-------|---------|\n")
            for candidate in takeover_candidates:
                f.write(f"| {candidate['subdomain']} | {candidate['cname']} | {candidate['service']} |\n")

        f.write("\n## All Discovered Subdomains\n\n")
        for sub in sorted(subdomains):
            f.write(f"- {sub}\n")

    print(f"[+] Report saved to {report_path}")
    return report_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python process.py <domain> [output_dir] [--all]")
        sys.exit(1)

    domain = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else "./recon_output"
    use_all = "--all" in sys.argv

    print(f"[*] Starting subdomain enumeration for {domain}")
    subdomains = run_subfinder(domain, output_dir, use_all)

    if not subdomains:
        print("[-] No subdomains found. Exiting.")
        sys.exit(0)

    print("[*] Validating live hosts with httpx...")
    live_hosts = validate_with_httpx(subdomains, output_dir)

    print("[*] Checking for subdomain takeover candidates...")
    takeover_candidates = detect_takeover_candidates(subdomains)

    print("[*] Generating report...")
    generate_report(domain, subdomains, live_hosts, takeover_candidates, output_dir)

    print(f"[+] Enumeration complete. Results saved to {output_dir}/")


if __name__ == "__main__":
    main()
