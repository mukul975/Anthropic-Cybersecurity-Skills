#!/usr/bin/env python3
"""
Wireless Penetration Test — Automation Process

Parses airodump-ng CSV output and generates wireless assessment reports.

Usage:
    python process.py --scan-file scan-01.csv --authorized-aps authorized.txt --output ./results
"""

import csv
import json
import argparse
import datetime
from pathlib import Path


def parse_airodump_csv(csv_file: str) -> tuple[list[dict], list[dict]]:
    """Parse airodump-ng CSV output into APs and clients."""
    aps = []
    clients = []
    section = "ap"

    with open(csv_file, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if "Station MAC" in line:
                section = "client"
                continue
            if "BSSID" in line and section == "ap":
                continue

            fields = [f.strip() for f in line.split(",")]

            if section == "ap" and len(fields) >= 14:
                ap = {
                    "bssid": fields[0],
                    "first_seen": fields[1],
                    "last_seen": fields[2],
                    "channel": fields[3],
                    "speed": fields[4],
                    "privacy": fields[5],
                    "cipher": fields[6],
                    "authentication": fields[7],
                    "power": fields[8],
                    "beacons": fields[9],
                    "iv": fields[10],
                    "lan_ip": fields[11],
                    "id_length": fields[12],
                    "essid": fields[13] if len(fields) > 13 else "",
                }
                if ap["bssid"] and ap["bssid"] != "BSSID":
                    aps.append(ap)

            elif section == "client" and len(fields) >= 6:
                client = {
                    "station_mac": fields[0],
                    "first_seen": fields[1],
                    "last_seen": fields[2],
                    "power": fields[3],
                    "packets": fields[4],
                    "bssid": fields[5],
                    "probed_essids": fields[6] if len(fields) > 6 else "",
                }
                if client["station_mac"] and client["station_mac"] != "Station MAC":
                    clients.append(client)

    return aps, clients


def detect_rogue_aps(aps: list[dict], authorized_file: str) -> list[dict]:
    """Compare discovered APs against authorized list."""
    authorized_bssids = set()
    try:
        with open(authorized_file) as f:
            for line in f:
                bssid = line.strip().upper()
                if bssid:
                    authorized_bssids.add(bssid)
    except FileNotFoundError:
        print(f"[-] Authorized AP file not found: {authorized_file}")
        return []

    rogue_aps = []
    for ap in aps:
        if ap["bssid"].upper() not in authorized_bssids:
            rogue_aps.append(ap)

    return rogue_aps


def assess_encryption(aps: list[dict]) -> list[dict]:
    """Assess encryption strength of discovered APs."""
    findings = []
    for ap in aps:
        privacy = ap.get("privacy", "").upper()
        finding = {
            "essid": ap["essid"],
            "bssid": ap["bssid"],
            "encryption": privacy,
            "severity": "Info",
            "issue": None,
        }

        if "WEP" in privacy:
            finding["severity"] = "Critical"
            finding["issue"] = "WEP encryption is trivially crackable"
        elif "OPN" in privacy or not privacy.strip():
            finding["severity"] = "High"
            finding["issue"] = "Open network with no encryption"
        elif "WPA" in privacy and "TKIP" in ap.get("cipher", "").upper():
            finding["severity"] = "Medium"
            finding["issue"] = "TKIP cipher is deprecated"
        elif "WPA2" in privacy and "PSK" in ap.get("authentication", "").upper():
            finding["severity"] = "Low"
            finding["issue"] = "WPA2-PSK susceptible to dictionary attacks"
        elif "WPA3" in privacy:
            finding["severity"] = "Info"
            finding["issue"] = "WPA3-SAE provides strong protection"

        if finding["issue"]:
            findings.append(finding)

    return findings


def generate_report(aps: list[dict], clients: list[dict],
                     rogue_aps: list[dict], findings: list[dict],
                     output_dir: Path) -> str:
    """Generate wireless assessment report."""
    report_file = output_dir / "wireless_assessment_report.md"
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    with open(report_file, "w") as f:
        f.write("# Wireless Network Penetration Test Report\n\n")
        f.write(f"**Generated:** {timestamp}\n\n---\n\n")

        f.write("## Network Discovery\n\n")
        f.write(f"Total access points: **{len(aps)}**\n")
        f.write(f"Total clients: **{len(clients)}**\n\n")

        f.write("### Discovered Access Points\n\n")
        f.write("| ESSID | BSSID | Channel | Encryption | Auth | Signal |\n")
        f.write("|-------|-------|---------|-----------|------|--------|\n")
        for ap in aps:
            f.write(f"| {ap['essid']} | {ap['bssid']} | {ap['channel']} "
                    f"| {ap['privacy']} | {ap['authentication']} | {ap['power']}dBm |\n")
        f.write("\n")

        if rogue_aps:
            f.write("## Rogue Access Points\n\n")
            f.write(f"**{len(rogue_aps)} unauthorized APs detected**\n\n")
            for rap in rogue_aps:
                f.write(f"- **{rap['essid']}** ({rap['bssid']}) — Ch {rap['channel']}\n")
            f.write("\n")

        f.write("## Security Findings\n\n")
        for finding in sorted(findings, key=lambda x: {"Critical": 0, "High": 1,
                                                         "Medium": 2, "Low": 3,
                                                         "Info": 4}.get(x["severity"], 5)):
            f.write(f"### [{finding['severity']}] {finding['essid']}\n")
            f.write(f"- BSSID: {finding['bssid']}\n")
            f.write(f"- Issue: {finding['issue']}\n\n")

        f.write("## Recommendations\n\n")
        f.write("1. Upgrade all WEP/open networks to WPA2-Enterprise or WPA3\n")
        f.write("2. Deploy WIDS/WIPS for rogue AP detection\n")
        f.write("3. Use 20+ character passphrases for any remaining PSK networks\n")
        f.write("4. Enable client isolation on guest networks\n")
        f.write("5. Implement 802.1X with certificate validation\n")

    print(f"[+] Report: {report_file}")
    return str(report_file)


def main():
    parser = argparse.ArgumentParser(description="Wireless Pentest Report Generator")
    parser.add_argument("--scan-file", required=True, help="Airodump-ng CSV file")
    parser.add_argument("--authorized-aps", help="File with authorized BSSIDs")
    parser.add_argument("--output", default="./results")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    aps, clients = parse_airodump_csv(args.scan_file)
    print(f"[+] Parsed {len(aps)} APs and {len(clients)} clients")

    rogue_aps = []
    if args.authorized_aps:
        rogue_aps = detect_rogue_aps(aps, args.authorized_aps)

    findings = assess_encryption(aps)
    generate_report(aps, clients, rogue_aps, findings, output_dir)


if __name__ == "__main__":
    main()
