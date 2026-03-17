#!/usr/bin/env python3
"""
Zeek Lateral Movement Detector

Parses Zeek log files (conn.log, smb_mapping.log, dce_rpc.log, ntlm.log,
files.log) and identifies indicators of lateral movement including:

- SMB admin share access (PsExec / T1021.002)
- RDP pivoting patterns (T1021.001)
- Pass-the-Hash via NTLM analysis (T1550.002)
- DCSync attempts via DCE/RPC (T1003.006)
- Lateral tool transfer of executables (T1570)

Usage:
    python3 process.py --log-dir /opt/zeek/logs/current --output report.json
    python3 process.py --log-dir /opt/zeek/logs/current --verbose
"""

import argparse
import csv
import ipaddress
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Internal network ranges for filtering
INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# Thresholds
PTH_SOURCE_THRESHOLD = 3  # Min distinct sources for same user to flag PtH
ADMIN_SHARES = {"c$", "admin$", "ipc$"}
EXECUTABLE_MIME_TYPES = {
    "application/x-dosexec",
    "application/x-executable",
    "application/x-mach-binary",
    "application/x-elf",
}


def is_internal(ip_str: str) -> bool:
    """Check if an IP address is in a private/internal range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in INTERNAL_NETWORKS)
    except ValueError:
        return False


def parse_zeek_log(filepath: str) -> list[dict[str, str]]:
    """
    Parse a Zeek tab-separated log file, handling the #fields header.
    Returns a list of dicts keyed by field names.
    """
    records = []
    fields = None

    if not os.path.exists(filepath):
        return records

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#fields"):
                # Extract field names from the #fields directive
                fields = line.split("\t")[1:]
            elif line.startswith("#") or not line:
                continue
            elif fields:
                values = line.split("\t")
                if len(values) == len(fields):
                    record = dict(zip(fields, values))
                    records.append(record)

    return records


def ts_to_iso(ts_str: str) -> str:
    """Convert Zeek epoch timestamp to ISO 8601 string."""
    try:
        epoch = float(ts_str)
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    except (ValueError, OSError):
        return ts_str


def detect_admin_share_access(log_dir: str, verbose: bool = False) -> list[dict[str, Any]]:
    """Detect access to admin shares (C$, ADMIN$, IPC$) in smb_mapping.log."""
    findings = []
    smb_log = os.path.join(log_dir, "smb_mapping.log")
    records = parse_zeek_log(smb_log)

    if verbose:
        print(f"[*] Parsing {smb_log}: {len(records)} records")

    for rec in records:
        orig_h = rec.get("id.orig_h", "")
        resp_h = rec.get("id.resp_h", "")
        path = rec.get("path", "")

        if not (is_internal(orig_h) and is_internal(resp_h)):
            continue

        # Extract share name from UNC path (e.g., \\server\ADMIN$)
        share_name = path.rstrip("\\").split("\\")[-1].lower() if path else ""

        if share_name in ADMIN_SHARES:
            finding = {
                "timestamp": ts_to_iso(rec.get("ts", "")),
                "source": orig_h,
                "destination": resp_h,
                "share_path": path,
                "mitre_technique": "T1021.002",
                "description": f"Admin share access: {orig_h} -> {resp_h} ({path})",
            }
            findings.append(finding)
            if verbose:
                print(f"  [!] Admin share: {finding['description']}")

    return findings


def detect_rdp_pivots(log_dir: str, verbose: bool = False) -> list[dict[str, Any]]:
    """Detect RDP pivoting: hosts that are both RDP clients and servers."""
    findings = []
    conn_log = os.path.join(log_dir, "conn.log")
    records = parse_zeek_log(conn_log)

    if verbose:
        print(f"[*] Parsing {conn_log}: {len(records)} records")

    # Track inbound and outbound RDP connections
    rdp_inbound: dict[str, set[str]] = defaultdict(set)   # dest -> set of sources
    rdp_outbound: dict[str, set[str]] = defaultdict(set)  # source -> set of dests

    for rec in records:
        resp_p = rec.get("id.resp_p", "")
        if resp_p != "3389":
            continue

        orig_h = rec.get("id.orig_h", "")
        resp_h = rec.get("id.resp_h", "")

        if not (is_internal(orig_h) and is_internal(resp_h)):
            continue

        rdp_inbound[resp_h].add(orig_h)
        rdp_outbound[orig_h].add(resp_h)

    # Find pivot hosts: received RDP AND initiated RDP to different hosts
    for host in set(rdp_inbound.keys()) & set(rdp_outbound.keys()):
        inbound_sources = rdp_inbound[host]
        outbound_dests = rdp_outbound[host]

        for src in inbound_sources:
            for dst in outbound_dests:
                if src != dst:
                    chain = [src, host, dst]
                    finding = {
                        "chain": chain,
                        "pivot_host": host,
                        "mitre_technique": "T1021.001",
                        "description": f"RDP pivot: {src} -> {host} -> {dst}",
                    }
                    findings.append(finding)
                    if verbose:
                        print(f"  [!] RDP pivot: {finding['description']}")

    return findings


def detect_pass_the_hash(log_dir: str, verbose: bool = False) -> list[dict[str, Any]]:
    """Detect Pass-the-Hash: same user authenticating from multiple sources."""
    findings = []
    ntlm_log = os.path.join(log_dir, "ntlm.log")
    records = parse_zeek_log(ntlm_log)

    if verbose:
        print(f"[*] Parsing {ntlm_log}: {len(records)} records")

    # Track sources per username
    user_sources: dict[str, set[str]] = defaultdict(set)

    for rec in records:
        username = rec.get("username", "")
        orig_h = rec.get("id.orig_h", "")
        success = rec.get("success", "")

        if not username or username == "-" or success != "T":
            continue

        if is_internal(orig_h):
            user_sources[username].add(orig_h)

    for username, sources in user_sources.items():
        if len(sources) >= PTH_SOURCE_THRESHOLD:
            finding = {
                "username": username,
                "source_count": len(sources),
                "sources": sorted(sources),
                "mitre_technique": "T1550.002",
                "description": (
                    f"Possible Pass-the-Hash: '{username}' authenticated "
                    f"from {len(sources)} distinct sources"
                ),
            }
            findings.append(finding)
            if verbose:
                print(f"  [!] PtH suspect: {finding['description']}")

    return findings


def detect_dcsync(
    log_dir: str, dc_ips: list[str] | None = None, verbose: bool = False
) -> list[dict[str, Any]]:
    """Detect DCSync: drsuapi calls from non-DC hosts."""
    findings = []
    dce_log = os.path.join(log_dir, "dce_rpc.log")
    records = parse_zeek_log(dce_log)
    dc_set = set(dc_ips) if dc_ips else set()

    if verbose:
        print(f"[*] Parsing {dce_log}: {len(records)} records")

    for rec in records:
        endpoint = rec.get("endpoint", "").lower()
        operation = rec.get("operation", "").lower()
        orig_h = rec.get("id.orig_h", "")
        resp_h = rec.get("id.resp_h", "")

        if "drsuapi" in endpoint:
            if orig_h not in dc_set:
                finding = {
                    "timestamp": ts_to_iso(rec.get("ts", "")),
                    "source": orig_h,
                    "destination": resp_h,
                    "endpoint": endpoint,
                    "operation": operation,
                    "mitre_technique": "T1003.006",
                    "description": (
                        f"Possible DCSync: non-DC host {orig_h} "
                        f"calling drsuapi on {resp_h}"
                    ),
                }
                findings.append(finding)
                if verbose:
                    print(f"  [!] DCSync: {finding['description']}")

    return findings


def detect_lateral_tool_transfer(log_dir: str, verbose: bool = False) -> list[dict[str, Any]]:
    """Detect executable file transfers between internal hosts."""
    findings = []
    files_log = os.path.join(log_dir, "files.log")
    records = parse_zeek_log(files_log)

    if verbose:
        print(f"[*] Parsing {files_log}: {len(records)} records")

    for rec in records:
        mime_type = rec.get("mime_type", "").lower()

        if mime_type not in EXECUTABLE_MIME_TYPES:
            continue

        tx_hosts = rec.get("tx_hosts", "")
        rx_hosts = rec.get("rx_hosts", "")

        # Parse comma-separated host lists
        for tx in tx_hosts.split(","):
            tx = tx.strip()
            for rx in rx_hosts.split(","):
                rx = rx.strip()
                if tx and rx and is_internal(tx) and is_internal(rx) and tx != rx:
                    finding = {
                        "timestamp": ts_to_iso(rec.get("ts", "")),
                        "source": tx,
                        "destination": rx,
                        "filename": rec.get("filename", "-"),
                        "mime_type": mime_type,
                        "size_bytes": int(rec.get("total_bytes", 0) or 0),
                        "mitre_technique": "T1570",
                        "description": (
                            f"Executable transfer: {tx} -> {rx} "
                            f"file={rec.get('filename', '-')} "
                            f"({mime_type})"
                        ),
                    }
                    findings.append(finding)
                    if verbose:
                        print(f"  [!] Tool transfer: {finding['description']}")

    return findings


def determine_severity(findings: dict[str, list]) -> str:
    """Determine overall severity based on findings."""
    total = sum(len(v) for v in findings.values())
    has_dcsync = len(findings.get("dcsync_attempts", [])) > 0
    has_pth = len(findings.get("pass_the_hash_suspects", [])) > 0
    has_admin = len(findings.get("admin_share_access", [])) > 0

    if has_dcsync:
        return "CRITICAL"
    if has_pth and has_admin:
        return "HIGH"
    if total >= 5:
        return "HIGH"
    if total >= 2:
        return "MEDIUM"
    if total >= 1:
        return "LOW"
    return "NONE"


def generate_recommendation(findings: dict[str, list]) -> str:
    """Generate a recommendation based on findings."""
    # Collect all source IPs across findings
    sources: dict[str, int] = defaultdict(int)

    for category, items in findings.items():
        for item in items:
            if "source" in item:
                sources[item["source"]] += 1
            if "sources" in item:
                for s in item["sources"]:
                    sources[s] += 1

    if not sources:
        return "No lateral movement indicators detected."

    top_source = max(sources, key=sources.get)
    return (
        f"Investigate host {top_source} as potential pivot point — "
        f"appeared in {sources[top_source]} lateral movement indicators."
    )


def main():
    parser = argparse.ArgumentParser(
        description="Detect lateral movement indicators in Zeek logs"
    )
    parser.add_argument(
        "--log-dir",
        required=True,
        help="Path to Zeek log directory (e.g., /opt/zeek/logs/current)",
    )
    parser.add_argument(
        "--output",
        help="Output JSON report file path",
    )
    parser.add_argument(
        "--dc-ips",
        nargs="*",
        default=[],
        help="Known domain controller IP addresses (for DCSync detection)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed findings to stderr",
    )

    args = parser.parse_args()

    if not os.path.isdir(args.log_dir):
        print(f"Error: Log directory not found: {args.log_dir}", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        print(f"[*] Scanning Zeek logs in: {args.log_dir}", file=sys.stderr)

    # Run all detections
    findings = {
        "admin_share_access": detect_admin_share_access(args.log_dir, args.verbose),
        "rdp_pivots": detect_rdp_pivots(args.log_dir, args.verbose),
        "pass_the_hash_suspects": detect_pass_the_hash(args.log_dir, args.verbose),
        "dcsync_attempts": detect_dcsync(args.log_dir, args.dc_ips, args.verbose),
        "lateral_tool_transfers": detect_lateral_tool_transfer(args.log_dir, args.verbose),
    }

    total_findings = sum(len(v) for v in findings.values())
    severity = determine_severity(findings)
    recommendation = generate_recommendation(findings)

    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "log_directory": args.log_dir,
        "findings": findings,
        "summary": {
            "total_findings": total_findings,
            "severity": severity,
            "recommendation": recommendation,
        },
    }

    report_json = json.dumps(report, indent=2, default=str)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report_json)
        print(f"Report written to: {args.output}")
    else:
        print(report_json)

    if args.verbose:
        print(f"\n[*] Summary: {total_findings} findings, severity: {severity}", file=sys.stderr)
        print(f"[*] {recommendation}", file=sys.stderr)


if __name__ == "__main__":
    main()
