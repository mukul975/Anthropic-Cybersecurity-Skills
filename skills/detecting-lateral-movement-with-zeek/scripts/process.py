#!/usr/bin/env python3
"""
Zeek Lateral Movement Detector
===============================
Parses Zeek log files (conn.log, smb_mapping.log, dce_rpc.log, ntlm.log, rdp.log)
and identifies indicators of lateral movement activity.

Usage:
    python3 process.py --log-dir /var/log/zeek/current/ --output report.json
    python3 process.py --conn-log conn.log --smb-log smb_mapping.log
    python3 process.py --log-dir /var/log/zeek/current/ --internal-nets 10.0.0.0/8 172.16.0.0/12

Outputs a JSON report of findings ranked by severity.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ADMIN_SHARES = {"c$", "admin$", "ipc$"}
LATERAL_PORTS = {445, 3389, 135, 5985, 5986, 22}
PSEXEC_SVCCTL_OPNUM = 12  # CreateServiceW
DCSYNC_DRSUAPI_OPNUM = 3  # DRSGetNCChanges

DEFAULT_INTERNAL_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    timestamp: str
    severity: str  # critical, high, medium, low
    category: str
    source_ip: str
    dest_ip: str
    description: str
    mitre_technique: str
    uid: str = ""
    details: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Zeek log parser
# ---------------------------------------------------------------------------


def parse_zeek_log(filepath: str) -> list[dict]:
    """Parse a Zeek TSV log file, respecting its #fields header."""
    rows: list[dict] = []
    fields: list[str] = []

    if not os.path.isfile(filepath):
        return rows

    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if not fields:
                continue
            values = line.split("\t")
            row = {}
            for i, f in enumerate(fields):
                row[f] = values[i] if i < len(values) else "-"
            rows.append(row)

    return rows


def is_internal(ip_str: str, internal_nets: list[ipaddress.IPv4Network]) -> bool:
    """Check whether an IP belongs to an internal network."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in internal_nets)


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def detect_admin_share_access(
    smb_rows: list[dict], internal_nets: list
) -> list[Finding]:
    """Detect access to administrative shares (C$, ADMIN$, IPC$)."""
    findings: list[Finding] = []
    for row in smb_rows:
        path = row.get("path", "").lower()
        share_name = path.rsplit("\\", 1)[-1] if "\\" in path else path
        if share_name in ADMIN_SHARES:
            src = row.get("id.orig_h", "-")
            dst = row.get("id.resp_h", "-")
            ts = row.get("ts", "-")
            uid = row.get("uid", "-")
            findings.append(
                Finding(
                    timestamp=ts,
                    severity="high",
                    category="SMB Admin Share Access",
                    source_ip=src,
                    dest_ip=dst,
                    description=f"Host {src} accessed admin share {path} on {dst}",
                    mitre_technique="T1021.002",
                    uid=uid,
                    details={"share": share_name, "full_path": path},
                )
            )
    return findings


def detect_internal_lateral_connections(
    conn_rows: list[dict], internal_nets: list
) -> list[Finding]:
    """Detect internal-to-internal connections on lateral movement ports."""
    findings: list[Finding] = []
    src_dst_count: dict[str, set[str]] = defaultdict(set)

    for row in conn_rows:
        src = row.get("id.orig_h", "-")
        dst = row.get("id.resp_h", "-")
        try:
            dport = int(row.get("id.resp_p", "0"))
        except ValueError:
            continue

        if dport not in LATERAL_PORTS:
            continue
        if not (is_internal(src, internal_nets) and is_internal(dst, internal_nets)):
            continue

        src_dst_count[src].add(dst)

    # Flag hosts connecting to many internal hosts on lateral ports
    for src, destinations in src_dst_count.items():
        if len(destinations) >= 3:
            findings.append(
                Finding(
                    timestamp="-",
                    severity="high",
                    category="Internal Lateral Sweep",
                    source_ip=src,
                    dest_ip=", ".join(sorted(destinations)[:10]),
                    description=(
                        f"Host {src} connected to {len(destinations)} internal hosts "
                        f"on lateral movement ports"
                    ),
                    mitre_technique="T1021",
                    details={
                        "destination_count": len(destinations),
                        "sample_destinations": sorted(destinations)[:10],
                    },
                )
            )

    return findings


def detect_psexec_patterns(dce_rows: list[dict]) -> list[Finding]:
    """Detect PsExec-style service creation via SVCCTL RPC."""
    findings: list[Finding] = []
    for row in dce_rows:
        endpoint = row.get("endpoint", "").lower()
        try:
            opnum = int(row.get("operation", "-1"))
        except ValueError:
            continue

        if endpoint == "svcctl" and opnum == PSEXEC_SVCCTL_OPNUM:
            src = row.get("id.orig_h", "-")
            dst = row.get("id.resp_h", "-")
            ts = row.get("ts", "-")
            uid = row.get("uid", "-")
            findings.append(
                Finding(
                    timestamp=ts,
                    severity="critical",
                    category="PsExec Service Installation",
                    source_ip=src,
                    dest_ip=dst,
                    description=(
                        f"Remote service creation (SVCCTL CreateServiceW) "
                        f"from {src} to {dst} — PsExec pattern"
                    ),
                    mitre_technique="T1021.002 / T1569.002",
                    uid=uid,
                )
            )
    return findings


def detect_dcsync(
    dce_rows: list[dict], dc_ips: Optional[set[str]] = None
) -> list[Finding]:
    """Detect DCSync — DRSGetNCChanges from non-DC hosts."""
    findings: list[Finding] = []
    dc_ips = dc_ips or set()

    for row in dce_rows:
        endpoint = row.get("endpoint", "").lower()
        try:
            opnum = int(row.get("operation", "-1"))
        except ValueError:
            continue

        if endpoint == "drsuapi" and opnum == DCSYNC_DRSUAPI_OPNUM:
            src = row.get("id.orig_h", "-")
            dst = row.get("id.resp_h", "-")
            ts = row.get("ts", "-")
            uid = row.get("uid", "-")

            if src not in dc_ips:
                findings.append(
                    Finding(
                        timestamp=ts,
                        severity="critical",
                        category="DCSync Attack",
                        source_ip=src,
                        dest_ip=dst,
                        description=(
                            f"Non-DC host {src} requested directory replication "
                            f"(DRSGetNCChanges) from {dst} — DCSync attack"
                        ),
                        mitre_technique="T1003.006",
                        uid=uid,
                    )
                )
    return findings


def detect_rdp_pivoting(rdp_rows: list[dict], internal_nets: list) -> list[Finding]:
    """Detect RDP pivoting — one host RDPing to multiple destinations."""
    findings: list[Finding] = []
    rdp_map: dict[str, set[str]] = defaultdict(set)

    for row in rdp_rows:
        src = row.get("id.orig_h", "-")
        dst = row.get("id.resp_h", "-")
        if is_internal(src, internal_nets) and is_internal(dst, internal_nets):
            rdp_map[src].add(dst)

    for src, destinations in rdp_map.items():
        if len(destinations) >= 3:
            findings.append(
                Finding(
                    timestamp="-",
                    severity="high",
                    category="RDP Pivoting",
                    source_ip=src,
                    dest_ip=", ".join(sorted(destinations)[:10]),
                    description=(
                        f"Host {src} has RDP sessions to {len(destinations)} "
                        f"internal hosts — possible pivot"
                    ),
                    mitre_technique="T1021.001",
                    details={
                        "destination_count": len(destinations),
                        "destinations": sorted(destinations)[:10],
                    },
                )
            )

    return findings


def detect_ntlm_bursts(ntlm_rows: list[dict], threshold: int = 5) -> list[Finding]:
    """Detect NTLM authentication bursts suggesting Pass-the-Hash."""
    findings: list[Finding] = []
    ntlm_count: dict[str, list[dict]] = defaultdict(list)

    for row in ntlm_rows:
        src = row.get("id.orig_h", "-")
        ntlm_count[src].append(row)

    for src, rows in ntlm_count.items():
        if len(rows) >= threshold:
            users = {r.get("username", "-") for r in rows}
            domains = {r.get("domainname", "-") for r in rows}
            destinations = {r.get("id.resp_h", "-") for r in rows}
            findings.append(
                Finding(
                    timestamp=rows[0].get("ts", "-"),
                    severity="medium",
                    category="Pass-the-Hash Suspected",
                    source_ip=src,
                    dest_ip=", ".join(sorted(destinations)[:5]),
                    description=(
                        f"Host {src} performed {len(rows)} NTLM authentications — "
                        f"possible Pass-the-Hash. Users: {', '.join(users)}"
                    ),
                    mitre_technique="T1550.002",
                    details={
                        "auth_count": len(rows),
                        "users": sorted(users),
                        "domains": sorted(domains),
                        "destinations": sorted(destinations)[:10],
                    },
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def generate_report(findings: list[Finding]) -> dict:
    """Generate a structured JSON report from findings."""
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    summary = defaultdict(int)
    for f in findings:
        summary[f.severity] += 1

    return {
        "report_generated": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "summary": dict(summary),
        "findings": [asdict(f) for f in findings],
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Zeek Lateral Movement Detector — parse Zeek logs for lateral movement indicators"
    )
    parser.add_argument(
        "--log-dir",
        help="Directory containing Zeek log files",
    )
    parser.add_argument("--conn-log", help="Path to conn.log")
    parser.add_argument("--smb-log", help="Path to smb_mapping.log")
    parser.add_argument("--dce-log", help="Path to dce_rpc.log")
    parser.add_argument("--ntlm-log", help="Path to ntlm.log")
    parser.add_argument("--rdp-log", help="Path to rdp.log")
    parser.add_argument("--output", "-o", help="Output JSON report path", default="-")
    parser.add_argument(
        "--internal-nets",
        nargs="*",
        help="Internal network CIDRs (default: RFC1918)",
    )
    parser.add_argument(
        "--dc-ips",
        nargs="*",
        help="Known domain controller IPs (to exclude from DCSync detection)",
    )
    parser.add_argument(
        "--ntlm-threshold",
        type=int,
        default=5,
        help="NTLM auth count threshold for PtH detection (default: 5)",
    )

    args = parser.parse_args()

    # Resolve internal networks
    if args.internal_nets:
        internal_nets = [ipaddress.ip_network(n, strict=False) for n in args.internal_nets]
    else:
        internal_nets = DEFAULT_INTERNAL_NETS

    dc_ips = set(args.dc_ips) if args.dc_ips else set()

    # Resolve log file paths
    def resolve_log(explicit: Optional[str], log_dir: Optional[str], filename: str) -> str:
        if explicit:
            return explicit
        if log_dir:
            return os.path.join(log_dir, filename)
        return ""

    conn_path = resolve_log(args.conn_log, args.log_dir, "conn.log")
    smb_path = resolve_log(args.smb_log, args.log_dir, "smb_mapping.log")
    dce_path = resolve_log(args.dce_log, args.log_dir, "dce_rpc.log")
    ntlm_path = resolve_log(args.ntlm_log, args.log_dir, "ntlm.log")
    rdp_path = resolve_log(args.rdp_log, args.log_dir, "rdp.log")

    # Parse logs
    conn_rows = parse_zeek_log(conn_path) if conn_path else []
    smb_rows = parse_zeek_log(smb_path) if smb_path else []
    dce_rows = parse_zeek_log(dce_path) if dce_path else []
    ntlm_rows = parse_zeek_log(ntlm_path) if ntlm_path else []
    rdp_rows = parse_zeek_log(rdp_path) if rdp_path else []

    log_counts = {
        "conn.log": len(conn_rows),
        "smb_mapping.log": len(smb_rows),
        "dce_rpc.log": len(dce_rows),
        "ntlm.log": len(ntlm_rows),
        "rdp.log": len(rdp_rows),
    }
    print(f"[*] Parsed log entries: {json.dumps(log_counts)}", file=sys.stderr)

    # Run detectors
    findings: list[Finding] = []
    findings.extend(detect_admin_share_access(smb_rows, internal_nets))
    findings.extend(detect_internal_lateral_connections(conn_rows, internal_nets))
    findings.extend(detect_psexec_patterns(dce_rows))
    findings.extend(detect_dcsync(dce_rows, dc_ips))
    findings.extend(detect_rdp_pivoting(rdp_rows, internal_nets))
    findings.extend(detect_ntlm_bursts(ntlm_rows, args.ntlm_threshold))

    # Generate report
    report = generate_report(findings)
    report["logs_parsed"] = log_counts

    report_json = json.dumps(report, indent=2)

    if args.output == "-":
        print(report_json)
    else:
        with open(args.output, "w") as fh:
            fh.write(report_json)
        print(f"[+] Report written to {args.output}", file=sys.stderr)

    # Print summary
    print(f"\n[+] Total findings: {report['total_findings']}", file=sys.stderr)
    for sev, count in sorted(report["summary"].items(), key=lambda x: SEVERITY_ORDER.get(x[0], 99)):
        print(f"    {sev.upper()}: {count}", file=sys.stderr)


if __name__ == "__main__":
    main()
