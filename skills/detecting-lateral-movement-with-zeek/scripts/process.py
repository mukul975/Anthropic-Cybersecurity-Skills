#!/usr/bin/env python3
"""Parse Zeek logs to detect lateral movement indicators.

Usage:
    python process.py smb_mapping <log_file> [--internal-nets 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]
    python process.py conn <log_file>
    python process.py ntlm <log_file> [--window 300]
    python process.py dce_rpc <log_file> [--dc-ips 10.0.1.1,10.0.1.2]
"""
import csv
import sys
import ipaddress
from collections import defaultdict

DEFAULT_INTERNAL = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def is_internal(ip_str, networks):
    """Check if IP is in internal networks."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in networks)
    except ValueError:
        return False


def parse_internal_nets(nets_str):
    """Parse comma-separated CIDR networks."""
    if not nets_str:
        return [ipaddress.ip_network(n) for n in DEFAULT_INTERNAL]
    return [ipaddress.ip_network(n.strip()) for n in nets_str.split(",")]


def parse_zeek_log(filepath):
    """Parse a Zeek TSV log file, skipping comment lines."""
    rows = []
    fields = []
    with open(filepath) as f:
        for line in f:
            if line.startswith('#fields'):
                fields = line.strip().split('\t')[1:]
            elif not line.startswith('#'):
                values = line.strip().split('\t')
                if fields and len(values) == len(fields):
                    rows.append(dict(zip(fields, values)))
    return rows


def detect_admin_shares(log_file, internal_nets):
    """Detect admin share access — only between internal hosts."""
    networks = parse_internal_nets(internal_nets)
    entries = parse_zeek_log(log_file)
    for entry in entries:
        src = entry.get('id.orig_h', '')
        dst = entry.get('id.resp_h', '')
        share = entry.get('path', '') or entry.get('share_type', '')
        if not (is_internal(src, networks) and is_internal(dst, networks)):
            continue
        share_upper = share.upper()
        if any(s in share_upper for s in ['ADMIN$', 'C$', 'IPC$']):
            severity = "HIGH" if 'ADMIN$' in share_upper or 'C$' in share_upper else "MEDIUM"
            print(f"[{severity}] ADMIN SHARE: {entry.get('ts', '')} {src} -> {dst} ({share})")


def detect_rdp_pivots(log_file, window_minutes=10):
    """Detect RDP pivot chains from conn.log."""
    entries = parse_zeek_log(log_file)
    rdp_sessions = [(float(e.get('ts', 0)), e.get('id.orig_h', ''), e.get('id.resp_h', ''))
                     for e in entries if e.get('id.resp_p') == '3389']
    rdp_sessions.sort()
    
    # Find chains: A->B then B->C within window
    dst_arrivals = defaultdict(list)
    for ts, src, dst in rdp_sessions:
        dst_arrivals[dst].append((ts, src))
    
    for ts, src, dst in rdp_sessions:
        for arrival_ts, arrival_src in dst_arrivals.get(src, []):
            if 0 < (ts - arrival_ts) < window_minutes * 60:
                print(f"[HIGH] RDP PIVOT: {arrival_src} -> {src} -> {dst} (delta: {int(ts - arrival_ts)}s)")


def detect_ntlm_spray(log_file, window_seconds=300, threshold=3):
    """Detect NTLM account spray via time-windowed burst analysis."""
    entries = parse_zeek_log(log_file)
    user_events = defaultdict(list)
    
    for entry in entries:
        user = entry.get('username', '')
        dst = entry.get('id.resp_h', '')
        ts = float(entry.get('ts', 0))
        if user and user != '-':
            user_events[user].append((ts, dst))
    
    for user, events in user_events.items():
        events.sort()
        # Sliding window analysis
        for i, (ts_start, _) in enumerate(events):
            window_hosts = set()
            for j in range(i, len(events)):
                ts_j, dst_j = events[j]
                if ts_j - ts_start > window_seconds:
                    break
                window_hosts.add(dst_j)
            if len(window_hosts) >= threshold:
                print(f"[CRITICAL] NTLM ACCOUNT SPRAY: {user} authenticated to {len(window_hosts)} "
                      f"hosts within {window_seconds}s: {', '.join(sorted(window_hosts))}")
                break  # One alert per user


def detect_dcsync(log_file, dc_ips=None):
    """Detect DCSync attacks via DRS replication calls — requires DC IPs."""
    if not dc_ips:
        print("[WARN] DCSync detection skipped: --dc-ips not provided. "
              "Specify domain controller IPs to enable this detector.")
        return
    
    dc_set = set(dc_ips.split(","))
    entries = parse_zeek_log(log_file)
    for entry in entries:
        src = entry.get('id.orig_h', '')
        dst = entry.get('id.resp_h', '')
        operation = entry.get('operation', '')
        if dst in dc_set and src not in dc_set:
            if 'DrsReplicaAdd' in operation or 'DrsGetNCChanges' in operation:
                print(f"[CRITICAL] DCSYNC: {src} -> {dst} ({operation})")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    
    log_type, log_file = sys.argv[1], sys.argv[2]
    
    # Parse optional args
    args = {sys.argv[i]: sys.argv[i+1] for i in range(3, len(sys.argv)-1, 2) if sys.argv[i].startswith('--')}
    
    if log_type == "smb_mapping":
        detect_admin_shares(log_file, args.get('--internal-nets'))
    elif log_type == "conn":
        detect_rdp_pivots(log_file, int(args.get('--window', 10)))
    elif log_type == "ntlm":
        detect_ntlm_spray(log_file, int(args.get('--window', 300)), int(args.get('--threshold', 3)))
    elif log_type == "dce_rpc":
        detect_dcsync(log_file, args.get('--dc-ips'))
    else:
        print(f"Unknown log type: {log_type}")
        sys.exit(1)
