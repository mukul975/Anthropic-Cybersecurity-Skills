#!/usr/bin/env python3
"""Parse Zeek logs to detect lateral movement indicators."""
import csv
import sys
from collections import defaultdict
from datetime import datetime, timedelta

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

def detect_admin_shares(smb_mapping_log):
    """Detect admin share access patterns."""
    entries = parse_zeek_log(smb_mapping_log)
    suspicious = []
    for entry in entries:
        share = entry.get('share_type', '') or entry.get('path', '')
        if any(s in share.upper() for s in ['ADMIN$', 'C$', 'IPC$']):
            suspicious.append({
                'timestamp': entry.get('ts', ''),
                'source': entry.get('id.orig_h', ''),
                'destination': entry.get('id.resp_h', ''),
                'share': share
            })
    return suspicious

def detect_rdp_pivots(conn_log, window_minutes=10):
    """Detect RDP pivot chains from conn.log."""
    entries = parse_zeek_log(conn_log)
    rdp_sessions = [e for e in entries if e.get('id.resp_p') == '3389']
    
    pivots = []
    dst_to_src = defaultdict(list)
    for session in rdp_sessions:
        src = session.get('id.orig_h', '')
        dst = session.get('id.resp_h', '')
        ts = float(session.get('ts', 0))
        dst_to_src[dst].append((ts, src))
    
    for host, incoming in dst_to_src.items():
        outgoing = [e for e in rdp_sessions if e.get('id.orig_h') == host]
        for out_session in outgoing:
            out_ts = float(out_session.get('ts', 0))
            out_dst = out_session.get('id.resp_h', '')
            for in_ts, in_src in incoming:
                if 0 < (out_ts - in_ts) < window_minutes * 60:
                    pivots.append(f"{in_src} -> {host} -> {out_dst}")
    return pivots

def detect_ntlm_spray(ntlm_log, window_seconds=300, threshold=3):
    """Detect same account authenticating to multiple hosts (pass-the-hash indicator)."""
    entries = parse_zeek_log(ntlm_log)
    user_hosts = defaultdict(set)
    user_times = defaultdict(list)
    
    for entry in entries:
        user = entry.get('username', '')
        dst = entry.get('id.resp_h', '')
        ts = float(entry.get('ts', 0))
        if user and user != '-':
            user_hosts[user].add(dst)
            user_times[user].append(ts)
    
    suspicious = {}
    for user, hosts in user_hosts.items():
        if len(hosts) >= threshold:
            times = sorted(user_times[user])
            if times[-1] - times[0] < window_seconds:
                suspicious[user] = list(hosts)
    return suspicious

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python process.py <log_type> <log_file>")
        print("  log_type: smb_mapping | conn | ntlm")
        sys.exit(1)
    
    log_type, log_file = sys.argv[1], sys.argv[2]
    
    if log_type == "smb_mapping":
        results = detect_admin_shares(log_file)
        for r in results:
            print(f"[ADMIN SHARE] {r['timestamp']} {r['source']} -> {r['destination']} ({r['share']})")
    elif log_type == "conn":
        pivots = detect_rdp_pivots(log_file)
        for p in pivots:
            print(f"[RDP PIVOT] {p}")
    elif log_type == "ntlm":
        spray = detect_ntlm_spray(log_file)
        for user, hosts in spray.items():
            print(f"[PASS-THE-HASH] {user} authenticated to {len(hosts)} hosts: {', '.join(hosts)}")
