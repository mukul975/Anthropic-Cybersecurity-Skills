#!/usr/bin/env python3
"""Wireshark/tshark packet analysis agent for network security investigations."""

import subprocess
import os
import sys
import json
import re
from collections import defaultdict


def run_tshark(pcap_path, args):
    """Execute tshark with custom arguments."""
    cmd = f"tshark -r {pcap_path} {args}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def capture_live(interface, output_path, duration=60, capture_filter=None):
    """Start a live packet capture using tshark."""
    cmd = f"tshark -i {interface} -w {output_path} -a duration:{duration}"
    if capture_filter:
        cmd += f' -f "{capture_filter}"'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=duration + 10)
    return result.returncode == 0


def get_capture_summary(pcap_path):
    """Get overall PCAP capture statistics."""
    stdout, _, _ = run_tshark(pcap_path, "-q -z io,stat,0")
    return stdout


def get_protocol_hierarchy(pcap_path):
    """Get protocol hierarchy statistics."""
    stdout, _, _ = run_tshark(pcap_path, "-q -z io,phs")
    return stdout


def get_conversations(pcap_path, conv_type="ip"):
    """Get conversation statistics (ip, tcp, udp, ethernet)."""
    stdout, _, _ = run_tshark(pcap_path, f"-q -z conv,{conv_type}")
    return stdout


def get_endpoints(pcap_path, endpoint_type="ip"):
    """Get endpoint statistics."""
    stdout, _, _ = run_tshark(pcap_path, f"-q -z endpoints,{endpoint_type}")
    return stdout


def extract_http_requests(pcap_path):
    """Extract HTTP requests with key fields."""
    stdout, _, _ = run_tshark(
        pcap_path,
        '-Y "http.request" -T fields -e frame.time -e ip.src -e ip.dst '
        '-e http.request.method -e http.host -e http.request.uri -e http.user_agent '
        '-E separator="|"'
    )
    requests = []
    for line in stdout.splitlines():
        parts = line.split("|")
        if len(parts) >= 6:
            requests.append({
                "time": parts[0],
                "src": parts[1],
                "dst": parts[2],
                "method": parts[3],
                "host": parts[4],
                "uri": parts[5],
                "user_agent": parts[6] if len(parts) > 6 else "",
            })
    return requests


def extract_dns_queries(pcap_path):
    """Extract DNS queries and responses."""
    stdout, _, _ = run_tshark(
        pcap_path,
        '-Y "dns" -T fields -e frame.time -e ip.src -e ip.dst '
        '-e dns.qry.name -e dns.qry.type -e dns.flags.response '
        '-E separator="|"'
    )
    queries = []
    for line in stdout.splitlines():
        parts = line.split("|")
        if len(parts) >= 5:
            queries.append({
                "time": parts[0],
                "src": parts[1],
                "dst": parts[2],
                "query": parts[3],
                "type": parts[4],
                "is_response": parts[5] if len(parts) > 5 else "0",
            })
    return queries


def extract_tls_info(pcap_path):
    """Extract TLS handshake information including JA3 fingerprints."""
    stdout, _, _ = run_tshark(
        pcap_path,
        '-Y "tls.handshake.type==1" -T fields -e ip.src -e ip.dst '
        '-e tls.handshake.extensions_server_name -e tls.handshake.ja3 '
        '-E separator="|"'
    )
    tls_sessions = []
    for line in stdout.splitlines():
        parts = line.split("|")
        if len(parts) >= 3:
            tls_sessions.append({
                "client": parts[0],
                "server": parts[1],
                "sni": parts[2],
                "ja3": parts[3] if len(parts) > 3 else "",
            })
    return tls_sessions


def detect_suspicious_traffic(pcap_path):
    """Detect common suspicious traffic patterns."""
    findings = []

    # Large ICMP packets (possible data exfiltration)
    stdout, _, rc = run_tshark(pcap_path, '-Y "icmp && frame.len > 100" -T fields -e ip.src -e ip.dst -e frame.len')
    if stdout:
        findings.append({
            "type": "Large ICMP",
            "description": "ICMP packets with large payloads detected",
            "count": len(stdout.splitlines()),
        })

    # DNS TXT queries (possible tunneling)
    stdout, _, rc = run_tshark(pcap_path, '-Y "dns.qry.type==16" -T fields -e ip.src -e dns.qry.name')
    if stdout:
        findings.append({
            "type": "DNS TXT Queries",
            "description": "DNS TXT record queries detected",
            "count": len(stdout.splitlines()),
        })

    # Non-standard HTTP ports
    stdout, _, rc = run_tshark(
        pcap_path,
        '-Y "http && tcp.port != 80 && tcp.port != 443 && tcp.port != 8080" '
        '-T fields -e ip.src -e ip.dst -e tcp.dstport'
    )
    if stdout:
        findings.append({
            "type": "HTTP on non-standard port",
            "description": "HTTP traffic on unusual ports",
            "count": len(stdout.splitlines()),
        })

    return findings


def export_http_objects(pcap_path, output_dir):
    """Export HTTP transferred objects."""
    os.makedirs(output_dir, exist_ok=True)
    _, _, rc = run_tshark(pcap_path, f'--export-objects "http,{output_dir}"')
    files = []
    for f in os.listdir(output_dir):
        fpath = os.path.join(output_dir, f)
        files.append({"name": f, "size": os.path.getsize(fpath)})
    return files


def apply_display_filter(pcap_path, display_filter, fields):
    """Apply a custom display filter and extract specified fields."""
    field_str = " ".join(f"-e {f}" for f in fields)
    stdout, _, _ = run_tshark(
        pcap_path, f'-Y "{display_filter}" -T fields {field_str} -E separator="|"'
    )
    results = []
    for line in stdout.splitlines():
        parts = line.split("|")
        results.append(dict(zip(fields, parts)))
    return results


if __name__ == "__main__":
    print("=" * 60)
    print("Wireshark/tshark Network Analysis Agent")
    print("Packet analysis, protocol stats, artifact extraction")
    print("=" * 60)

    pcap = sys.argv[1] if len(sys.argv) > 1 else None

    if pcap and os.path.exists(pcap):
        print(f"\n[*] Analyzing: {pcap}")

        print("\n--- Capture Summary ---")
        summary = get_capture_summary(pcap)
        print(summary[:500] if summary else "  No stats available")

        print("\n--- Protocol Hierarchy ---")
        hierarchy = get_protocol_hierarchy(pcap)
        print(hierarchy[:500] if hierarchy else "  No hierarchy available")

        print("\n--- HTTP Requests ---")
        http = extract_http_requests(pcap)
        for r in http[:10]:
            print(f"  {r['method']} {r['host']}{r['uri']}")

        print("\n--- DNS Queries ---")
        dns = extract_dns_queries(pcap)
        queries_only = [d for d in dns if d["is_response"] == "0"]
        print(f"  Total DNS queries: {len(queries_only)}")

        print("\n--- TLS Sessions ---")
        tls = extract_tls_info(pcap)
        for t in tls[:10]:
            print(f"  {t['client']} -> {t['sni']} (JA3={t['ja3'][:16]}...)" if t['ja3'] else
                  f"  {t['client']} -> {t['sni']}")

        print("\n--- Suspicious Traffic ---")
        suspicious = detect_suspicious_traffic(pcap)
        for s in suspicious:
            print(f"  [!] {s['type']}: {s['description']} ({s['count']} occurrences)")
    else:
        print(f"\n[DEMO] Usage: python agent.py <capture.pcap>")
