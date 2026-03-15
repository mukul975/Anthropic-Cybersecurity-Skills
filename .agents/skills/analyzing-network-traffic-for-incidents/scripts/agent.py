#!/usr/bin/env python3
"""Network traffic incident analysis agent using scapy and tshark for PCAP investigation."""

import subprocess
import os
import sys
import json
import statistics
from collections import defaultdict, Counter

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw, ARP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


def run_tshark(pcap_path, display_filter, fields):
    """Run tshark with a display filter and extract specific fields."""
    field_args = " ".join(f"-e {f}" for f in fields)
    cmd = f'tshark -r {pcap_path} -Y "{display_filter}" -T fields {field_args} -E separator="|"'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
    rows = []
    if result.returncode == 0:
        for line in result.stdout.strip().splitlines():
            parts = line.split("|")
            if len(parts) == len(fields):
                rows.append(dict(zip(fields, parts)))
    return rows


def get_pcap_summary(pcap_path):
    """Get high-level PCAP statistics."""
    cmd = f"tshark -r {pcap_path} -q -z conv,ip"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
    return result.stdout if result.returncode == 0 else ""


def detect_lateral_movement(pcap_path):
    """Detect potential lateral movement patterns (SMB, RDP, WinRM, SSH)."""
    lateral_ports = {"445": "SMB", "3389": "RDP", "5985": "WinRM", "5986": "WinRM-S",
                     "22": "SSH", "135": "RPC", "139": "NetBIOS"}
    connections = run_tshark(pcap_path, "tcp.flags.syn==1 && tcp.flags.ack==0",
                             ["ip.src", "ip.dst", "tcp.dstport"])
    lateral = []
    for conn in connections:
        port = conn.get("tcp.dstport", "")
        if port in lateral_ports:
            lateral.append({
                "src": conn["ip.src"],
                "dst": conn["ip.dst"],
                "port": port,
                "service": lateral_ports[port],
            })
    return lateral


def detect_data_exfiltration(pcap_path, threshold_mb=10):
    """Detect potential data exfiltration based on outbound data volume."""
    cmd = f'tshark -r {pcap_path} -q -z conv,ip'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
    suspects = []
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 8 and "<->" in line:
                try:
                    ip_a = parts[0]
                    ip_b = parts[2]
                    bytes_a_to_b = int(parts[4]) if parts[4].isdigit() else 0
                    bytes_b_to_a = int(parts[7]) if len(parts) > 7 and parts[7].isdigit() else 0
                    total_bytes = bytes_a_to_b + bytes_b_to_a
                    if total_bytes > threshold_mb * 1024 * 1024:
                        suspects.append({
                            "ip_a": ip_a,
                            "ip_b": ip_b,
                            "bytes_a_to_b": bytes_a_to_b,
                            "bytes_b_to_a": bytes_b_to_a,
                            "total_mb": round(total_bytes / (1024 * 1024), 2),
                        })
                except (ValueError, IndexError):
                    continue
    return suspects


def detect_beaconing(pcap_path, min_conns=10):
    """Detect periodic beaconing patterns from TCP connections."""
    if not HAS_SCAPY:
        return []
    packets = rdpcap(pcap_path)
    conn_times = defaultdict(list)
    for pkt in packets:
        if IP in pkt and TCP in pkt and (pkt[TCP].flags & 0x02):
            key = f"{pkt[IP].src}->{pkt[IP].dst}:{pkt[TCP].dport}"
            conn_times[key].append(float(pkt.time))
    beacons = []
    for key, times in conn_times.items():
        if len(times) < min_conns:
            continue
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        avg = statistics.mean(intervals)
        std = statistics.stdev(intervals) if len(intervals) > 1 else 0
        jitter = (std / avg * 100) if avg > 0 else 0
        if 5 < avg < 7200 and jitter < 30:
            beacons.append({
                "flow": key,
                "connections": len(times),
                "avg_interval": round(avg, 1),
                "jitter_pct": round(jitter, 1),
            })
    return beacons


def extract_dns_queries(pcap_path):
    """Extract DNS queries and identify suspicious patterns."""
    queries = run_tshark(pcap_path, "dns.qr==0",
                          ["ip.src", "dns.qry.name", "dns.qry.type"])
    return queries


def detect_ids_alerts(pcap_path):
    """Run Suricata on the PCAP and extract alerts."""
    cmd = f"suricata -r {pcap_path} -l /tmp/suricata_output -k none 2>/dev/null"
    subprocess.run(cmd, shell=True, timeout=120)
    alerts = []
    alert_file = "/tmp/suricata_output/fast.log"
    if os.path.exists(alert_file):
        with open(alert_file, "r") as f:
            for line in f:
                alerts.append(line.strip())
    return alerts


def extract_http_objects(pcap_path, output_dir):
    """Extract HTTP objects (files) from the PCAP."""
    os.makedirs(output_dir, exist_ok=True)
    cmd = f'tshark -r {pcap_path} --export-objects "http,{output_dir}"'
    subprocess.run(cmd, shell=True, timeout=60)
    exported = []
    if os.path.exists(output_dir):
        for f in os.listdir(output_dir):
            filepath = os.path.join(output_dir, f)
            exported.append({"filename": f, "size": os.path.getsize(filepath)})
    return exported


def generate_incident_report(pcap_path, beacons, lateral, exfil, dns_queries):
    """Generate a network incident analysis report."""
    report = {
        "pcap": pcap_path,
        "pcap_size_mb": round(os.path.getsize(pcap_path) / (1024*1024), 1),
        "findings": {
            "beacons_detected": len(beacons),
            "lateral_movement_flows": len(lateral),
            "exfiltration_suspects": len(exfil),
            "dns_queries": len(dns_queries),
        },
        "beacons": beacons,
        "lateral_movement": lateral[:10],
        "exfiltration": exfil,
    }
    return report


if __name__ == "__main__":
    print("=" * 60)
    print("Network Traffic Incident Analysis Agent")
    print("Beaconing, lateral movement, exfiltration detection")
    print("=" * 60)

    pcap = sys.argv[1] if len(sys.argv) > 1 else None

    if pcap and os.path.exists(pcap):
        print(f"\n[*] Analyzing: {pcap}")
        print(f"[*] Size: {os.path.getsize(pcap)/(1024*1024):.1f} MB")

        print("\n--- Beacon Detection ---")
        beacons = detect_beaconing(pcap)
        for b in beacons:
            print(f"  [!] {b['flow']}: interval={b['avg_interval']}s "
                  f"jitter={b['jitter_pct']}% ({b['connections']} conns)")

        print("\n--- Lateral Movement Detection ---")
        lateral = detect_lateral_movement(pcap)
        for l in lateral[:10]:
            print(f"  [!] {l['src']} -> {l['dst']}:{l['port']} ({l['service']})")

        print("\n--- Data Exfiltration Detection ---")
        exfil = detect_data_exfiltration(pcap, threshold_mb=5)
        for e in exfil:
            print(f"  [!] {e['ip_a']} <-> {e['ip_b']}: {e['total_mb']} MB")

        print("\n--- DNS Queries ---")
        dns = extract_dns_queries(pcap)
        print(f"  Total queries: {len(dns)}")

        report = generate_incident_report(pcap, beacons, lateral, exfil, dns)
        print(f"\n[*] Report summary: {json.dumps(report['findings'], indent=2)}")
    else:
        print(f"\n[DEMO] Usage: python agent.py <capture.pcap>")
