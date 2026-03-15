#!/usr/bin/env python3
"""C2 communication analysis agent for beacon detection and protocol decoding."""

import statistics
import base64
import json
import os
import sys
from collections import defaultdict

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import dpkt
    HAS_DPKT = True
except ImportError:
    HAS_DPKT = False


def detect_beacons(pcap_path, min_connections=5, max_jitter_pct=25.0):
    """Analyze PCAP for periodic beacon patterns using TCP SYN timing."""
    if not HAS_SCAPY:
        print("[ERROR] scapy not installed: pip install scapy")
        return []
    packets = rdpcap(pcap_path)
    connections = defaultdict(list)
    for pkt in packets:
        if IP in pkt and TCP in pkt and (pkt[TCP].flags & 0x02):
            key = f"{pkt[IP].dst}:{pkt[TCP].dport}"
            connections[key].append(float(pkt.time))
    beacons = []
    for dst, times in sorted(connections.items()):
        if len(times) < min_connections:
            continue
        intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]
        avg_interval = statistics.mean(intervals)
        stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        jitter_pct = (stdev / avg_interval * 100) if avg_interval > 0 else 0
        is_beacon = 5 < avg_interval < 7200 and jitter_pct < max_jitter_pct
        record = {
            "destination": dst,
            "connections": len(times),
            "duration_seconds": round(times[-1] - times[0], 1),
            "avg_interval_seconds": round(avg_interval, 1),
            "stdev_seconds": round(stdev, 1),
            "jitter_percent": round(jitter_pct, 1),
            "is_beacon": is_beacon,
        }
        if is_beacon:
            beacons.append(record)
    return beacons


def extract_http_requests(pcap_path):
    """Extract HTTP requests from a PCAP file using dpkt."""
    if not HAS_DPKT:
        print("[ERROR] dpkt not installed: pip install dpkt")
        return []
    requests = []
    with open(pcap_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                tcp = ip.data
                if len(tcp.data) == 0:
                    continue
                try:
                    http = dpkt.http.Request(tcp.data)
                    decoded_body = None
                    if http.body:
                        try:
                            decoded_body = base64.b64decode(http.body).decode("utf-8", errors="replace")
                        except Exception:
                            decoded_body = http.body[:200]
                    requests.append({
                        "timestamp": ts,
                        "src_ip": ".".join(str(b) for b in ip.src),
                        "dst_ip": ".".join(str(b) for b in ip.dst),
                        "dst_port": tcp.dport,
                        "method": http.method,
                        "uri": http.uri,
                        "host": http.headers.get("host", ""),
                        "user_agent": http.headers.get("user-agent", ""),
                        "body_size": len(http.body) if http.body else 0,
                        "decoded_body_preview": decoded_body,
                    })
                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                    pass
            except Exception:
                continue
    return requests


def extract_dns_queries(pcap_path):
    """Extract DNS queries from a PCAP for C2 domain identification."""
    if not HAS_SCAPY:
        return []
    packets = rdpcap(pcap_path)
    queries = []
    for pkt in packets:
        if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
            qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
            queries.append({
                "src_ip": pkt[IP].src if IP in pkt else "?",
                "query": qname,
                "type": pkt[DNSQR].qtype,
            })
    return queries


def identify_c2_framework(http_requests):
    """Match HTTP request patterns against known C2 framework signatures."""
    cs_uris = ["/pixel", "/submit.php", "/__utm.gif", "/ca", "/dpixel",
               "/push", "/visit.js", "/tab_icon"]
    framework_hits = []
    for req in http_requests:
        uri = req.get("uri", "")
        ua = req.get("user_agent", "")
        for cs_uri in cs_uris:
            if cs_uri in uri:
                framework_hits.append({
                    "framework": "Cobalt Strike",
                    "indicator": f"URI pattern: {cs_uri}",
                    "request": req,
                })
                break
        if "MeterSSL" in ua or len(uri) == 5 and uri.startswith("/"):
            framework_hits.append({
                "framework": "Metasploit/Meterpreter",
                "indicator": f"URI/UA pattern: {uri} / {ua[:50]}",
                "request": req,
            })
    return framework_hits


def generate_suricata_rules(beacons, http_requests):
    """Generate Suricata IDS rules from observed C2 patterns."""
    rules = []
    sid = 9000100
    for beacon in beacons:
        dst_ip, dst_port = beacon["destination"].rsplit(":", 1)
        rules.append(
            f'alert tcp $HOME_NET any -> {dst_ip} {dst_port} ('
            f'msg:"MALWARE Detected C2 Beacon to {dst_ip}:{dst_port}"; '
            f'flow:established,to_server; '
            f'threshold:type threshold, track by_src, count 5, seconds 600; '
            f'sid:{sid}; rev:1;)'
        )
        sid += 1
    for req in http_requests[:5]:
        if req.get("uri"):
            uri = req["uri"]
            rules.append(
                f'alert http $HOME_NET any -> $EXTERNAL_NET any ('
                f'msg:"MALWARE Suspected C2 HTTP Request {uri}"; '
                f'flow:established,to_server; '
                f'http.method; content:"{req["method"]}"; '
                f'http.uri; content:"{uri}"; '
                f'sid:{sid}; rev:1;)'
            )
            sid += 1
    return rules


if __name__ == "__main__":
    print("=" * 60)
    print("C2 Communication Analysis Agent")
    print("Beacon detection, protocol decoding, signature generation")
    print("=" * 60)

    pcap_file = sys.argv[1] if len(sys.argv) > 1 else None

    if pcap_file and os.path.exists(pcap_file):
        print(f"\n[*] Analyzing PCAP: {pcap_file}")

        print("\n--- Beacon Detection ---")
        beacons = detect_beacons(pcap_file)
        for b in beacons:
            print(f"[!] BEACON: {b['destination']} "
                  f"interval={b['avg_interval_seconds']}s "
                  f"jitter={b['jitter_percent']}% "
                  f"sessions={b['connections']}")

        print("\n--- HTTP Requests ---")
        http_reqs = extract_http_requests(pcap_file)
        for r in http_reqs[:10]:
            print(f"  {r['method']} {r['host']}{r['uri']}")

        print("\n--- DNS Queries ---")
        dns_qs = extract_dns_queries(pcap_file)
        for q in dns_qs[:10]:
            print(f"  {q['src_ip']} -> {q['query']}")

        print("\n--- C2 Framework Identification ---")
        hits = identify_c2_framework(http_reqs)
        for h in hits:
            print(f"[!] {h['framework']}: {h['indicator']}")

        print("\n--- Suricata Rules ---")
        rules = generate_suricata_rules(beacons, http_reqs)
        for r in rules:
            print(r)
    else:
        print("\n[DEMO] Usage: python agent.py <capture.pcap>")
        print("[*] Provide a PCAP file to analyze for C2 communication patterns.")
