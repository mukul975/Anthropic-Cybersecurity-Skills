#!/usr/bin/env python3
"""Zeek network anomaly detection agent for log analysis and threat hunting."""

import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


ZEEK_BIN = "/opt/zeek/bin/zeek"
ZEEK_LOG_DIR = "/opt/zeek/logs/current"


def check_zeek_status():
    """Check Zeek installation and running status."""
    version = {"installed": False}
    try:
        result = subprocess.run([ZEEK_BIN, "--version"], capture_output=True, text=True, timeout=10)
        version = {"installed": True, "version": result.stdout.strip() or result.stderr.strip()}
    except FileNotFoundError:
        try:
            result = subprocess.run(["zeek", "--version"], capture_output=True, text=True, timeout=10)
            version = {"installed": True, "version": result.stdout.strip()}
        except FileNotFoundError:
            version = {"installed": False}

    running = False
    try:
        r = subprocess.run(["zeekctl", "status"], capture_output=True, text=True, timeout=10)
        running = "running" in r.stdout.lower()
    except FileNotFoundError:
        pass

    return {**version, "running": running}


def parse_conn_log(log_path=None):
    """Parse Zeek conn.log for connection statistics and anomalies."""
    log_path = log_path or os.path.join(ZEEK_LOG_DIR, "conn.log")
    if not os.path.exists(log_path):
        return {"error": f"conn.log not found: {log_path}"}

    total = 0
    protocols = Counter()
    services = Counter()
    top_talkers = Counter()
    top_destinations = Counter()
    long_connections = []

    with open(log_path, "r") as f:
        header = {}
        for line in f:
            if line.startswith("#fields"):
                fields_list = line.strip().split("\t")[1:]
                header = {name: i for i, name in enumerate(fields_list)}
                continue
            if line.startswith("#"):
                continue
            parts = line.strip().split("\t")
            total += 1
            if not header:
                continue

            src = parts[header.get("id.orig_h", 2)] if len(parts) > header.get("id.orig_h", 2) else ""
            dst = parts[header.get("id.resp_h", 4)] if len(parts) > header.get("id.resp_h", 4) else ""
            proto = parts[header.get("proto", 6)] if len(parts) > header.get("proto", 6) else ""
            service = parts[header.get("service", 7)] if len(parts) > header.get("service", 7) else "-"
            duration = parts[header.get("duration", 8)] if len(parts) > header.get("duration", 8) else "-"

            protocols[proto] += 1
            if service != "-":
                services[service] += 1
            top_talkers[src] += 1
            top_destinations[dst] += 1

            if duration != "-":
                try:
                    dur = float(duration)
                    if dur > 3600:
                        long_connections.append({"src": src, "dst": dst, "duration_sec": dur, "service": service})
                except ValueError:
                    pass

    return {
        "total_connections": total,
        "protocols": dict(protocols),
        "top_services": services.most_common(15),
        "top_sources": top_talkers.most_common(15),
        "top_destinations": top_destinations.most_common(15),
        "long_connections": sorted(long_connections, key=lambda x: x["duration_sec"], reverse=True)[:20],
    }


def parse_dns_log(log_path=None):
    """Parse Zeek dns.log for DNS anomaly detection."""
    log_path = log_path or os.path.join(ZEEK_LOG_DIR, "dns.log")
    if not os.path.exists(log_path):
        return {"error": f"dns.log not found: {log_path}"}

    queries = Counter()
    query_types = Counter()
    long_queries = []
    nxdomain = []

    with open(log_path, "r") as f:
        header = {}
        for line in f:
            if line.startswith("#fields"):
                fields_list = line.strip().split("\t")[1:]
                header = {name: i for i, name in enumerate(fields_list)}
                continue
            if line.startswith("#"):
                continue
            parts = line.strip().split("\t")
            if not header:
                continue

            query = parts[header.get("query", 9)] if len(parts) > header.get("query", 9) else ""
            qtype = parts[header.get("qtype_name", 13)] if len(parts) > header.get("qtype_name", 13) else ""
            rcode = parts[header.get("rcode_name", 15)] if len(parts) > header.get("rcode_name", 15) else ""
            src = parts[header.get("id.orig_h", 2)] if len(parts) > header.get("id.orig_h", 2) else ""

            queries[query] += 1
            query_types[qtype] += 1

            if len(query) > 60:
                long_queries.append({"source": src, "query": query, "length": len(query)})
            if rcode == "NXDOMAIN":
                nxdomain.append({"source": src, "query": query})

    return {
        "unique_queries": len(queries),
        "top_queries": queries.most_common(20),
        "query_types": dict(query_types),
        "long_queries_tunneling": long_queries[:20],
        "nxdomain_count": len(nxdomain),
        "nxdomain_samples": nxdomain[:20],
    }


def parse_ssl_log(log_path=None):
    """Parse Zeek ssl.log for TLS anomalies and certificate issues."""
    log_path = log_path or os.path.join(ZEEK_LOG_DIR, "ssl.log")
    if not os.path.exists(log_path):
        return {"error": f"ssl.log not found: {log_path}"}

    ja3_hashes = Counter()
    server_names = Counter()
    expired_certs = []

    with open(log_path, "r") as f:
        header = {}
        for line in f:
            if line.startswith("#fields"):
                fields_list = line.strip().split("\t")[1:]
                header = {name: i for i, name in enumerate(fields_list)}
                continue
            if line.startswith("#"):
                continue
            parts = line.strip().split("\t")
            if not header:
                continue

            ja3 = parts[header.get("ja3", -1)] if header.get("ja3") and len(parts) > header["ja3"] else "-"
            sni = parts[header.get("server_name", -1)] if header.get("server_name") and len(parts) > header["server_name"] else "-"
            valid = parts[header.get("validation_status", -1)] if header.get("validation_status") and len(parts) > header["validation_status"] else "-"

            if ja3 != "-":
                ja3_hashes[ja3] += 1
            if sni != "-":
                server_names[sni] += 1
            if "expired" in valid.lower() if valid != "-" else False:
                expired_certs.append({"sni": sni, "validation": valid})

    return {
        "unique_ja3": len(ja3_hashes),
        "top_ja3": ja3_hashes.most_common(20),
        "top_sni": server_names.most_common(20),
        "expired_certs": expired_certs[:20],
    }


def detect_beaconing(log_path=None, interval_tolerance=0.15):
    """Detect C2 beaconing patterns from Zeek conn.log."""
    log_path = log_path or os.path.join(ZEEK_LOG_DIR, "conn.log")
    if not os.path.exists(log_path):
        return {"error": f"conn.log not found: {log_path}"}

    pair_times = defaultdict(list)
    with open(log_path, "r") as f:
        header = {}
        for line in f:
            if line.startswith("#fields"):
                fields_list = line.strip().split("\t")[1:]
                header = {name: i for i, name in enumerate(fields_list)}
                continue
            if line.startswith("#"):
                continue
            parts = line.strip().split("\t")
            if not header:
                continue
            ts = parts[header.get("ts", 0)] if len(parts) > header.get("ts", 0) else ""
            src = parts[header.get("id.orig_h", 2)] if len(parts) > header.get("id.orig_h", 2) else ""
            dst = parts[header.get("id.resp_h", 4)] if len(parts) > header.get("id.resp_h", 4) else ""
            try:
                pair_times[f"{src}->{dst}"].append(float(ts))
            except ValueError:
                pass

    beacons = []
    for pair, times in pair_times.items():
        if len(times) < 10:
            continue
        times.sort()
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        if not intervals:
            continue
        avg = sum(intervals) / len(intervals)
        if avg < 1:
            continue
        jitter = sum(abs(i - avg) for i in intervals) / len(intervals) / avg if avg > 0 else 1
        if jitter < interval_tolerance:
            src, dst = pair.split("->")
            beacons.append({
                "source": src, "destination": dst,
                "connections": len(times),
                "avg_interval_sec": round(avg, 1),
                "jitter_pct": round(jitter * 100, 1),
            })

    beacons.sort(key=lambda x: x["connections"], reverse=True)
    return {"beacons_detected": len(beacons), "beacons": beacons[:20]}


def analyze_pcap(pcap_path):
    """Analyze a PCAP file with Zeek to generate logs."""
    if not os.path.exists(pcap_path):
        return {"error": f"PCAP not found: {pcap_path}"}

    output_dir = f"/tmp/zeek_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(output_dir, exist_ok=True)
    try:
        result = subprocess.run(
            ["zeek", "-r", pcap_path, "-C"],
            capture_output=True, text=True, timeout=120, cwd=output_dir
        )
        logs = list(Path(output_dir).glob("*.log"))
        return {
            "pcap": pcap_path,
            "output_dir": output_dir,
            "logs_generated": [l.name for l in logs],
            "exit_code": result.returncode,
        }
    except Exception as e:
        return {"error": str(e)}


def generate_report(log_dir=None):
    """Generate comprehensive Zeek network analysis report."""
    log_dir = log_dir or ZEEK_LOG_DIR
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "status": check_zeek_status(),
        "connections": parse_conn_log(os.path.join(log_dir, "conn.log")),
        "dns": parse_dns_log(os.path.join(log_dir, "dns.log")),
        "tls": parse_ssl_log(os.path.join(log_dir, "ssl.log")),
        "beaconing": detect_beaconing(os.path.join(log_dir, "conn.log")),
    }


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "report"
    log_dir = sys.argv[2] if len(sys.argv) > 2 else ZEEK_LOG_DIR
    if action == "report":
        print(json.dumps(generate_report(log_dir), indent=2, default=str))
    elif action == "connections":
        print(json.dumps(parse_conn_log(os.path.join(log_dir, "conn.log")), indent=2))
    elif action == "dns":
        print(json.dumps(parse_dns_log(os.path.join(log_dir, "dns.log")), indent=2))
    elif action == "tls":
        print(json.dumps(parse_ssl_log(os.path.join(log_dir, "ssl.log")), indent=2))
    elif action == "beaconing":
        print(json.dumps(detect_beaconing(os.path.join(log_dir, "conn.log")), indent=2))
    elif action == "pcap" and len(sys.argv) > 2:
        print(json.dumps(analyze_pcap(sys.argv[2]), indent=2))
    else:
        print("Usage: agent.py [report|connections|dns|tls|beaconing|pcap <file>] [log_dir]")
