#!/usr/bin/env python3
"""S7comm Protocol Security Analysis agent — analyzes Siemens S7 protocol
traffic from PCAP files using pyshark to detect unauthorized PLC access,
password brute-force, and dangerous write operations."""

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

try:
    import pyshark
except ImportError:
    print("Install pyshark: pip install pyshark", file=sys.stderr)
    sys.exit(1)


S7_PORT = 102
S7_FUNCTION_CODES = {
    "0x04": "read_var",
    "0x05": "write_var",
    "0x00": "cpu_services",
    "0x28": "setup_communication",
    "0x29": "run",
    "0x1a": "stop",
    "0xf0": "userdata",
}

DANGEROUS_FUNCTIONS = {"write_var", "run", "stop"}


def load_pcap(pcap_path: str, display_filter: str = "s7comm") -> list:
    """Load S7comm packets from PCAP file."""
    cap = pyshark.FileCapture(pcap_path, display_filter=display_filter)
    packets = []
    for pkt in cap:
        try:
            s7_layer = pkt.s7comm
            packets.append({
                "timestamp": str(pkt.sniff_time),
                "src_ip": str(pkt.ip.src),
                "dst_ip": str(pkt.ip.dst),
                "src_port": str(pkt.tcp.srcport),
                "dst_port": str(pkt.tcp.dstport),
                "rosctr": getattr(s7_layer, "rosctr", "unknown"),
                "function": getattr(s7_layer, "param_func", "unknown"),
                "error_class": getattr(s7_layer, "error_class", "0"),
                "error_code": getattr(s7_layer, "error_code", "0"),
            })
        except AttributeError:
            continue
    cap.close()
    return packets


def detect_unauthorized_access(packets: list) -> list[dict]:
    """Detect potential unauthorized access to PLCs."""
    findings = []
    plc_connections = defaultdict(set)
    for pkt in packets:
        plc_connections[pkt["dst_ip"]].add(pkt["src_ip"])

    for plc_ip, sources in plc_connections.items():
        if len(sources) > 3:
            findings.append({
                "type": "multiple_sources_to_plc",
                "severity": "high",
                "plc_ip": plc_ip,
                "source_count": len(sources),
                "sources": sorted(sources),
                "detail": f"PLC {plc_ip} accessed by {len(sources)} unique sources",
            })
    return findings


def detect_dangerous_operations(packets: list) -> list[dict]:
    """Flag write, run, and stop operations on PLCs."""
    findings = []
    for pkt in packets:
        func_code = pkt.get("function", "unknown")
        func_name = S7_FUNCTION_CODES.get(func_code, func_code)
        if func_name in DANGEROUS_FUNCTIONS:
            findings.append({
                "type": f"dangerous_operation_{func_name}",
                "severity": "critical" if func_name in ("stop", "run") else "high",
                "src_ip": pkt["src_ip"],
                "dst_ip": pkt["dst_ip"],
                "timestamp": pkt["timestamp"],
                "function": func_name,
                "detail": f"{func_name} operation from {pkt['src_ip']} to PLC {pkt['dst_ip']}",
            })
    return findings


def detect_brute_force(packets: list, threshold: int = 10) -> list[dict]:
    """Detect authentication brute-force via repeated setup_communication with errors."""
    findings = []
    error_counts = Counter()
    for pkt in packets:
        if pkt.get("error_class", "0") != "0" or pkt.get("error_code", "0") != "0":
            key = (pkt["src_ip"], pkt["dst_ip"])
            error_counts[key] += 1

    for (src, dst), count in error_counts.items():
        if count >= threshold:
            findings.append({
                "type": "potential_brute_force",
                "severity": "critical",
                "src_ip": src,
                "dst_ip": dst,
                "error_count": count,
                "detail": f"{count} error responses from PLC {dst} to {src} — possible brute-force",
            })
    return findings


def analyze_traffic_patterns(packets: list) -> dict:
    """Compute traffic statistics."""
    func_counts = Counter()
    src_counts = Counter()
    dst_counts = Counter()
    for pkt in packets:
        func_code = pkt.get("function", "unknown")
        func_name = S7_FUNCTION_CODES.get(func_code, func_code)
        func_counts[func_name] += 1
        src_counts[pkt["src_ip"]] += 1
        dst_counts[pkt["dst_ip"]] += 1

    return {
        "total_packets": len(packets),
        "function_distribution": dict(func_counts.most_common(20)),
        "top_sources": dict(src_counts.most_common(10)),
        "top_destinations": dict(dst_counts.most_common(10)),
    }


def generate_report(pcap_path: str, brute_threshold: int) -> dict:
    """Run all analyses and produce consolidated JSON report."""
    packets = load_pcap(pcap_path)
    findings = []
    findings.extend(detect_unauthorized_access(packets))
    findings.extend(detect_dangerous_operations(packets))
    findings.extend(detect_brute_force(packets, brute_threshold))
    traffic = analyze_traffic_patterns(packets)

    severity_counts = Counter(f["severity"] for f in findings)
    return {
        "report": "s7comm_protocol_security_analysis",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "pcap_file": pcap_path,
        "total_s7_packets": len(packets),
        "total_findings": len(findings),
        "severity_summary": dict(severity_counts),
        "traffic_patterns": traffic,
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="S7comm Protocol Security Analysis Agent")
    parser.add_argument("--pcap", required=True, help="Path to PCAP file with S7comm traffic")
    parser.add_argument("--brute-threshold", type=int, default=10, help="Error count threshold for brute-force (default: 10)")
    parser.add_argument("--output", help="Output JSON file path")
    args = parser.parse_args()

    report = generate_report(args.pcap, args.brute_threshold)
    output = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
