#!/usr/bin/env python3
"""NetFlow Analysis Agent - Parses NetFlow v9/IPFIX for anomalies, port scans, and exfiltration."""

import json
import math
import logging
import argparse
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def load_flow_data(flow_file):
    """Load preprocessed flow records from JSON file."""
    with open(flow_file, "r") as f:
        flows = json.load(f)
    logger.info("Loaded %d flow records from %s", len(flows), flow_file)
    return flows


def parse_netflow_capture(pcap_file):
    """Parse NetFlow packets from a PCAP capture using the netflow library."""
    import netflow
    templates = {}
    flows = []
    with open(pcap_file, "rb") as f:
        while True:
            try:
                data = f.read(65535)
                if not data:
                    break
                packet, templates = netflow.parse_packet(data, templates)
                for flow in packet.flows:
                    flows.append({
                        "src_ip": str(getattr(flow, "IPV4_SRC_ADDR", "")),
                        "dst_ip": str(getattr(flow, "IPV4_DST_ADDR", "")),
                        "src_port": getattr(flow, "L4_SRC_PORT", 0),
                        "dst_port": getattr(flow, "L4_DST_PORT", 0),
                        "protocol": getattr(flow, "PROTOCOL", 0),
                        "bytes_in": getattr(flow, "IN_BYTES", 0),
                        "bytes_out": getattr(flow, "OUT_BYTES", 0),
                        "packets": getattr(flow, "IN_PKTS", 0),
                        "duration": getattr(flow, "LAST_SWITCHED", 0) - getattr(flow, "FIRST_SWITCHED", 0),
                        "tcp_flags": getattr(flow, "TCP_FLAGS", 0),
                    })
            except Exception:
                break
    logger.info("Parsed %d flows from PCAP", len(flows))
    return flows


def detect_port_scanning(flows, threshold=20):
    """Detect port scanning: one source hitting many ports on same or multiple destinations."""
    src_dst_ports = defaultdict(lambda: defaultdict(set))
    for flow in flows:
        src_dst_ports[flow["src_ip"]][flow["dst_ip"]].add(flow["dst_port"])
    scanners = []
    for src, dst_map in src_dst_ports.items():
        for dst, ports in dst_map.items():
            if len(ports) >= threshold:
                scanners.append({
                    "source": src,
                    "target": dst,
                    "unique_ports": len(ports),
                    "ports_sample": sorted(list(ports))[:20],
                    "severity": "high",
                    "indicator": "Port scan detected",
                })
    total_targets = sum(len(d) for d in src_dst_ports.values())
    for src, dst_map in src_dst_ports.items():
        if len(dst_map) >= 50:
            total_ports = sum(len(p) for p in dst_map.values())
            scanners.append({
                "source": src,
                "unique_targets": len(dst_map),
                "total_ports_probed": total_ports,
                "severity": "critical",
                "indicator": "Network sweep detected",
            })
    logger.info("Detected %d scanning activities", len(scanners))
    return scanners


def detect_data_exfiltration(flows, byte_threshold=100_000_000):
    """Detect potential data exfiltration via high-volume outbound flows."""
    src_dst_bytes = defaultdict(int)
    for flow in flows:
        key = (flow["src_ip"], flow["dst_ip"])
        src_dst_bytes[key] += flow.get("bytes_in", 0) + flow.get("bytes_out", 0)
    exfil_candidates = []
    for (src, dst), total_bytes in src_dst_bytes.items():
        if total_bytes >= byte_threshold:
            exfil_candidates.append({
                "source": src,
                "destination": dst,
                "total_bytes": total_bytes,
                "total_mb": round(total_bytes / 1_000_000, 1),
                "severity": "critical",
                "indicator": "High-volume data transfer (potential exfiltration)",
            })
    exfil_candidates.sort(key=lambda x: x["total_bytes"], reverse=True)
    logger.info("Detected %d high-volume transfer pairs", len(exfil_candidates))
    return exfil_candidates


def detect_beaconing(flows, min_connections=10, jitter_threshold=0.15):
    """Detect C2 beaconing patterns via periodic connection analysis."""
    pair_timestamps = defaultdict(list)
    for i, flow in enumerate(flows):
        key = (flow["src_ip"], flow["dst_ip"], flow["dst_port"])
        pair_timestamps[key].append(i)
    beacons = []
    for (src, dst, port), indices in pair_timestamps.items():
        if len(indices) < min_connections:
            continue
        intervals = [indices[i+1] - indices[i] for i in range(len(indices)-1)]
        if not intervals:
            continue
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval == 0:
            continue
        variance = sum((x - mean_interval)**2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        jitter = std_dev / mean_interval
        if jitter < jitter_threshold:
            beacons.append({
                "source": src,
                "destination": dst,
                "port": port,
                "connection_count": len(indices),
                "mean_interval": round(mean_interval, 2),
                "jitter_ratio": round(jitter, 3),
                "severity": "critical",
                "indicator": "Periodic beaconing (potential C2)",
            })
    logger.info("Detected %d beaconing patterns", len(beacons))
    return beacons


def build_traffic_baseline(flows):
    """Build statistical baseline of network traffic."""
    protocol_bytes = defaultdict(int)
    port_counts = defaultdict(int)
    total_bytes = 0
    for flow in flows:
        protocol_bytes[flow.get("protocol", 0)] += flow.get("bytes_in", 0)
        port_counts[flow["dst_port"]] += 1
        total_bytes += flow.get("bytes_in", 0) + flow.get("bytes_out", 0)
    return {
        "total_flows": len(flows),
        "total_bytes": total_bytes,
        "protocol_distribution": dict(protocol_bytes),
        "top_ports": dict(sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:20]),
    }


def generate_report(flows, scanners, exfil, beacons, baseline):
    """Generate NetFlow analysis report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_flows": len(flows),
        "baseline": baseline,
        "port_scans": scanners,
        "exfiltration_candidates": exfil[:20],
        "beaconing_patterns": beacons,
        "summary": {
            "scan_alerts": len(scanners),
            "exfil_alerts": len(exfil),
            "beacon_alerts": len(beacons),
        },
    }
    total = len(scanners) + len(exfil) + len(beacons)
    print(f"NETFLOW REPORT: {len(flows)} flows, {total} alerts")
    return report


def main():
    parser = argparse.ArgumentParser(description="NetFlow Analysis Agent")
    parser.add_argument("--flow-file", required=True, help="JSON flow data file")
    parser.add_argument("--byte-threshold", type=int, default=100_000_000)
    parser.add_argument("--scan-threshold", type=int, default=20)
    parser.add_argument("--output", default="netflow_report.json")
    args = parser.parse_args()

    flows = load_flow_data(args.flow_file)
    baseline = build_traffic_baseline(flows)
    scanners = detect_port_scanning(flows, args.scan_threshold)
    exfil = detect_data_exfiltration(flows, args.byte_threshold)
    beacons = detect_beaconing(flows)

    report = generate_report(flows, scanners, exfil, beacons, baseline)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
