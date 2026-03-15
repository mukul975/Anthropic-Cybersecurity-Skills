#!/usr/bin/env python3
"""Arkime Network Traffic Analysis Agent - Queries Arkime API for session analysis and anomaly detection."""

import json
import logging
import argparse
from datetime import datetime
from collections import defaultdict

import requests
from requests.auth import HTTPDigestAuth

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def arkime_request(base_url, endpoint, auth, params=None):
    """Make an authenticated request to Arkime API v3."""
    url = f"{base_url}{endpoint}"
    try:
        resp = requests.get(url, auth=HTTPDigestAuth(*auth), params=params, verify=False, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        logger.error("Arkime API error %s: %s", endpoint, e)
        return None


def search_sessions(base_url, auth, expression, date_range=1, length=500):
    """Search Arkime sessions with an expression filter."""
    params = {
        "date": date_range,
        "expression": expression,
        "length": length,
        "order": "lastPacket:desc",
    }
    data = arkime_request(base_url, "/api/sessions", auth, params)
    if data and "data" in data:
        logger.info("Found %d sessions for expression: %s", len(data["data"]), expression)
        return data["data"]
    return []


def get_connections(base_url, auth, expression, date_range=1):
    """Get connection graph data from Arkime."""
    params = {"date": date_range, "expression": expression}
    data = arkime_request(base_url, "/api/connections", auth, params)
    if data:
        nodes = data.get("nodes", [])
        links = data.get("links", [])
        logger.info("Connection graph: %d nodes, %d links", len(nodes), len(links))
        return {"nodes": nodes, "links": links}
    return {"nodes": [], "links": []}


def get_spi_view(base_url, auth, expression, date_range=1):
    """Get SPI view field statistics from Arkime."""
    params = {"date": date_range, "expression": expression, "spi": "srcIp,dstIp,dstPort"}
    data = arkime_request(base_url, "/api/spiview", auth, params)
    return data if data else {}


def detect_beaconing(sessions, interval_threshold=0.15):
    """Detect C2 beaconing by analyzing connection intervals."""
    connections = defaultdict(list)
    for s in sessions:
        key = (s.get("srcIp", ""), s.get("dstIp", ""), s.get("dstPort", 0))
        connections[key].append(s.get("lastPacket", 0))

    beacons = []
    for (src, dst, port), timestamps in connections.items():
        if len(timestamps) < 10:
            continue
        timestamps.sort()
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        if not intervals:
            continue
        avg_interval = sum(intervals) / len(intervals)
        if avg_interval == 0:
            continue
        std_dev = (sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)) ** 0.5
        jitter_ratio = std_dev / avg_interval

        if jitter_ratio < interval_threshold:
            beacons.append({
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": port,
                "session_count": len(timestamps),
                "avg_interval_sec": round(avg_interval / 1000, 1),
                "jitter_ratio": round(jitter_ratio, 4),
                "confidence": "high" if jitter_ratio < 0.05 else "medium",
                "severity": "critical",
            })
            logger.warning("Beaconing: %s -> %s:%d (jitter: %.4f)", src, dst, port, jitter_ratio)
    return beacons


def detect_dns_tunneling(sessions, query_len_threshold=50):
    """Detect DNS tunneling via abnormally long DNS queries."""
    dns_sessions = [s for s in sessions if s.get("dstPort") == 53]
    suspicious = []
    src_stats = defaultdict(lambda: {"count": 0, "total_bytes": 0})

    for s in dns_sessions:
        src = s.get("srcIp", "")
        src_stats[src]["count"] += 1
        src_stats[src]["total_bytes"] += s.get("srcBytes", 0) + s.get("dstBytes", 0)

    for src, stats in src_stats.items():
        avg_bytes = stats["total_bytes"] / max(stats["count"], 1)
        if stats["count"] > 100 and avg_bytes > query_len_threshold:
            suspicious.append({
                "src_ip": src,
                "dns_query_count": stats["count"],
                "avg_bytes_per_query": round(avg_bytes, 1),
                "total_bytes": stats["total_bytes"],
                "severity": "high",
                "indicator": "DNS tunneling - high volume with large payloads",
            })
    return suspicious


def detect_large_transfers(sessions, threshold_mb=100):
    """Detect unusually large data transfers."""
    threshold_bytes = threshold_mb * 1024 * 1024
    large = []
    for s in sessions:
        total = s.get("srcBytes", 0) + s.get("dstBytes", 0)
        if total > threshold_bytes:
            large.append({
                "src_ip": s.get("srcIp", ""),
                "dst_ip": s.get("dstIp", ""),
                "dst_port": s.get("dstPort", 0),
                "total_bytes": total,
                "total_mb": round(total / (1024 * 1024), 2),
                "severity": "high",
            })
    return large


def detect_tls_anomalies(sessions):
    """Detect TLS certificate anomalies (self-signed, expired, unusual issuers)."""
    anomalies = []
    for s in sessions:
        tls = s.get("tls", {})
        if not tls:
            continue
        ja3 = s.get("srcJa3", "")
        issuer_cn = tls.get("issuerCN", "")
        not_after = tls.get("notAfter", 0)
        if issuer_cn and issuer_cn == tls.get("subjectCN", ""):
            anomalies.append({
                "src_ip": s.get("srcIp", ""),
                "dst_ip": s.get("dstIp", ""),
                "issue": "self-signed certificate",
                "issuer": issuer_cn,
                "severity": "medium",
            })
        if not_after and not_after < int(datetime.utcnow().timestamp() * 1000):
            anomalies.append({
                "src_ip": s.get("srcIp", ""),
                "dst_ip": s.get("dstIp", ""),
                "issue": "expired certificate",
                "issuer": issuer_cn,
                "severity": "medium",
            })
    return anomalies


def generate_report(beacons, dns_tunneling, large_transfers, tls_anomalies, session_count):
    """Generate network traffic analysis report."""
    all_findings = beacons + dns_tunneling + large_transfers + tls_anomalies
    critical = [f for f in all_findings if f.get("severity") == "critical"]
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "sessions_analyzed": session_count,
        "findings_total": len(all_findings),
        "critical_count": len(critical),
        "beaconing_detected": beacons,
        "dns_tunneling": dns_tunneling,
        "large_transfers": large_transfers,
        "tls_anomalies": tls_anomalies,
    }
    print(f"ARKIME REPORT: {len(all_findings)} findings ({len(critical)} critical) from {session_count} sessions")
    return report


def main():
    parser = argparse.ArgumentParser(description="Arkime Network Traffic Analysis Agent")
    parser.add_argument("--arkime-url", required=True, help="Arkime viewer URL")
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--expression", default="*", help="Arkime search expression")
    parser.add_argument("--date-range", type=int, default=1, help="Date range in hours")
    parser.add_argument("--output", default="arkime_report.json")
    args = parser.parse_args()

    auth = (args.user, args.password)
    sessions = search_sessions(args.arkime_url, auth, args.expression, args.date_range)
    beacons = detect_beaconing(sessions)
    dns_tunnel = detect_dns_tunneling(sessions)
    large = detect_large_transfers(sessions)
    tls = detect_tls_anomalies(sessions)

    report = generate_report(beacons, dns_tunnel, large, tls, len(sessions))
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
