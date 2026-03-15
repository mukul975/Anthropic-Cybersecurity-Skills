#!/usr/bin/env python3
"""Cobalt Strike Beacon Hunter - detects beacon signatures in network traffic and Zeek logs."""

import json
import argparse
import logging
import os
import re
import math
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

CS_DEFAULT_CERT_SERIAL = "8bb00ee"
CS_KNOWN_JA3S = [
    "ae4edc6faf64d08308082ad26be60767",
    "a0e9f5d64349fb13191bc781f81f42e1",
]
CS_KNOWN_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"


def parse_zeek_ssl_log(ssl_log_path):
    """Parse Zeek ssl.log for default Cobalt Strike certificates."""
    findings = []
    try:
        with open(ssl_log_path) as f:
            for line in f:
                if line.startswith("#"):
                    continue
                fields = line.strip().split("\t")
                if len(fields) < 22:
                    continue
                ts, uid, src_ip, src_port, dst_ip, dst_port = fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]
                serial = fields[20] if len(fields) > 20 else ""
                ja3s = fields[21] if len(fields) > 21 else ""
                if serial.lower().replace(":", "") == CS_DEFAULT_CERT_SERIAL:
                    findings.append({
                        "indicator": "default_cs_certificate",
                        "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port,
                        "cert_serial": serial, "timestamp": ts,
                        "severity": "critical", "confidence": 95,
                    })
                if ja3s in CS_KNOWN_JA3S:
                    findings.append({
                        "indicator": "known_cs_ja3s",
                        "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port,
                        "ja3s_hash": ja3s, "timestamp": ts,
                        "severity": "high", "confidence": 80,
                    })
    except FileNotFoundError:
        logger.warning("Zeek ssl.log not found: %s", ssl_log_path)
    return findings


def analyze_beacon_timing(conn_log_path, min_connections=20, max_jitter_pct=25):
    """Analyze connection timing for beacon-like regular intervals."""
    connections = defaultdict(list)
    try:
        with open(conn_log_path) as f:
            for line in f:
                if line.startswith("#"):
                    continue
                fields = line.strip().split("\t")
                if len(fields) < 7:
                    continue
                ts = float(fields[0])
                src_ip, dst_ip, dst_port = fields[2], fields[4], fields[5]
                key = (src_ip, dst_ip, dst_port)
                connections[key].append(ts)
    except (FileNotFoundError, ValueError):
        logger.warning("Zeek conn.log parse failed: %s", conn_log_path)
        return []
    beacons = []
    for (src, dst, port), timestamps in connections.items():
        if len(timestamps) < min_connections:
            continue
        timestamps.sort()
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        if not intervals:
            continue
        avg_interval = sum(intervals) / len(intervals)
        if avg_interval < 1:
            continue
        std_interval = math.sqrt(sum((x - avg_interval) ** 2 for x in intervals) / len(intervals))
        jitter_pct = (std_interval / avg_interval) * 100 if avg_interval > 0 else 100
        if jitter_pct <= max_jitter_pct:
            beacon_score = round(max(0, 1 - (jitter_pct / 100)) * 100, 1)
            if beacon_score >= 60:
                beacons.append({
                    "indicator": "beacon_timing",
                    "src_ip": src, "dst_ip": dst, "dst_port": port,
                    "connections": len(timestamps),
                    "avg_interval_sec": round(avg_interval, 1),
                    "jitter_pct": round(jitter_pct, 1),
                    "beacon_score": beacon_score,
                    "severity": "critical" if beacon_score >= 85 else "high",
                    "confidence": int(beacon_score),
                })
    return sorted(beacons, key=lambda x: x["beacon_score"], reverse=True)


def check_http_profiles(http_log_path):
    """Detect known Cobalt Strike HTTP malleable C2 profile patterns."""
    cs_uri_patterns = [
        r"^/[a-zA-Z]{4}$", r"^/submit\.php\?id=\d+$", r"^/pixel\.(gif|png)$",
        r"^/__utm\.gif$", r"^/updates\.(rss|json)$", r"^/visit\.js$",
    ]
    cs_ua_patterns = [
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)",
    ]
    findings = []
    try:
        with open(http_log_path) as f:
            for line in f:
                if line.startswith("#"):
                    continue
                fields = line.strip().split("\t")
                if len(fields) < 12:
                    continue
                src_ip, dst_ip = fields[2], fields[4]
                uri = fields[9] if len(fields) > 9 else ""
                user_agent = fields[12] if len(fields) > 12 else ""
                for pattern in cs_uri_patterns:
                    if re.match(pattern, uri):
                        findings.append({
                            "indicator": "cs_http_profile",
                            "src_ip": src_ip, "dst_ip": dst_ip,
                            "uri": uri, "user_agent": user_agent[:100],
                            "matched_pattern": pattern,
                            "severity": "high", "confidence": 60,
                        })
                        break
                if user_agent in cs_ua_patterns:
                    findings.append({
                        "indicator": "cs_default_user_agent",
                        "src_ip": src_ip, "dst_ip": dst_ip,
                        "user_agent": user_agent,
                        "severity": "high", "confidence": 70,
                    })
    except FileNotFoundError:
        logger.warning("Zeek http.log not found: %s", http_log_path)
    return findings


def generate_report(tls_findings, beacon_findings, http_findings):
    all_findings = tls_findings + beacon_findings + http_findings
    critical = sum(1 for f in all_findings if f.get("severity") == "critical")
    by_dst = defaultdict(int)
    for f in all_findings:
        by_dst[f.get("dst_ip", "")] += 1
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "tls_certificate_hits": len(tls_findings),
        "beacon_timing_detections": len(beacon_findings),
        "http_profile_matches": len(http_findings),
        "total_indicators": len(all_findings),
        "critical_indicators": critical,
        "top_suspect_destinations": dict(sorted(by_dst.items(), key=lambda x: x[1], reverse=True)[:10]),
        "findings": all_findings[:30],
        "cobalt_strike_likely": critical > 0,
    }


def main():
    parser = argparse.ArgumentParser(description="Cobalt Strike Beacon Hunting Agent")
    parser.add_argument("--zeek-dir", required=True, help="Directory containing Zeek log files")
    parser.add_argument("--min-connections", type=int, default=20, help="Minimum connections for beacon analysis")
    parser.add_argument("--max-jitter", type=int, default=25, help="Maximum jitter percentage for beacon scoring")
    parser.add_argument("--output", default="cobalt_strike_hunt_report.json")
    args = parser.parse_args()

    ssl_log = os.path.join(args.zeek_dir, "ssl.log")
    conn_log = os.path.join(args.zeek_dir, "conn.log")
    http_log = os.path.join(args.zeek_dir, "http.log")
    tls_findings = parse_zeek_ssl_log(ssl_log)
    beacon_findings = analyze_beacon_timing(conn_log, args.min_connections, args.max_jitter)
    http_findings = check_http_profiles(http_log)
    report = generate_report(tls_findings, beacon_findings, http_findings)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("CS Hunt: %d TLS hits, %d beacons, %d HTTP matches, CS likely: %s",
                len(tls_findings), len(beacon_findings), len(http_findings), report["cobalt_strike_likely"])
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
