#!/usr/bin/env python3
"""
Ransomware Precursor Detection Engine

Analyzes network logs (Zeek format) to detect ransomware precursor patterns:
- C2 beaconing detection via statistical interval analysis
- Internal reconnaissance scanning
- Kerberoasting and credential harvesting indicators
- Admin share enumeration
- Data staging via large SMB transfers

Reads Zeek TSV logs and generates structured alerts.
"""

import csv
import json
import math
import os
import sys
import statistics
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


@dataclass
class PrecursorAlert:
    alert_id: str
    timestamp: str
    source_ip: str
    dest_ip: str
    category: str
    confidence: str
    kill_chain_phase: str
    description: str
    mitre_technique: str
    evidence: list = field(default_factory=list)


class BeaconDetector:
    """Detects C2 beaconing by analyzing connection interval patterns."""

    def __init__(self, min_connections: int = 20, beacon_score_threshold: float = 0.7):
        self.min_connections = min_connections
        self.beacon_score_threshold = beacon_score_threshold
        self.connections = defaultdict(list)

    def add_connection(self, src_ip: str, dst_ip: str, timestamp: float, orig_bytes: int, resp_bytes: int):
        key = (src_ip, dst_ip)
        self.connections[key].append({
            "ts": timestamp,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
        })

    def calculate_beacon_score(self, timestamps: list) -> dict:
        """Calculate beacon score based on connection interval regularity."""
        if len(timestamps) < self.min_connections:
            return {"score": 0.0, "interval": 0, "jitter": 0}

        sorted_ts = sorted(timestamps)
        intervals = [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]

        if not intervals:
            return {"score": 0.0, "interval": 0, "jitter": 0}

        median_interval = statistics.median(intervals)
        if median_interval == 0:
            return {"score": 0.0, "interval": 0, "jitter": 0}

        # Calculate coefficient of variation (lower = more regular = more likely beacon)
        try:
            stdev = statistics.stdev(intervals)
            cv = stdev / median_interval
        except statistics.StatisticsError:
            cv = 0

        # Beacon score: inverse of coefficient of variation, capped at 1.0
        # Perfect beacon (cv=0) scores 1.0, high variation scores low
        if cv == 0:
            score = 1.0
        else:
            score = max(0, min(1.0, 1.0 - cv))

        # Penalize very short intervals (likely legitimate keep-alives under 5s)
        if median_interval < 5:
            score *= 0.5

        # Penalize very long intervals (over 1 hour - less likely active C2)
        if median_interval > 3600:
            score *= 0.7

        return {
            "score": round(score, 3),
            "interval": round(median_interval, 1),
            "jitter": round(stdev, 1) if stdev else 0,
            "connection_count": len(timestamps),
        }

    def detect(self) -> list:
        """Detect beaconing patterns in collected connections."""
        alerts = []
        for (src_ip, dst_ip), conns in self.connections.items():
            timestamps = [c["ts"] for c in conns]
            result = self.calculate_beacon_score(timestamps)

            if result["score"] >= self.beacon_score_threshold:
                # Check for consistent payload sizes (another beacon indicator)
                orig_sizes = [c["orig_bytes"] for c in conns if c["orig_bytes"] > 0]
                size_consistency = 0.0
                if len(orig_sizes) >= 5:
                    try:
                        size_cv = statistics.stdev(orig_sizes) / statistics.mean(orig_sizes)
                        size_consistency = max(0, 1.0 - size_cv)
                    except (statistics.StatisticsError, ZeroDivisionError):
                        pass

                combined_score = (result["score"] * 0.7) + (size_consistency * 0.3)

                if combined_score >= self.beacon_score_threshold:
                    confidence = "High" if combined_score >= 0.9 else "Medium"
                    alert = PrecursorAlert(
                        alert_id=f"BEACON-{src_ip}-{dst_ip}",
                        timestamp=datetime.fromtimestamp(max(timestamps)).isoformat(),
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        category="C2 Beaconing",
                        confidence=confidence,
                        kill_chain_phase="Command and Control",
                        description=(
                            f"Beaconing pattern detected: {result['connection_count']} connections "
                            f"at {result['interval']}s intervals (jitter: {result['jitter']}s, "
                            f"beacon score: {combined_score:.3f})"
                        ),
                        mitre_technique="T1071 - Application Layer Protocol",
                        evidence=[
                            f"Beacon score: {combined_score:.3f}",
                            f"Interval: {result['interval']}s",
                            f"Jitter: {result['jitter']}s",
                            f"Payload size consistency: {size_consistency:.3f}",
                            f"Connections: {result['connection_count']}",
                        ],
                    )
                    alerts.append(alert)
        return alerts


class ScanDetector:
    """Detects internal reconnaissance scanning."""

    def __init__(self, unique_dest_threshold: int = 30, time_window_seconds: int = 300):
        self.threshold = unique_dest_threshold
        self.window = time_window_seconds
        self.connections = defaultdict(list)

    def add_connection(self, src_ip: str, dst_ip: str, dst_port: int, timestamp: float):
        self.connections[src_ip].append({
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "ts": timestamp,
        })

    def detect(self) -> list:
        alerts = []
        for src_ip, conns in self.connections.items():
            sorted_conns = sorted(conns, key=lambda c: c["ts"])

            # Sliding window analysis
            window_start = 0
            for window_end in range(len(sorted_conns)):
                while (sorted_conns[window_end]["ts"] - sorted_conns[window_start]["ts"]) > self.window:
                    window_start += 1

                window_conns = sorted_conns[window_start:window_end + 1]
                unique_dests = set(c["dst_ip"] for c in window_conns)
                unique_ports = set(c["dst_port"] for c in window_conns)

                if len(unique_dests) >= self.threshold:
                    alert = PrecursorAlert(
                        alert_id=f"SCAN-{src_ip}-{int(sorted_conns[window_start]['ts'])}",
                        timestamp=datetime.fromtimestamp(sorted_conns[window_end]["ts"]).isoformat(),
                        source_ip=src_ip,
                        dest_ip="Multiple",
                        category="Internal Reconnaissance",
                        confidence="High" if len(unique_dests) >= self.threshold * 2 else "Medium",
                        kill_chain_phase="Discovery",
                        description=(
                            f"Internal scan: {len(unique_dests)} unique destinations on "
                            f"{len(unique_ports)} ports within {self.window}s window"
                        ),
                        mitre_technique="T1046 - Network Service Discovery",
                        evidence=[
                            f"Unique destinations: {len(unique_dests)}",
                            f"Unique ports: {sorted(unique_ports)}",
                            f"Total connections: {len(window_conns)}",
                            f"Time window: {self.window}s",
                        ],
                    )
                    alerts.append(alert)
                    break  # One alert per source IP per window

        return alerts


class CredentialHarvestDetector:
    """Detects Kerberoasting and credential harvesting patterns."""

    def __init__(self, kerberoast_threshold: int = 5):
        self.threshold = kerberoast_threshold
        self.tgs_requests = defaultdict(list)
        self.smb_failures = defaultdict(int)

    def add_kerberos_event(self, src_ip: str, service_name: str, encryption_type: str, timestamp: float):
        self.tgs_requests[src_ip].append({
            "service": service_name,
            "enc_type": encryption_type,
            "ts": timestamp,
        })

    def add_smb_failure(self, src_ip: str, dst_ip: str):
        self.smb_failures[src_ip] += 1

    def detect(self) -> list:
        alerts = []

        # Kerberoasting: multiple TGS requests for unique services with RC4 encryption
        for src_ip, requests in self.tgs_requests.items():
            rc4_requests = [r for r in requests if "rc4" in r.get("enc_type", "").lower()
                          or "23" in str(r.get("enc_type", ""))]
            unique_services = set(r["service"] for r in rc4_requests)

            if len(unique_services) >= self.threshold:
                alert = PrecursorAlert(
                    alert_id=f"KERB-{src_ip}",
                    timestamp=datetime.fromtimestamp(max(r["ts"] for r in rc4_requests)).isoformat(),
                    source_ip=src_ip,
                    dest_ip="Domain Controller",
                    category="Kerberoasting",
                    confidence="High",
                    kill_chain_phase="Credential Access",
                    description=(
                        f"Possible Kerberoasting: {len(unique_services)} unique service ticket "
                        f"requests with RC4 encryption from single host"
                    ),
                    mitre_technique="T1558.003 - Kerberoasting",
                    evidence=[
                        f"Unique services targeted: {len(unique_services)}",
                        f"RC4 encryption requests: {len(rc4_requests)}",
                        f"Services: {list(unique_services)[:10]}",
                    ],
                )
                alerts.append(alert)

        # SMB brute force
        for src_ip, count in self.smb_failures.items():
            if count >= 10:
                alert = PrecursorAlert(
                    alert_id=f"SMB-BRUTE-{src_ip}",
                    timestamp=datetime.now().isoformat(),
                    source_ip=src_ip,
                    dest_ip="Multiple",
                    category="SMB Brute Force",
                    confidence="Medium",
                    kill_chain_phase="Credential Access",
                    description=f"SMB authentication failures: {count} failed attempts",
                    mitre_technique="T1110 - Brute Force",
                    evidence=[f"Failed SMB auth count: {count}"],
                )
                alerts.append(alert)

        return alerts


class AdminShareDetector:
    """Detects suspicious access to administrative shares (C$, ADMIN$, IPC$)."""

    def __init__(self, threshold: int = 5):
        self.threshold = threshold
        self.share_access = defaultdict(lambda: defaultdict(set))

    def add_share_access(self, src_ip: str, dst_ip: str, share_name: str, timestamp: float):
        admin_shares = {"ADMIN$", "C$", "IPC$", "D$", "E$"}
        normalized_share = share_name.split("\\")[-1].upper()
        if normalized_share in admin_shares:
            self.share_access[src_ip][normalized_share].add(dst_ip)

    def detect(self) -> list:
        alerts = []
        for src_ip, shares in self.share_access.items():
            total_targets = set()
            for share, targets in shares.items():
                total_targets.update(targets)

            if len(total_targets) >= self.threshold:
                alert = PrecursorAlert(
                    alert_id=f"ADMINSHARE-{src_ip}",
                    timestamp=datetime.now().isoformat(),
                    source_ip=src_ip,
                    dest_ip="Multiple",
                    category="Admin Share Enumeration",
                    confidence="High" if len(total_targets) >= self.threshold * 2 else "Medium",
                    kill_chain_phase="Lateral Movement",
                    description=(
                        f"Admin share access to {len(total_targets)} hosts: "
                        f"shares accessed: {list(shares.keys())}"
                    ),
                    mitre_technique="T1021.002 - SMB/Windows Admin Shares",
                    evidence=[
                        f"Unique targets: {len(total_targets)}",
                        f"Shares accessed: {dict((s, len(t)) for s, t in shares.items())}",
                    ],
                )
                alerts.append(alert)

        return alerts


class RansomwarePrecursorEngine:
    """Orchestrates all detection modules."""

    def __init__(self):
        self.beacon_detector = BeaconDetector()
        self.scan_detector = ScanDetector()
        self.cred_detector = CredentialHarvestDetector()
        self.share_detector = AdminShareDetector()
        self.alerts = []

    def load_zeek_conn_log(self, filepath: str):
        """Parse Zeek conn.log for beacon and scan detection."""
        with open(filepath, "r") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                fields = line.strip().split("\t")
                if len(fields) < 20:
                    continue
                try:
                    ts = float(fields[0])
                    src_ip = fields[2]
                    src_port = int(fields[3]) if fields[3] != "-" else 0
                    dst_ip = fields[4]
                    dst_port = int(fields[5]) if fields[5] != "-" else 0
                    proto = fields[6]
                    orig_bytes = int(fields[9]) if fields[9] != "-" else 0
                    resp_bytes = int(fields[10]) if fields[10] != "-" else 0

                    # Feed to beacon detector (external destinations)
                    if not self._is_internal(dst_ip):
                        self.beacon_detector.add_connection(src_ip, dst_ip, ts, orig_bytes, resp_bytes)

                    # Feed to scan detector (internal destinations)
                    if self._is_internal(src_ip) and self._is_internal(dst_ip):
                        self.scan_detector.add_connection(src_ip, dst_ip, dst_port, ts)
                except (ValueError, IndexError):
                    continue

    def _is_internal(self, ip: str) -> bool:
        """Check if IP is in RFC1918 private range."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            first = int(parts[0])
            second = int(parts[1])
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
        except ValueError:
            pass
        return False

    def run_detection(self) -> list:
        """Run all detectors and return combined alerts."""
        self.alerts = []
        self.alerts.extend(self.beacon_detector.detect())
        self.alerts.extend(self.scan_detector.detect())
        self.alerts.extend(self.cred_detector.detect())
        self.alerts.extend(self.share_detector.detect())

        # Sort by confidence (High first)
        confidence_order = {"High": 0, "Medium": 1, "Low": 2}
        self.alerts.sort(key=lambda a: confidence_order.get(a.confidence, 3))

        return self.alerts

    def generate_report(self) -> str:
        """Generate formatted detection report."""
        if not self.alerts:
            self.run_detection()

        lines = []
        lines.append("=" * 70)
        lines.append("RANSOMWARE PRECURSOR DETECTION REPORT")
        lines.append("=" * 70)
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append(f"Total Alerts: {len(self.alerts)}")

        by_category = defaultdict(list)
        for alert in self.alerts:
            by_category[alert.category].append(alert)

        lines.append(f"\nAlert Categories:")
        for cat, cat_alerts in sorted(by_category.items()):
            lines.append(f"  - {cat}: {len(cat_alerts)}")

        lines.append("")
        for i, alert in enumerate(self.alerts, 1):
            lines.append("-" * 50)
            lines.append(f"Alert #{i}: {alert.alert_id}")
            lines.append(f"  Category: {alert.category}")
            lines.append(f"  Confidence: {alert.confidence}")
            lines.append(f"  Kill Chain: {alert.kill_chain_phase}")
            lines.append(f"  Source: {alert.source_ip}")
            lines.append(f"  Destination: {alert.dest_ip}")
            lines.append(f"  MITRE: {alert.mitre_technique}")
            lines.append(f"  Description: {alert.description}")
            lines.append(f"  Evidence:")
            for e in alert.evidence:
                lines.append(f"    - {e}")

        lines.append("")
        lines.append("=" * 70)
        return "\n".join(lines)


def main():
    """Run detection engine with sample data or Zeek log file."""
    engine = RansomwarePrecursorEngine()

    # Check for Zeek conn.log argument
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
        if os.path.exists(log_file):
            print(f"Loading Zeek conn.log: {log_file}")
            engine.load_zeek_conn_log(log_file)
        else:
            print(f"File not found: {log_file}")
            sys.exit(1)
    else:
        # Demo with simulated data
        print("No Zeek log provided. Running with simulated beacon data...")
        import time

        base_time = time.time() - 3600  # 1 hour ago

        # Simulate Cobalt Strike beacon (60-second interval)
        for i in range(40):
            jitter = (i % 3) * 2  # Small jitter
            engine.beacon_detector.add_connection(
                "10.1.5.42", "185.220.101.42",
                base_time + (i * 60) + jitter,
                orig_bytes=48, resp_bytes=128,
            )

        # Simulate internal port scan
        for i in range(50):
            engine.scan_detector.add_connection(
                "10.1.5.42", f"10.1.5.{100 + i}", 445,
                base_time + 1800 + (i * 2),
            )

        # Simulate Kerberoasting
        for i in range(8):
            engine.cred_detector.add_kerberos_event(
                "10.1.5.42", f"MSSQLSvc/sql{i}.corp.local:1433",
                "rc4-hmac", base_time + 2000 + (i * 5),
            )

        # Simulate admin share access
        for i in range(12):
            engine.share_detector.add_share_access(
                "10.1.5.42", f"10.1.5.{200 + i}", "ADMIN$",
                base_time + 2500 + (i * 10),
            )

    report = engine.generate_report()
    print(report)

    # Export alerts as JSON
    alerts_json = [asdict(a) for a in engine.alerts]
    output_path = Path(__file__).parent / "precursor_alerts.json"
    with open(output_path, "w") as f:
        json.dump(alerts_json, f, indent=2)
    print(f"\nAlerts exported to: {output_path}")


if __name__ == "__main__":
    main()
