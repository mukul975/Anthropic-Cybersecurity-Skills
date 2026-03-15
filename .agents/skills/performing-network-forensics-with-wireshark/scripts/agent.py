#!/usr/bin/env python3
"""Agent for performing network forensics with Wireshark/pyshark.

Analyzes PCAP files to extract conversations, DNS queries, HTTP
objects, detect beaconing patterns, and identify C2 communications.
"""

import pyshark
import json
import sys
from collections import defaultdict
from pathlib import Path
from datetime import datetime


class NetworkForensicsAgent:
    """Analyzes PCAP files for forensic investigations."""

    def __init__(self, pcap_path, output_dir):
        self.pcap_path = pcap_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def get_capture_info(self):
        """Get basic capture file statistics."""
        cap = pyshark.FileCapture(self.pcap_path, only_summaries=True)
        packet_count = 0
        first_time = None
        last_time = None
        for pkt in cap:
            packet_count += 1
            if first_time is None:
                first_time = pkt.time
            last_time = pkt.time
        cap.close()
        return {
            "file": self.pcap_path,
            "packets": packet_count,
            "first_packet": str(first_time),
            "last_packet": str(last_time),
        }

    def extract_dns_queries(self, limit=5000):
        """Extract DNS queries from the capture."""
        cap = pyshark.FileCapture(self.pcap_path, display_filter="dns.qr==0")
        queries = []
        count = 0
        for pkt in cap:
            if count >= limit:
                break
            try:
                queries.append({
                    "timestamp": str(pkt.sniff_time),
                    "src_ip": pkt.ip.src,
                    "query": pkt.dns.qry_name,
                    "type": pkt.dns.qry_type,
                })
                count += 1
            except AttributeError:
                continue
        cap.close()
        return queries

    def detect_dns_tunneling(self, min_length=30):
        """Detect potential DNS tunneling by subdomain length."""
        queries = self.extract_dns_queries()
        suspicious = []
        for q in queries:
            domain = q.get("query", "")
            subdomain = domain.split(".")[0] if "." in domain else domain
            if len(subdomain) >= min_length:
                suspicious.append({
                    "query": domain,
                    "subdomain_length": len(subdomain),
                    "src_ip": q["src_ip"],
                    "timestamp": q["timestamp"],
                })
        return suspicious

    def extract_http_requests(self, limit=5000):
        """Extract HTTP requests with method, host, URI, and user-agent."""
        cap = pyshark.FileCapture(self.pcap_path, display_filter="http.request")
        requests_list = []
        count = 0
        for pkt in cap:
            if count >= limit:
                break
            try:
                req = {
                    "timestamp": str(pkt.sniff_time),
                    "src_ip": pkt.ip.src,
                    "dst_ip": pkt.ip.dst,
                    "method": pkt.http.request_method,
                    "host": getattr(pkt.http, "host", ""),
                    "uri": getattr(pkt.http, "request_uri", ""),
                    "user_agent": getattr(pkt.http, "user_agent", ""),
                }
                requests_list.append(req)
                count += 1
            except AttributeError:
                continue
        cap.close()
        return requests_list

    def extract_tls_sni(self, limit=5000):
        """Extract TLS Server Name Indication values."""
        cap = pyshark.FileCapture(
            self.pcap_path,
            display_filter="tls.handshake.extensions_server_name"
        )
        sni_list = []
        count = 0
        for pkt in cap:
            if count >= limit:
                break
            try:
                sni_list.append({
                    "timestamp": str(pkt.sniff_time),
                    "src_ip": pkt.ip.src,
                    "dst_ip": pkt.ip.dst,
                    "sni": pkt.tls.handshake_extensions_server_name,
                })
                count += 1
            except AttributeError:
                continue
        cap.close()
        return sni_list

    def get_top_talkers(self, limit=20):
        """Identify top source and destination IPs by packet count."""
        cap = pyshark.FileCapture(self.pcap_path, only_summaries=True)
        ip_counts = defaultdict(int)
        for pkt in cap:
            try:
                ip_counts[pkt.source] += 1
                ip_counts[pkt.destination] += 1
            except AttributeError:
                continue
        cap.close()
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"ip": ip, "packets": count} for ip, count in sorted_ips[:limit]]

    def detect_beaconing(self, target_ip, tolerance=5):
        """Detect beaconing patterns to a specific IP."""
        cap = pyshark.FileCapture(
            self.pcap_path,
            display_filter=f"ip.dst=={target_ip} and tcp.flags.syn==1"
        )
        timestamps = []
        for pkt in cap:
            try:
                timestamps.append(float(pkt.sniff_timestamp))
            except (AttributeError, ValueError):
                continue
        cap.close()

        if len(timestamps) < 3:
            return {"beaconing": False, "connections": len(timestamps)}

        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        avg_interval = sum(intervals) / len(intervals)
        consistent = sum(1 for i in intervals if abs(i - avg_interval) < tolerance)

        return {
            "target_ip": target_ip,
            "connections": len(timestamps),
            "avg_interval_sec": round(avg_interval, 1),
            "consistent_intervals": consistent,
            "total_intervals": len(intervals),
            "beaconing": consistent / len(intervals) > 0.7 if intervals else False,
        }

    def find_suspicious_ports(self):
        """Find connections to commonly malicious ports."""
        suspicious_ports = {"4444", "8080", "1337", "6667", "9001", "31337"}
        cap = pyshark.FileCapture(self.pcap_path, display_filter="tcp")
        findings = defaultdict(lambda: {"count": 0, "sources": set()})

        for pkt in cap:
            try:
                dport = pkt.tcp.dstport
                if dport in suspicious_ports:
                    findings[dport]["count"] += 1
                    findings[dport]["sources"].add(pkt.ip.src)
            except AttributeError:
                continue
        cap.close()

        return {
            port: {"count": data["count"], "sources": list(data["sources"])}
            for port, data in findings.items()
        }

    def generate_report(self, target_ip=None):
        """Generate comprehensive network forensics report."""
        report = {
            "capture_info": self.get_capture_info(),
            "top_talkers": self.get_top_talkers(),
            "dns_query_count": len(self.extract_dns_queries()),
            "dns_tunneling_suspects": self.detect_dns_tunneling(),
            "http_request_count": len(self.extract_http_requests()),
            "tls_sni_count": len(self.extract_tls_sni()),
            "suspicious_ports": self.find_suspicious_ports(),
        }

        if target_ip:
            report["beaconing_analysis"] = self.detect_beaconing(target_ip)

        report_path = self.output_dir / "network_forensics_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=list)
        print(json.dumps(report, indent=2, default=list))
        return report


def main():
    if len(sys.argv) < 3:
        print("Usage: agent.py <pcap_file> <output_dir> [target_ip]")
        sys.exit(1)

    pcap_path = sys.argv[1]
    output_dir = sys.argv[2]
    target_ip = sys.argv[3] if len(sys.argv) > 3 else None

    agent = NetworkForensicsAgent(pcap_path, output_dir)
    agent.generate_report(target_ip)


if __name__ == "__main__":
    main()
