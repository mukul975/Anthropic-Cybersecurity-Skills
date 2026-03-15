#!/usr/bin/env python3
"""Agent for performing network traffic analysis with Zeek (Bro) log files."""

import json
import argparse
import subprocess
import csv
from datetime import datetime
from pathlib import Path
from collections import Counter


def parse_zeek_log(log_file, delimiter="\t"):
    """Parse a Zeek TSV log file into structured records."""
    lines = Path(log_file).read_text(encoding="utf-8", errors="replace").splitlines()
    headers = []
    records = []
    for line in lines:
        if line.startswith("#fields"):
            headers = line.split(delimiter)[1:]
        elif line.startswith("#"):
            continue
        elif headers:
            values = line.split(delimiter)
            record = dict(zip(headers, values))
            records.append(record)
    return headers, records


def analyze_conn_log(conn_log):
    """Analyze Zeek conn.log for network connection patterns."""
    headers, records = parse_zeek_log(conn_log)
    total = len(records)
    protocols = Counter(r.get("proto", "") for r in records)
    services = Counter(r.get("service", "-") for r in records)
    src_ips = Counter(r.get("id.orig_h", "") for r in records)
    dst_ips = Counter(r.get("id.resp_h", "") for r in records)
    dst_ports = Counter(r.get("id.resp_p", "") for r in records)
    total_bytes = sum(int(r.get("orig_bytes", 0) or 0) + int(r.get("resp_bytes", 0) or 0) for r in records)
    long_connections = [r for r in records if float(r.get("duration", 0) or 0) > 3600]
    return {
        "log_file": conn_log, "total_connections": total,
        "protocols": dict(protocols), "services": dict(services.most_common(10)),
        "top_src_ips": dict(src_ips.most_common(10)),
        "top_dst_ips": dict(dst_ips.most_common(10)),
        "top_dst_ports": dict(dst_ports.most_common(15)),
        "total_bytes": total_bytes,
        "long_connections": len(long_connections),
    }


def analyze_dns_log(dns_log):
    """Analyze Zeek dns.log for DNS query patterns and anomalies."""
    headers, records = parse_zeek_log(dns_log)
    queries = Counter(r.get("query", "") for r in records)
    qtypes = Counter(r.get("qtype_name", r.get("qtype", "")) for r in records)
    rcodes = Counter(r.get("rcode_name", r.get("rcode", "")) for r in records)
    long_queries = [r for r in records if len(r.get("query", "")) > 50]
    txt_queries = [r for r in records if r.get("qtype_name", "") == "TXT"]
    nxdomain = [r for r in records if r.get("rcode_name", "") == "NXDOMAIN"]
    top_domains = Counter()
    for r in records:
        query = r.get("query", "")
        parts = query.rsplit(".", 2)
        if len(parts) >= 2:
            top_domains[".".join(parts[-2:])] += 1
    return {
        "log_file": dns_log, "total_queries": len(records),
        "query_types": dict(qtypes),
        "response_codes": dict(rcodes),
        "top_queried_domains": dict(top_domains.most_common(15)),
        "long_queries": len(long_queries),
        "txt_queries": len(txt_queries),
        "nxdomain_count": len(nxdomain),
        "potential_tunneling": len(long_queries) + len(txt_queries),
    }


def analyze_http_log(http_log):
    """Analyze Zeek http.log for web traffic patterns."""
    headers, records = parse_zeek_log(http_log)
    methods = Counter(r.get("method", "") for r in records)
    status_codes = Counter(r.get("status_code", "") for r in records)
    hosts = Counter(r.get("host", "") for r in records)
    user_agents = Counter(r.get("user_agent", "")[:100] for r in records)
    suspicious_ua = [r for r in records if any(kw in r.get("user_agent", "").lower()
                     for kw in ["curl", "wget", "python", "powershell", "certutil", "bitsadmin"])]
    return {
        "log_file": http_log, "total_requests": len(records),
        "methods": dict(methods), "status_codes": dict(status_codes),
        "top_hosts": dict(hosts.most_common(15)),
        "top_user_agents": dict(user_agents.most_common(10)),
        "suspicious_user_agents": len(suspicious_ua),
        "suspicious_requests": [{"host": r.get("host"), "uri": r.get("uri", "")[:100],
                                  "ua": r.get("user_agent", "")[:100]} for r in suspicious_ua[:10]],
    }


def analyze_notice_log(notice_log):
    """Analyze Zeek notice.log for security alerts."""
    headers, records = parse_zeek_log(notice_log)
    notice_types = Counter(r.get("note", r.get("msg", "")) for r in records)
    return {
        "log_file": notice_log, "total_notices": len(records),
        "notice_types": dict(notice_types),
        "notices": [{"note": r.get("note"), "msg": r.get("msg", "")[:200],
                      "src": r.get("src", r.get("id.orig_h", "")),
                      "dst": r.get("dst", r.get("id.resp_h", ""))} for r in records[:20]],
    }


def run_zeek_on_pcap(pcap_file, output_dir="/tmp/zeek_output"):
    """Run Zeek on a PCAP file to generate logs."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    cmd = ["zeek", "-r", pcap_file, f"Log::default_logdir={output_dir}"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=output_dir)
        logs = list(Path(output_dir).glob("*.log"))
        return {
            "pcap_file": pcap_file, "output_dir": output_dir,
            "logs_generated": [l.name for l in logs],
            "success": result.returncode == 0,
            "stderr": result.stderr[:300] if result.stderr else "",
        }
    except FileNotFoundError:
        return {"error": "zeek not found in PATH"}
    except Exception as e:
        return {"error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Zeek Network Traffic Analysis Agent")
    sub = parser.add_subparsers(dest="command")
    c = sub.add_parser("conn", help="Analyze conn.log")
    c.add_argument("--log", required=True)
    d = sub.add_parser("dns", help="Analyze dns.log")
    d.add_argument("--log", required=True)
    h = sub.add_parser("http", help="Analyze http.log")
    h.add_argument("--log", required=True)
    n = sub.add_parser("notice", help="Analyze notice.log")
    n.add_argument("--log", required=True)
    r = sub.add_parser("run", help="Run Zeek on PCAP")
    r.add_argument("--pcap", required=True)
    r.add_argument("--output-dir", default="/tmp/zeek_output")
    args = parser.parse_args()
    if args.command == "conn":
        result = analyze_conn_log(args.log)
    elif args.command == "dns":
        result = analyze_dns_log(args.log)
    elif args.command == "http":
        result = analyze_http_log(args.log)
    elif args.command == "notice":
        result = analyze_notice_log(args.log)
    elif args.command == "run":
        result = run_zeek_on_pcap(args.pcap, args.output_dir)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
