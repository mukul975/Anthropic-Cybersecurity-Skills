#!/usr/bin/env python3
"""Agent for detecting shadow IT cloud usage via proxy logs, DNS queries, and netflow."""

import json
import csv
import re
import argparse
from datetime import datetime
from collections import defaultdict

try:
    import pandas as pd
except ImportError:
    pd = None

try:
    import tldextract
except ImportError:
    tldextract = None

KNOWN_SAAS_DOMAINS = {
    "storage": ["dropbox.com", "box.com", "mega.nz", "wetransfer.com", "mediafire.com",
                 "pcloud.com", "sync.com", "icloud.com"],
    "email": ["protonmail.com", "tutanota.com", "guerrillamail.com", "yandex.com",
              "mail.ru", "zoho.com"],
    "dev_tools": ["github.com", "gitlab.com", "bitbucket.org", "replit.com",
                  "codepen.io", "stackblitz.com", "vercel.app", "netlify.app"],
    "ai_ml": ["chat.openai.com", "claude.ai", "bard.google.com", "huggingface.co",
              "midjourney.com", "perplexity.ai"],
    "messaging": ["telegram.org", "web.telegram.org", "signal.org", "discord.com",
                  "slack.com", "whatsapp.com"],
    "file_sharing": ["pastebin.com", "hastebin.com", "justpaste.it", "file.io",
                     "anonfiles.com", "gofile.io"],
    "vpn_proxy": ["nordvpn.com", "expressvpn.com", "surfshark.com", "hide.me",
                  "windscribe.com", "protonvpn.com"],
}

APPROVED_DOMAINS = set()


def load_approved_list(filepath):
    """Load approved SaaS domain list from a text file."""
    global APPROVED_DOMAINS
    try:
        with open(filepath, "r") as f:
            APPROVED_DOMAINS = {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        APPROVED_DOMAINS = set()


def extract_domain(url_or_host):
    """Extract registered domain from URL or hostname."""
    if tldextract:
        ext = tldextract.extract(url_or_host)
        return f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else url_or_host.lower()
    host = re.sub(r'^https?://', '', url_or_host).split('/')[0].split(':')[0]
    parts = host.lower().split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else host


def parse_proxy_log(filepath):
    """Parse proxy access log (Squid/common format) into structured records."""
    records = []
    squid_pattern = re.compile(
        r'^(\S+)\s+(\d+)\s+(\S+)\s+\w+/(\d+)\s+(\d+)\s+(\w+)\s+(\S+)\s+'
    )
    with open(filepath, "r") as f:
        for line in f:
            m = squid_pattern.match(line)
            if m:
                records.append({
                    "timestamp": m.group(1),
                    "duration_ms": int(m.group(2)),
                    "client_ip": m.group(3),
                    "status_code": int(m.group(4)),
                    "bytes": int(m.group(5)),
                    "method": m.group(6),
                    "url": m.group(7),
                    "domain": extract_domain(m.group(7)),
                })
            else:
                parts = line.strip().split()
                if len(parts) >= 7:
                    url = parts[6] if parts[6].startswith("http") else parts[5]
                    records.append({
                        "client_ip": parts[0],
                        "timestamp": parts[3].lstrip("["),
                        "method": parts[5].lstrip('"'),
                        "url": url,
                        "domain": extract_domain(url),
                        "status_code": int(parts[8]) if len(parts) > 8 and parts[8].isdigit() else 0,
                        "bytes": int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else 0,
                    })
    return records


def parse_dns_log(filepath):
    """Parse DNS query log (named/bind query log format)."""
    records = []
    dns_pattern = re.compile(r'query:\s+(\S+)\s+IN\s+(\w+)')
    with open(filepath, "r") as f:
        for line in f:
            m = dns_pattern.search(line)
            if m:
                queried = m.group(1).rstrip(".")
                records.append({
                    "query_name": queried,
                    "query_type": m.group(2),
                    "domain": extract_domain(queried),
                    "raw_line": line.strip()[:200],
                })
    return records


def parse_csv_log(filepath):
    """Parse generic CSV log with columns: timestamp, src_ip, dst_domain, bytes_out, bytes_in."""
    records = []
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = extract_domain(row.get("dst_domain", row.get("domain", row.get("url", ""))))
            records.append({
                "timestamp": row.get("timestamp", ""),
                "client_ip": row.get("src_ip", row.get("client_ip", "")),
                "domain": domain,
                "bytes_out": int(row.get("bytes_out", row.get("bytes", 0)) or 0),
                "bytes_in": int(row.get("bytes_in", 0) or 0),
            })
    return records


def classify_domain(domain):
    """Classify a domain against known SaaS categories."""
    for category, domains in KNOWN_SAAS_DOMAINS.items():
        if domain in domains:
            return category
    return "unknown"


def analyze_traffic(records):
    """Aggregate traffic by domain using pandas and classify."""
    if not pd:
        agg = defaultdict(lambda: {"bytes": 0, "requests": 0, "users": set()})
        for r in records:
            d = r.get("domain", "")
            if not d:
                continue
            agg[d]["bytes"] += r.get("bytes", 0) + r.get("bytes_out", 0)
            agg[d]["requests"] += 1
            agg[d]["users"].add(r.get("client_ip", "unknown"))
        results = []
        for domain, stats in agg.items():
            cat = classify_domain(domain)
            approved = domain in APPROVED_DOMAINS
            risk = 0
            if not approved:
                risk += 30
            if cat in ("storage", "file_sharing", "vpn_proxy"):
                risk += 25
            if cat == "email":
                risk += 15
            risk += min(stats["bytes"] // (10 * 1024 * 1024), 20)
            risk += min(len(stats["users"]) * 3, 15)
            risk = min(risk, 100)
            results.append({
                "domain": domain,
                "category": cat,
                "approved": approved,
                "total_bytes": stats["bytes"],
                "total_bytes_mb": round(stats["bytes"] / (1024 * 1024), 2),
                "request_count": stats["requests"],
                "unique_users": len(stats["users"]),
                "risk_score": risk,
                "risk_level": "CRITICAL" if risk >= 70 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 25 else "LOW",
            })
        results.sort(key=lambda x: x["risk_score"], reverse=True)
        return results

    df = pd.DataFrame(records)
    if "bytes" not in df.columns:
        df["bytes"] = df.get("bytes_out", 0)
    df["bytes"] = pd.to_numeric(df["bytes"], errors="coerce").fillna(0)
    grouped = df.groupby("domain").agg(
        total_bytes=("bytes", "sum"),
        request_count=("domain", "count"),
        unique_users=("client_ip", "nunique") if "client_ip" in df.columns else ("domain", "count"),
    ).reset_index()
    results = []
    for _, row in grouped.iterrows():
        domain = row["domain"]
        cat = classify_domain(domain)
        approved = domain in APPROVED_DOMAINS
        risk = 0
        if not approved:
            risk += 30
        if cat in ("storage", "file_sharing", "vpn_proxy"):
            risk += 25
        if cat == "email":
            risk += 15
        risk += min(int(row["total_bytes"]) // (10 * 1024 * 1024), 20)
        risk += min(int(row["unique_users"]) * 3, 15)
        risk = min(risk, 100)
        results.append({
            "domain": domain,
            "category": cat,
            "approved": approved,
            "total_bytes": int(row["total_bytes"]),
            "total_bytes_mb": round(row["total_bytes"] / (1024 * 1024), 2),
            "request_count": int(row["request_count"]),
            "unique_users": int(row["unique_users"]),
            "risk_score": risk,
            "risk_level": "CRITICAL" if risk >= 70 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 25 else "LOW",
        })
    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return results


def full_audit(log_path, log_type="proxy", approved_list=None):
    """Run full shadow IT discovery audit."""
    if approved_list:
        load_approved_list(approved_list)
    if log_type == "proxy":
        records = parse_proxy_log(log_path)
    elif log_type == "dns":
        records = parse_dns_log(log_path)
    elif log_type == "csv":
        records = parse_csv_log(log_path)
    else:
        return {"error": f"Unknown log type: {log_type}"}
    analysis = analyze_traffic(records)
    unauthorized = [a for a in analysis if not a["approved"] and a["category"] != "unknown"]
    return {
        "audit_type": "Shadow IT Cloud Usage Discovery",
        "timestamp": datetime.utcnow().isoformat(),
        "log_file": log_path,
        "log_type": log_type,
        "total_records_parsed": len(records),
        "unique_domains": len(analysis),
        "unauthorized_saas_services": len(unauthorized),
        "critical_findings": sum(1 for a in analysis if a["risk_level"] == "CRITICAL"),
        "high_findings": sum(1 for a in analysis if a["risk_level"] == "HIGH"),
        "top_shadow_it_services": unauthorized[:20],
        "all_services": analysis[:50],
    }


def main():
    parser = argparse.ArgumentParser(description="Shadow IT Cloud Usage Detection Agent")
    parser.add_argument("log_file", help="Path to log file")
    parser.add_argument("--type", choices=["proxy", "dns", "csv"], default="proxy", help="Log file format")
    parser.add_argument("--approved", help="Path to approved domains list (one per line)")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("parse", help="Parse log file and show raw records")
    sub.add_parser("analyze", help="Analyze traffic patterns")
    sub.add_parser("full", help="Full shadow IT audit")
    args = parser.parse_args()

    if approved := args.approved:
        load_approved_list(approved)

    if args.command == "parse":
        if args.type == "proxy":
            result = parse_proxy_log(args.log_file)
        elif args.type == "dns":
            result = parse_dns_log(args.log_file)
        else:
            result = parse_csv_log(args.log_file)
    elif args.command == "analyze":
        if args.type == "proxy":
            records = parse_proxy_log(args.log_file)
        elif args.type == "dns":
            records = parse_dns_log(args.log_file)
        else:
            records = parse_csv_log(args.log_file)
        result = analyze_traffic(records)
    elif args.command == "full" or args.command is None:
        result = full_audit(args.log_file, args.type, args.approved)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
