#!/usr/bin/env python3
"""Detect domain fronting C2 traffic via SNI/Host header mismatch and TLS certificate analysis."""

import json
import csv
import ssl
import socket
import argparse
from collections import defaultdict
from datetime import datetime

try:
    from OpenSSL import crypto
    HAS_PYOPENSSL = True
except ImportError:
    HAS_PYOPENSSL = False


CDN_PROVIDERS = {
    "cloudfront.net": "Amazon CloudFront",
    "azureedge.net": "Azure CDN",
    "cloudflare.com": "Cloudflare",
    "akamaiedge.net": "Akamai",
    "fastly.net": "Fastly",
    "googleapis.com": "Google Cloud CDN",
    "azurefd.net": "Azure Front Door",
}


def load_proxy_logs(filepath):
    """Load proxy logs CSV with columns: timestamp, src_ip, sni, host_header, dst_ip, dst_port, method, url, status."""
    records = []
    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append({
                "timestamp": row.get("timestamp", ""),
                "src_ip": row.get("src_ip", row.get("c-ip", "")),
                "sni": row.get("sni", row.get("cs-ssl-sni", "")).lower().strip(),
                "host_header": row.get("host_header", row.get("cs-host", "")).lower().strip(),
                "dst_ip": row.get("dst_ip", row.get("s-ip", "")),
                "dst_port": int(row.get("dst_port", row.get("s-port", "443"))),
                "method": row.get("method", row.get("cs-method", "")),
                "url": row.get("url", row.get("cs-uri-stem", "")),
                "status": row.get("status", row.get("sc-status", "")),
                "bytes": int(row.get("bytes", row.get("sc-bytes", "0"))),
            })
    return records


def extract_domain_root(domain):
    """Extract root domain from FQDN (e.g., sub.example.com -> example.com)."""
    parts = domain.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def identify_cdn_provider(domain):
    """Check if a domain belongs to a known CDN provider."""
    for cdn_suffix, provider in CDN_PROVIDERS.items():
        if domain.endswith(cdn_suffix):
            return provider
    return None


def detect_sni_host_mismatch(records):
    """Detect connections where SNI and Host header point to different domains."""
    alerts = []
    for rec in records:
        sni = rec["sni"]
        host = rec["host_header"]
        if not sni or not host:
            continue
        sni_root = extract_domain_root(sni)
        host_root = extract_domain_root(host)
        if sni_root != host_root:
            cdn = identify_cdn_provider(sni) or identify_cdn_provider(host)
            confidence = "high" if cdn else "medium"
            alerts.append({
                "detection": "SNI/Host Header Mismatch",
                "mitre_technique": "T1090.004",
                "timestamp": rec["timestamp"],
                "src_ip": rec["src_ip"],
                "sni": sni,
                "host_header": host,
                "sni_root": sni_root,
                "host_root": host_root,
                "cdn_provider": cdn,
                "dst_ip": rec["dst_ip"],
                "confidence": confidence,
                "severity": "critical" if cdn else "high",
                "description": f"Domain fronting: SNI={sni} but Host={host}",
            })
    return alerts


def get_tls_certificate_info(hostname, port=443, timeout=5):
    """Retrieve TLS certificate details for a given hostname using pyOpenSSL."""
    if not HAS_PYOPENSSL:
        return {"error": "pyOpenSSL not installed"}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(timeout)
            s.connect((hostname, port))
            der_cert = s.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)
        subject = dict(x509.get_subject().get_components())
        issuer = dict(x509.get_issuer().get_components())
        san_list = []
        for i in range(x509.get_extension_count()):
            ext = x509.get_extension(i)
            if ext.get_short_name() == b"subjectAltName":
                san_list = [s.strip().replace("DNS:", "") for s in str(ext).split(",")]
        return {
            "subject_cn": subject.get(b"CN", b"").decode(),
            "issuer_cn": issuer.get(b"CN", b"").decode(),
            "issuer_o": issuer.get(b"O", b"").decode(),
            "san": san_list[:20],
            "not_before": str(x509.get_notBefore()),
            "not_after": str(x509.get_notAfter()),
            "serial": str(x509.get_serial_number()),
        }
    except Exception as e:
        return {"error": str(e)}


def analyze_fronting_pairs(alerts):
    """Aggregate and rank domain fronting pairs by frequency."""
    pair_counts = defaultdict(int)
    for a in alerts:
        pair_counts[(a["sni"], a["host_header"])] += 1
    ranked = sorted(pair_counts.items(), key=lambda x: -x[1])
    return [{"sni": p[0], "host": p[1], "count": c} for (p, c) in ranked[:20]]


def main():
    parser = argparse.ArgumentParser(description="Domain Fronting C2 Traffic Hunter")
    parser.add_argument("--proxy-log", required=True, help="CSV proxy log with SNI and Host header fields")
    parser.add_argument("--check-certs", action="store_true", help="Fetch TLS certs for top fronting domains")
    parser.add_argument("--output", default="domain_fronting_report.json", help="Output report path")
    args = parser.parse_args()

    records = load_proxy_logs(args.proxy_log)
    print(f"[+] Loaded {len(records)} proxy log entries")

    alerts = detect_sni_host_mismatch(records)
    print(f"[+] Detected {len(alerts)} SNI/Host mismatches")

    fronting_pairs = analyze_fronting_pairs(alerts)
    cert_info = {}
    if args.check_certs and fronting_pairs:
        for pair in fronting_pairs[:5]:
            cert_info[pair["sni"]] = get_tls_certificate_info(pair["sni"])

    report = {
        "analysis_time": datetime.utcnow().isoformat() + "Z",
        "total_proxy_entries": len(records),
        "detections": alerts[:50],
        "total_mismatches": len(alerts),
        "fronting_pairs_ranked": fronting_pairs,
        "certificate_analysis": cert_info,
        "mitre_technique": "T1090.004",
        "cdn_involved": list({a["cdn_provider"] for a in alerts if a.get("cdn_provider")}),
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Top fronting pairs: {len(fronting_pairs)}")
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
