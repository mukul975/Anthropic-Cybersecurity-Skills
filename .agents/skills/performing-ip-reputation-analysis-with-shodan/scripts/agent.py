#!/usr/bin/env python3
"""Agent for performing IP reputation analysis using the Shodan API."""

import json
import argparse
from datetime import datetime

try:
    import shodan
    HAS_SHODAN = True
except ImportError:
    HAS_SHODAN = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def shodan_host_lookup(api_key, ip):
    """Look up IP details from Shodan."""
    api = shodan.Shodan(api_key)
    result = api.host(ip)
    return {
        "ip": result.get("ip_str"),
        "org": result.get("org"),
        "asn": result.get("asn"),
        "isp": result.get("isp"),
        "os": result.get("os"),
        "country": result.get("country_code"),
        "city": result.get("city"),
        "open_ports": result.get("ports", []),
        "vulns": result.get("vulns", []),
        "hostnames": result.get("hostnames", []),
        "last_update": result.get("last_update"),
        "services": [
            {"port": s.get("port"), "transport": s.get("transport"),
             "product": s.get("product"), "version": s.get("version")}
            for s in result.get("data", [])
        ][:20],
    }


def abuseipdb_check(api_key, ip, max_age_days=90):
    """Check IP reputation on AbuseIPDB."""
    resp = requests.get(ABUSEIPDB_URL, headers={"Key": api_key, "Accept": "application/json"},
                        params={"ipAddress": ip, "maxAgeInDays": max_age_days}, timeout=15)
    resp.raise_for_status()
    data = resp.json().get("data", {})
    return {
        "ip": data.get("ipAddress"),
        "abuse_confidence": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "is_tor": data.get("isTor"),
        "is_whitelisted": data.get("isWhitelisted"),
        "last_reported": data.get("lastReportedAt"),
    }


def bulk_reputation(shodan_key, ips, abuseipdb_key=None):
    """Analyze reputation of multiple IPs."""
    results = []
    for ip in ips:
        ip = ip.strip()
        if not ip:
            continue
        entry = {"ip": ip}
        try:
            entry["shodan"] = shodan_host_lookup(shodan_key, ip)
        except Exception as e:
            entry["shodan"] = {"error": str(e)}
        if abuseipdb_key:
            try:
                entry["abuseipdb"] = abuseipdb_check(abuseipdb_key, ip)
            except Exception as e:
                entry["abuseipdb"] = {"error": str(e)}
        risk = "low"
        abuse_score = entry.get("abuseipdb", {}).get("abuse_confidence", 0) or 0
        vulns = entry.get("shodan", {}).get("vulns", [])
        if abuse_score >= 80 or len(vulns) >= 3:
            risk = "critical"
        elif abuse_score >= 50 or len(vulns) >= 1:
            risk = "high"
        elif abuse_score >= 20:
            risk = "medium"
        entry["risk"] = risk
        results.append(entry)
    return {"timestamp": datetime.utcnow().isoformat(), "total": len(results), "results": results}


def main():
    parser = argparse.ArgumentParser(description="IP Reputation Analysis Agent")
    parser.add_argument("--shodan-key", required=True, help="Shodan API key")
    parser.add_argument("--abuseipdb-key", help="AbuseIPDB API key")
    sub = parser.add_subparsers(dest="command")
    l = sub.add_parser("lookup", help="Look up single IP")
    l.add_argument("--ip", required=True)
    b = sub.add_parser("bulk", help="Analyze multiple IPs")
    b.add_argument("--ips", nargs="+", required=True)
    args = parser.parse_args()
    if not HAS_SHODAN:
        print(json.dumps({"error": "shodan library not installed"}))
        return
    if args.command == "lookup":
        result = {"shodan": shodan_host_lookup(args.shodan_key, args.ip)}
        if args.abuseipdb_key and HAS_REQUESTS:
            result["abuseipdb"] = abuseipdb_check(args.abuseipdb_key, args.ip)
    elif args.command == "bulk":
        result = bulk_reputation(args.shodan_key, args.ips, args.abuseipdb_key)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
