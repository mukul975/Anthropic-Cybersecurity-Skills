#!/usr/bin/env python3
"""
URLScan.io URL Analysis Automation

Submits suspicious URLs to URLScan.io for analysis, retrieves results,
extracts IOCs, and cross-references with threat intelligence sources.

Usage:
    python process.py scan --url "https://suspicious-site.com"
    python process.py scan --url-file urls.txt
    python process.py result --uuid <scan-uuid>
    python process.py search --query "domain:evil.com"
    python process.py ioc --uuid <scan-uuid>
"""

import argparse
import json
import sys
import time
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field, asdict

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "")
URLSCAN_BASE = "https://urlscan.io/api/v1"
VT_API_KEY = os.environ.get("VT_API_KEY", "")


@dataclass
class URLScanResult:
    """Parsed URLScan result."""
    uuid: str = ""
    url: str = ""
    effective_url: str = ""
    status_code: int = 0
    domain: str = ""
    ip: str = ""
    asn: str = ""
    asn_name: str = ""
    country: str = ""
    server: str = ""
    title: str = ""
    tls_issuer: str = ""
    tls_subject: str = ""
    tls_valid_from: str = ""
    tls_valid_to: str = ""
    screenshot_url: str = ""
    dom_url: str = ""
    technologies: list = field(default_factory=list)
    redirects: list = field(default_factory=list)
    domains_contacted: list = field(default_factory=list)
    ips_contacted: list = field(default_factory=list)
    urls_contacted: list = field(default_factory=list)
    has_login_form: bool = False
    resource_hashes: list = field(default_factory=list)
    verdicts: dict = field(default_factory=dict)
    is_malicious: bool = False
    risk_indicators: list = field(default_factory=list)


def submit_scan(url: str, visibility: str = "private",
                api_key: str = "") -> dict:
    """Submit a URL to URLScan for scanning."""
    if not api_key:
        api_key = URLSCAN_API_KEY
    if not api_key:
        print("Warning: No URLScan API key provided. Using public submission.", file=sys.stderr)

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["API-Key"] = api_key

    data = {"url": url, "visibility": visibility}

    try:
        resp = requests.post(f"{URLSCAN_BASE}/scan/", headers=headers,
                             json=data, timeout=30)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 429:
            print("Rate limited. Waiting 10 seconds...", file=sys.stderr)
            time.sleep(10)
            resp = requests.post(f"{URLSCAN_BASE}/scan/", headers=headers,
                                 json=data, timeout=30)
            return resp.json() if resp.status_code == 200 else {"error": resp.text}
        else:
            return {"error": f"HTTP {resp.status_code}: {resp.text}"}
    except Exception as e:
        return {"error": str(e)}


def get_result(uuid: str, api_key: str = "", max_wait: int = 60) -> dict:
    """Get scan results, polling until ready."""
    if not api_key:
        api_key = URLSCAN_API_KEY

    headers = {}
    if api_key:
        headers["API-Key"] = api_key

    for attempt in range(max_wait // 5):
        try:
            resp = requests.get(f"{URLSCAN_BASE}/result/{uuid}/",
                                headers=headers, timeout=30)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                time.sleep(5)
                continue
            else:
                return {"error": f"HTTP {resp.status_code}: {resp.text}"}
        except Exception as e:
            return {"error": str(e)}

    return {"error": "Timeout waiting for scan results"}


def search_scans(query: str, api_key: str = "", size: int = 10) -> list:
    """Search URLScan database."""
    if not api_key:
        api_key = URLSCAN_API_KEY

    headers = {}
    if api_key:
        headers["API-Key"] = api_key

    try:
        resp = requests.get(f"{URLSCAN_BASE}/search/?q={query}&size={size}",
                            headers=headers, timeout=30)
        if resp.status_code == 200:
            return resp.json().get("results", [])
    except Exception:
        pass
    return []


def parse_result(raw_result: dict) -> URLScanResult:
    """Parse raw URLScan API result into structured data."""
    result = URLScanResult()

    task = raw_result.get("task", {})
    result.uuid = task.get("uuid", "")
    result.url = task.get("url", "")

    page = raw_result.get("page", {})
    result.effective_url = page.get("url", "")
    result.status_code = page.get("status", 0)
    result.domain = page.get("domain", "")
    result.ip = page.get("ip", "")
    result.asn = page.get("asn", "")
    result.asn_name = page.get("asnname", "")
    result.country = page.get("country", "")
    result.server = page.get("server", "")
    result.title = page.get("title", "")

    # TLS info
    tls_list = raw_result.get("lists", {}).get("certificates", [])
    if tls_list:
        cert = tls_list[0]
        result.tls_issuer = cert.get("issuer", "")
        result.tls_subject = cert.get("subjectName", "")
        result.tls_valid_from = cert.get("validFrom", "")
        result.tls_valid_to = cert.get("validTo", "")

    # Screenshot and DOM URLs
    result.screenshot_url = f"https://urlscan.io/screenshots/{result.uuid}.png"
    result.dom_url = f"https://urlscan.io/dom/{result.uuid}/"

    # Technologies
    meta = raw_result.get("meta", {})
    for processor in meta.get("processors", {}).values():
        if isinstance(processor, dict) and "data" in processor:
            techs = processor["data"]
            if isinstance(techs, list):
                for tech in techs:
                    if isinstance(tech, dict) and "app" in tech:
                        result.technologies.append(tech["app"])

    # Redirects
    data = raw_result.get("data", {})
    for request in data.get("requests", [])[:5]:
        req_url = request.get("request", {}).get("request", {}).get("url", "")
        resp_url = request.get("response", {}).get("response", {}).get("url", "")
        if req_url != result.url:
            result.redirects.append(req_url)

    # Domains and IPs contacted
    lists = raw_result.get("lists", {})
    result.domains_contacted = lists.get("domains", [])
    result.ips_contacted = lists.get("ips", [])
    result.urls_contacted = lists.get("urls", [])[:50]

    # Resource hashes
    for request in data.get("requests", []):
        resp_data = request.get("response", {}).get("response", {})
        resp_hash = resp_data.get("hash", "")
        if resp_hash:
            result.resource_hashes.append({
                "url": resp_data.get("url", ""),
                "hash": resp_hash,
                "size": resp_data.get("size", 0),
                "mimeType": resp_data.get("mimeType", "")
            })

    # Check for login forms in DOM
    dom_content = raw_result.get("data", {}).get("dom", "")
    if isinstance(dom_content, str):
        if ('type="password"' in dom_content.lower() or
                'input type=password' in dom_content.lower() or
                '<form' in dom_content.lower()):
            result.has_login_form = True

    # Verdicts
    verdicts = raw_result.get("verdicts", {})
    result.verdicts = {
        "overall_score": verdicts.get("overall", {}).get("score", 0),
        "overall_malicious": verdicts.get("overall", {}).get("malicious", False),
        "urlscan_score": verdicts.get("urlscan", {}).get("score", 0),
        "engines": verdicts.get("engines", {}).get("malicious", []),
        "community_score": verdicts.get("community", {}).get("score", 0),
    }
    result.is_malicious = verdicts.get("overall", {}).get("malicious", False)

    # Risk indicators
    if result.has_login_form and result.domain != result.url.split("/")[2]:
        result.risk_indicators.append("Credential harvesting form on non-origin domain")
    if result.url != result.effective_url:
        result.risk_indicators.append(f"URL redirected: {result.url} -> {result.effective_url}")
    if result.is_malicious:
        result.risk_indicators.append("Flagged as malicious by URLScan verdicts")
    if len(result.redirects) > 3:
        result.risk_indicators.append(f"Excessive redirects ({len(result.redirects)})")

    return result


def extract_iocs(result: URLScanResult) -> dict:
    """Extract IOCs from scan result."""
    iocs = {
        "domains": list(set(result.domains_contacted)),
        "ips": list(set(result.ips_contacted)),
        "urls": [result.url, result.effective_url] + result.redirects,
        "hashes": [h["hash"] for h in result.resource_hashes if h.get("hash")],
        "tls_fingerprint": result.tls_subject,
        "scan_uuid": result.uuid,
        "scan_date": datetime.now(timezone.utc).isoformat(),
    }
    # Deduplicate URLs
    iocs["urls"] = list(set(u for u in iocs["urls"] if u))
    return iocs


def check_virustotal(url: str, api_key: str = "") -> dict:
    """Check URL against VirusTotal (requires API key)."""
    if not api_key:
        api_key = VT_API_KEY
    if not api_key:
        return {}

    url_id = hashlib.sha256(url.encode()).hexdigest()
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                            headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
    except Exception:
        pass
    return {}


def format_report(result: URLScanResult) -> str:
    """Format scan result as text report."""
    lines = []
    lines.append("=" * 60)
    lines.append("  URL ANALYSIS REPORT (URLScan.io)")
    lines.append("=" * 60)
    lines.append(f"  Scan UUID: {result.uuid}")
    lines.append(f"  Submitted URL: {result.url}")
    lines.append(f"  Effective URL: {result.effective_url}")
    lines.append(f"  Status Code: {result.status_code}")
    lines.append(f"  Malicious: {'YES' if result.is_malicious else 'NO'}")
    lines.append("")

    lines.append("[PAGE INFO]")
    lines.append(f"  Title: {result.title}")
    lines.append(f"  Domain: {result.domain}")
    lines.append(f"  IP: {result.ip}")
    lines.append(f"  ASN: {result.asn} ({result.asn_name})")
    lines.append(f"  Country: {result.country}")
    lines.append(f"  Server: {result.server}")
    lines.append(f"  Login Form: {'DETECTED' if result.has_login_form else 'Not found'}")
    lines.append(f"  Screenshot: {result.screenshot_url}")
    lines.append("")

    if result.tls_issuer:
        lines.append("[TLS CERTIFICATE]")
        lines.append(f"  Issuer: {result.tls_issuer}")
        lines.append(f"  Subject: {result.tls_subject}")
        lines.append("")

    if result.redirects:
        lines.append(f"[REDIRECTS] ({len(result.redirects)} found)")
        for r in result.redirects[:10]:
            lines.append(f"  -> {r}")
        lines.append("")

    if result.risk_indicators:
        lines.append(f"[RISK INDICATORS] ({len(result.risk_indicators)})")
        for ind in result.risk_indicators:
            lines.append(f"  - {ind}")
        lines.append("")

    lines.append(f"[INFRASTRUCTURE]")
    lines.append(f"  Domains contacted: {len(result.domains_contacted)}")
    lines.append(f"  IPs contacted: {len(result.ips_contacted)}")
    lines.append(f"  Resource hashes: {len(result.resource_hashes)}")

    lines.append("=" * 60)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="URLScan.io URL Analysis Tool")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a URL")
    scan_parser.add_argument("--url", help="Single URL to scan")
    scan_parser.add_argument("--url-file", help="File with URLs (one per line)")
    scan_parser.add_argument("--visibility", default="private",
                             choices=["public", "unlisted", "private"])
    scan_parser.add_argument("--wait", action="store_true", help="Wait for results")

    result_parser = subparsers.add_parser("result", help="Get scan result")
    result_parser.add_argument("--uuid", required=True)

    search_parser = subparsers.add_parser("search", help="Search URLScan database")
    search_parser.add_argument("--query", "-q", required=True)
    search_parser.add_argument("--size", type=int, default=10)

    ioc_parser = subparsers.add_parser("ioc", help="Extract IOCs from scan")
    ioc_parser.add_argument("--uuid", required=True)

    parser.add_argument("--api-key", default=URLSCAN_API_KEY)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", "-o")

    args = parser.parse_args()

    if not HAS_REQUESTS:
        print("Error: 'requests' library required", file=sys.stderr)
        sys.exit(1)

    api_key = args.api_key

    if args.command == "scan":
        urls = []
        if args.url:
            urls.append(args.url)
        elif args.url_file:
            with open(args.url_file) as f:
                urls = [line.strip() for line in f if line.strip()]

        for url in urls:
            print(f"Scanning: {url}")
            scan_result = submit_scan(url, args.visibility, api_key)

            if "error" in scan_result:
                print(f"  Error: {scan_result['error']}", file=sys.stderr)
                continue

            uuid = scan_result.get("uuid", "")
            print(f"  UUID: {uuid}")
            print(f"  Result URL: https://urlscan.io/result/{uuid}/")

            if args.wait and uuid:
                print("  Waiting for results...")
                time.sleep(10)
                raw = get_result(uuid, api_key)
                if "error" not in raw:
                    result = parse_result(raw)
                    if args.json:
                        print(json.dumps(asdict(result), indent=2, default=str))
                    else:
                        print(format_report(result))

            if len(urls) > 1:
                time.sleep(2)  # Rate limiting

    elif args.command == "result":
        raw = get_result(args.uuid, api_key)
        if "error" in raw:
            print(f"Error: {raw['error']}", file=sys.stderr)
            sys.exit(1)
        result = parse_result(raw)
        if args.json:
            print(json.dumps(asdict(result), indent=2, default=str))
        else:
            print(format_report(result))

    elif args.command == "search":
        results = search_scans(args.query, api_key, args.size)
        for r in results:
            task = r.get("task", {})
            page = r.get("page", {})
            print(f"  {task.get('time', '')} | {task.get('url', '')} | "
                  f"{page.get('domain', '')} | {page.get('ip', '')}")

    elif args.command == "ioc":
        raw = get_result(args.uuid, api_key)
        if "error" in raw:
            print(f"Error: {raw['error']}", file=sys.stderr)
            sys.exit(1)
        result = parse_result(raw)
        iocs = extract_iocs(result)
        print(json.dumps(iocs, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
