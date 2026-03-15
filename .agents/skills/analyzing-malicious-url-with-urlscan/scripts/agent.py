#!/usr/bin/env python3
"""URLScan.io Malicious URL Analysis Agent - Submits and analyzes URLs via the urlscan.io API."""

import json
import time
import logging
import argparse
from datetime import datetime

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

URLSCAN_API = "https://urlscan.io/api/v1"


def submit_url(url, api_key, visibility="private"):
    """Submit a URL to urlscan.io for scanning."""
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    payload = {"url": url, "visibility": visibility}
    resp = requests.post(f"{URLSCAN_API}/scan/", headers=headers, json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    logger.info("Submitted URL: %s -> scan UUID: %s", url, data.get("uuid"))
    return data


def get_scan_result(uuid, api_key, max_wait=120):
    """Poll for scan results until complete."""
    headers = {"API-Key": api_key}
    for _ in range(max_wait // 5):
        try:
            resp = requests.get(f"{URLSCAN_API}/result/{uuid}/", headers=headers, timeout=30)
            if resp.status_code == 200:
                return resp.json()
        except requests.RequestException:
            pass
        time.sleep(5)
    return None


def search_urlscan(query, api_key, size=100):
    """Search urlscan.io for existing scans."""
    headers = {"API-Key": api_key}
    params = {"q": query, "size": size}
    resp = requests.get(f"{URLSCAN_API}/search/", headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json().get("results", [])


def analyze_result(result):
    """Analyze urlscan.io scan result for malicious indicators."""
    findings = []
    verdicts = result.get("verdicts", {})
    overall = verdicts.get("overall", {})
    urlscan_verdict = verdicts.get("urlscan", {})
    community = verdicts.get("community", {})

    if overall.get("malicious"):
        findings.append({"type": "Malicious verdict", "severity": "critical", "source": "overall", "score": overall.get("score", 0)})
    if urlscan_verdict.get("malicious"):
        findings.append({"type": "URLScan malicious", "severity": "critical", "score": urlscan_verdict.get("score", 0)})
    if community.get("score", 0) < 0:
        findings.append({"type": "Negative community score", "severity": "high", "score": community.get("score")})

    page = result.get("page", {})
    lists = result.get("lists", {})
    stats = result.get("stats", {})

    if lists.get("ips", []):
        for ip in lists["ips"]:
            if ip.get("malicious"):
                findings.append({"type": "Malicious IP contacted", "severity": "high", "ip": ip.get("ip"), "asn": ip.get("asn")})

    for cert in lists.get("certificates", []):
        if cert.get("validTo"):
            try:
                exp = datetime.fromisoformat(cert["validTo"].replace("Z", "+00:00"))
                if exp < datetime.now(exp.tzinfo):
                    findings.append({"type": "Expired TLS certificate", "severity": "medium", "subject": cert.get("subjectName")})
            except (ValueError, TypeError):
                pass

    js_count = len([r for r in stats.get("resourceStats", []) if "javascript" in r.get("type", "").lower()])
    if js_count > 20:
        findings.append({"type": "High JavaScript resource count", "severity": "medium", "count": js_count})

    redirects = stats.get("uniqCountries", 0)
    if result.get("data", {}).get("requests"):
        redirect_chain = [r.get("request", {}).get("redirectHasExtraInfo") for r in result["data"]["requests"][:5]]

    return {
        "url": page.get("url", ""),
        "domain": page.get("domain", ""),
        "ip": page.get("ip", ""),
        "country": page.get("country", ""),
        "server": page.get("server", ""),
        "status_code": page.get("status", 0),
        "title": page.get("title", ""),
        "mime_type": page.get("mimeType", ""),
        "tls_issuer": page.get("tlsIssuer", ""),
        "overall_malicious": overall.get("malicious", False),
        "overall_score": overall.get("score", 0),
        "findings": findings,
    }


def bulk_analyze(urls, api_key):
    """Submit and analyze multiple URLs."""
    results = []
    for url in urls:
        try:
            submission = submit_url(url, api_key)
            uuid = submission.get("uuid")
            if uuid:
                result = get_scan_result(uuid, api_key)
                if result:
                    analysis = analyze_result(result)
                    results.append(analysis)
                else:
                    results.append({"url": url, "error": "Scan timeout"})
        except requests.RequestException as e:
            results.append({"url": url, "error": str(e)})
    return results


def generate_report(analyses):
    """Generate URL analysis report."""
    malicious = [a for a in analyses if a.get("overall_malicious")]
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "urls_analyzed": len(analyses),
        "malicious_count": len(malicious),
        "results": analyses,
    }
    print(f"URLSCAN REPORT: {len(analyses)} URLs analyzed, {len(malicious)} malicious")
    return report


def main():
    parser = argparse.ArgumentParser(description="URLScan.io Malicious URL Analysis Agent")
    parser.add_argument("--api-key", required=True, help="urlscan.io API key")
    parser.add_argument("--url", help="Single URL to scan")
    parser.add_argument("--url-file", help="File with URLs (one per line)")
    parser.add_argument("--search", help="Search query for existing scans")
    parser.add_argument("--output", default="urlscan_report.json")
    args = parser.parse_args()

    urls = []
    if args.url:
        urls.append(args.url)
    if args.url_file:
        with open(args.url_file) as f:
            urls.extend(line.strip() for line in f if line.strip())

    if args.search:
        results = search_urlscan(args.search, args.api_key)
        analyses = [analyze_result(r) for r in results if "page" in r]
    else:
        analyses = bulk_analyze(urls, args.api_key)

    report = generate_report(analyses)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
