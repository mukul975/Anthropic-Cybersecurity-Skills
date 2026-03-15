#!/usr/bin/env python3
"""Agent for performing malware hash enrichment using VirusTotal API v3."""

import json
import argparse
import hashlib
import time
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None

VT_API_URL = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    def __init__(self, api_key):
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key, "Accept": "application/json"})

    def get_file_report(self, file_hash):
        """Get file analysis report by hash (MD5, SHA1, or SHA256)."""
        resp = self.session.get(f"{VT_API_URL}/files/{file_hash}", timeout=30)
        if resp.status_code == 404:
            return {"hash": file_hash, "found": False}
        resp.raise_for_status()
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "hash": file_hash,
            "found": True,
            "sha256": attrs.get("sha256"),
            "md5": attrs.get("md5"),
            "sha1": attrs.get("sha1"),
            "file_type": attrs.get("type_description"),
            "size": attrs.get("size"),
            "meaningful_name": attrs.get("meaningful_name"),
            "detection_ratio": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "first_seen": attrs.get("first_submission_date"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "tags": attrs.get("tags", []),
            "popular_threat_classification": attrs.get("popular_threat_classification", {}),
        }

    def get_file_behavior(self, file_hash):
        """Get sandbox behavior report for a file."""
        resp = self.session.get(f"{VT_API_URL}/files/{file_hash}/behaviours", timeout=30)
        resp.raise_for_status()
        data = resp.json().get("data", [])
        behaviors = []
        for b in data[:5]:
            attrs = b.get("attributes", {})
            behaviors.append({
                "sandbox": attrs.get("sandbox_name"),
                "processes_created": attrs.get("processes_created", [])[:10],
                "files_written": attrs.get("files_written", [])[:10],
                "registry_keys_set": attrs.get("registry_keys_set", [])[:10],
                "dns_lookups": attrs.get("dns_lookups", [])[:10],
                "http_conversations": attrs.get("http_conversations", [])[:10],
            })
        return {"hash": file_hash, "behaviors": behaviors}


def enrich_hash_list(api_key, hashes, rate_limit=4):
    """Enrich a list of hashes with VirusTotal reports (respects rate limit)."""
    client = VirusTotalClient(api_key)
    results = []
    for i, h in enumerate(hashes):
        h = h.strip()
        if not h:
            continue
        try:
            report = client.get_file_report(h)
            results.append(report)
        except Exception as e:
            results.append({"hash": h, "error": str(e)})
        if (i + 1) % rate_limit == 0:
            time.sleep(60)  # VT free tier: 4 requests/minute
    malicious = [r for r in results if r.get("malicious", 0) > 0]
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "total_hashes": len(results),
        "found": sum(1 for r in results if r.get("found")),
        "malicious": len(malicious),
        "results": results,
    }


def hash_file(filepath):
    """Calculate MD5, SHA1, SHA256 of a local file."""
    algos = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            for a in algos.values():
                a.update(chunk)
    return {name: a.hexdigest() for name, a in algos.items()}


def main():
    if not requests:
        print(json.dumps({"error": "requests not installed"}))
        return
    parser = argparse.ArgumentParser(description="VirusTotal Hash Enrichment Agent")
    parser.add_argument("--api-key", required=True, help="VirusTotal API key")
    sub = parser.add_subparsers(dest="command")
    l = sub.add_parser("lookup", help="Look up single hash")
    l.add_argument("--hash", required=True)
    b = sub.add_parser("bulk", help="Enrich list of hashes")
    b.add_argument("--hashes", nargs="+", required=True)
    b.add_argument("--rate-limit", type=int, default=4)
    bh = sub.add_parser("behavior", help="Get sandbox behavior")
    bh.add_argument("--hash", required=True)
    hf = sub.add_parser("hash-file", help="Hash a local file")
    hf.add_argument("--file", required=True)
    args = parser.parse_args()
    client = VirusTotalClient(args.api_key) if hasattr(args, "api_key") else None
    if args.command == "lookup":
        result = client.get_file_report(args.hash)
    elif args.command == "bulk":
        result = enrich_hash_list(args.api_key, args.hashes, args.rate_limit)
    elif args.command == "behavior":
        result = client.get_file_behavior(args.hash)
    elif args.command == "hash-file":
        result = hash_file(args.file)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
