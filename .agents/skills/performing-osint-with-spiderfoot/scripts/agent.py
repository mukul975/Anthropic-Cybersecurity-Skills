#!/usr/bin/env python3
"""OSINT automation agent using SpiderFoot REST API for target profiling and reconnaissance."""

import os
import json
import time
import argparse
from datetime import datetime

import requests


def get_sf_session(base_url):
    """Create a requests session for SpiderFoot API."""
    session = requests.Session()
    session.headers.update({"Accept": "application/json"})
    session.base_url = base_url.rstrip("/")
    return session


def list_modules(session):
    """List available SpiderFoot modules."""
    resp = session.get(f"{session.base_url}/api/modules")
    resp.raise_for_status()
    modules = resp.json()
    return [{"name": m.get("name", ""), "descr": m.get("descr", ""),
             "group": m.get("group", ""), "provides": m.get("provides", [])}
            for m in modules]


def list_scan_types(session):
    """List available scan types (use cases)."""
    resp = session.get(f"{session.base_url}/api/scantypes")
    resp.raise_for_status()
    return resp.json()


def start_scan(session, target, scan_name, use_case="all"):
    """Start a new SpiderFoot scan via REST API."""
    data = {
        "scanname": scan_name,
        "scantarget": target,
        "usecase": use_case,
    }
    resp = session.post(f"{session.base_url}/api/startscan", data=data)
    resp.raise_for_status()
    result = resp.json()
    scan_id = result.get("scanid", result.get("id", ""))
    print(f"[+] Scan started: {scan_id} (target: {target}, use_case: {use_case})")
    return scan_id


def get_scan_status(session, scan_id):
    """Check scan status."""
    resp = session.get(f"{session.base_url}/api/scanstatus/{scan_id}")
    resp.raise_for_status()
    return resp.json()


def wait_for_scan(session, scan_id, poll_interval=10, timeout=600):
    """Poll scan status until completion or timeout."""
    elapsed = 0
    while elapsed < timeout:
        status = get_scan_status(session, scan_id)
        state = status.get("status", "")
        if state in ("FINISHED", "ABORTED", "ERROR-FAILED"):
            print(f"[+] Scan {scan_id} completed with status: {state}")
            return state
        print(f"[*] Scan status: {state} (elapsed: {elapsed}s)")
        time.sleep(poll_interval)
        elapsed += poll_interval
    print(f"[!] Scan timed out after {timeout}s")
    return "TIMEOUT"


def get_scan_results(session, scan_id):
    """Retrieve all results from a completed scan."""
    resp = session.get(f"{session.base_url}/api/scanresults/{scan_id}")
    resp.raise_for_status()
    return resp.json()


def categorize_results(results):
    """Categorize scan results by data element type."""
    categories = {
        "domains": [], "ips": [], "emails": [], "credentials": [],
        "dns_records": [], "urls": [], "hostnames": [], "other": [],
    }
    type_map = {
        "INTERNET_NAME": "domains", "IP_ADDRESS": "ips", "EMAILADDR": "emails",
        "LEAKSITE_CONTENT": "credentials", "DNS_TEXT": "dns_records",
        "LINKED_URL_INTERNAL": "urls", "LINKED_URL_EXTERNAL": "urls",
        "AFFILIATE_INTERNET_NAME": "hostnames", "CO_HOSTED_SITE": "hostnames",
    }
    for result in results:
        data_type = result.get("type", "")
        category = type_map.get(data_type, "other")
        entry = {
            "data": result.get("data", ""),
            "type": data_type,
            "module": result.get("module", ""),
            "source": result.get("source", ""),
        }
        categories[category].append(entry)
    return categories


def generate_target_profile(target, categories):
    """Generate structured OSINT profile from categorized results."""
    return {
        "target": target,
        "profile_time": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "domains_found": len(categories["domains"]),
            "ips_found": len(categories["ips"]),
            "emails_found": len(categories["emails"]),
            "credentials_found": len(categories["credentials"]),
            "dns_records": len(categories["dns_records"]),
            "urls_found": len(categories["urls"]),
            "hostnames_found": len(categories["hostnames"]),
            "other_findings": len(categories["other"]),
        },
        "domains": [d["data"] for d in categories["domains"][:50]],
        "ips": [d["data"] for d in categories["ips"][:50]],
        "emails": [d["data"] for d in categories["emails"][:50]],
        "leaked_credentials": len(categories["credentials"]),
        "dns_records": [d["data"] for d in categories["dns_records"][:20]],
        "data_sources": list({r["module"] for cat in categories.values() for r in cat}),
    }


def main():
    parser = argparse.ArgumentParser(description="SpiderFoot OSINT Agent")
    parser.add_argument("--target", required=True, help="Scan target (domain, IP, email, name)")
    parser.add_argument("--server", default=os.environ.get("SPIDERFOOT_URL", "http://127.0.0.1:5001"),
                        help="SpiderFoot server URL")
    parser.add_argument("--use-case", choices=["all", "footprint", "investigate", "passive"],
                        default="footprint", help="Scan use case")
    parser.add_argument("--scan-name", default="", help="Scan name (default: auto-generated)")
    parser.add_argument("--timeout", type=int, default=600, help="Scan timeout in seconds")
    parser.add_argument("--poll-interval", type=int, default=10, help="Status poll interval in seconds")
    parser.add_argument("--output", default="osint_report.json", help="Output report path")
    parser.add_argument("--list-modules", action="store_true", help="List available modules and exit")
    args = parser.parse_args()

    session = get_sf_session(args.server)

    if args.list_modules:
        modules = list_modules(session)
        for m in modules:
            print(f"  {m['name']}: {m['descr']}")
        print(f"\n[+] Total modules: {len(modules)}")
        return

    scan_name = args.scan_name or f"osint-{args.target}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    scan_id = start_scan(session, args.target, scan_name, args.use_case)
    final_status = wait_for_scan(session, scan_id, args.poll_interval, args.timeout)

    results = get_scan_results(session, scan_id)
    print(f"[+] Retrieved {len(results)} results from scan")

    categories = categorize_results(results)
    profile = generate_target_profile(args.target, categories)
    profile["scan_id"] = scan_id
    profile["scan_status"] = final_status
    profile["use_case"] = args.use_case

    with open(args.output, "w") as f:
        json.dump(profile, f, indent=2)
    print(f"[+] Domains: {profile['summary']['domains_found']}, IPs: {profile['summary']['ips_found']}, "
          f"Emails: {profile['summary']['emails_found']}")
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
