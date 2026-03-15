#!/usr/bin/env python3
"""EPSS Vulnerability Prioritization Tool.

Fetches EPSS scores from FIRST API and prioritizes vulnerabilities
using a combined EPSS + CVSS matrix approach.
"""

import argparse
import csv
import gzip
import io
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

EPSS_API = "https://api.first.org/data/v1/epss"
EPSS_BULK_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

PRIORITY_MAP = {
    "P0": {"label": "Immediate", "sla_hours": 24},
    "P1": {"label": "Urgent", "sla_hours": 48},
    "P2": {"label": "High", "sla_days": 7},
    "P3": {"label": "Medium", "sla_days": 30},
    "P4": {"label": "Low", "sla_days": 90},
}


def fetch_epss_bulk():
    """Download full EPSS dataset for local lookups."""
    print("[*] Downloading full EPSS dataset...")
    resp = requests.get(EPSS_BULK_URL, timeout=60)
    resp.raise_for_status()
    content = gzip.decompress(resp.content).decode("utf-8")
    reader = csv.DictReader(io.StringIO(content))
    scores = {}
    for row in reader:
        cve = row.get("cve", "").strip()
        if cve:
            scores[cve] = {
                "epss": float(row.get("epss", 0)),
                "percentile": float(row.get("percentile", 0)),
            }
    print(f"    Loaded EPSS scores for {len(scores)} CVEs")
    return scores


def fetch_epss_api(cve_list):
    """Fetch EPSS scores for specific CVEs via API."""
    scores = {}
    batch_size = 100
    for i in range(0, len(cve_list), batch_size):
        batch = cve_list[i : i + batch_size]
        try:
            resp = requests.get(
                EPSS_API, params={"cve": ",".join(batch)}, timeout=30
            )
            if resp.status_code == 200:
                for entry in resp.json().get("data", []):
                    scores[entry["cve"]] = {
                        "epss": float(entry.get("epss", 0)),
                        "percentile": float(entry.get("percentile", 0)),
                    }
        except requests.RequestException as e:
            print(f"[-] EPSS API error: {e}")
        time.sleep(0.5)
    return scores


def fetch_kev_catalog():
    """Download CISA KEV catalog."""
    resp = requests.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    return {v["cveID"] for v in resp.json().get("vulnerabilities", [])}


def assign_priority(epss_score, cvss_score, in_kev=False):
    """Assign priority based on EPSS + CVSS + KEV matrix."""
    if in_kev:
        if cvss_score >= 9.0:
            return "P0"
        return "P1"
    if epss_score > 0.7 and cvss_score >= 9.0:
        return "P0"
    if epss_score > 0.7 and cvss_score >= 7.0:
        return "P1"
    if epss_score > 0.4 and cvss_score >= 7.0:
        return "P2"
    if epss_score > 0.1 or cvss_score >= 7.0:
        return "P3"
    return "P4"


def prioritize_scan_results(input_csv, output_csv, use_bulk=False):
    """Enrich vulnerability scan results with EPSS and prioritize."""
    vulnerabilities = []
    with open(input_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            vulnerabilities.append(row)

    cve_list = list({v.get("cve_id", "") for v in vulnerabilities if v.get("cve_id")})
    print(f"[*] Processing {len(vulnerabilities)} findings ({len(cve_list)} unique CVEs)")

    if use_bulk:
        epss_scores = fetch_epss_bulk()
    else:
        epss_scores = fetch_epss_api(cve_list)

    print("[*] Fetching CISA KEV catalog...")
    kev_set = fetch_kev_catalog()
    print(f"    {len(kev_set)} CVEs in KEV catalog")

    results = []
    for vuln in vulnerabilities:
        cve_id = vuln.get("cve_id", "")
        cvss = float(vuln.get("cvss_score", 0))
        epss_data = epss_scores.get(cve_id, {"epss": 0, "percentile": 0})
        in_kev = cve_id in kev_set
        priority = assign_priority(epss_data["epss"], cvss, in_kev)

        results.append({
            **vuln,
            "epss_score": round(epss_data["epss"], 5),
            "epss_percentile": round(epss_data["percentile"], 5),
            "in_cisa_kev": in_kev,
            "priority": priority,
            "priority_label": PRIORITY_MAP[priority]["label"],
        })

    results.sort(key=lambda r: (
        {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}[r["priority"]],
        -r["epss_score"],
    ))

    if results:
        with open(output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)

    priority_counts = {}
    for r in results:
        p = r["priority"]
        priority_counts[p] = priority_counts.get(p, 0) + 1

    print(f"\n[+] Prioritization Results -> {output_csv}")
    for p in ["P0", "P1", "P2", "P3", "P4"]:
        count = priority_counts.get(p, 0)
        print(f"    {p} ({PRIORITY_MAP[p]['label']}): {count}")
    print(f"    KEV matches: {sum(1 for r in results if r['in_cisa_kev'])}")
    return results


def detect_epss_spikes(previous_csv, current_scores, threshold=0.2):
    """Compare EPSS scores to detect significant increases."""
    previous = {}
    with open(previous_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve = row.get("cve_id", "")
            if cve:
                previous[cve] = float(row.get("epss_score", 0))

    spikes = []
    for cve, prev_score in previous.items():
        current = current_scores.get(cve, {}).get("epss", 0)
        increase = current - prev_score
        if increase >= threshold:
            spikes.append({
                "cve_id": cve,
                "previous_epss": prev_score,
                "current_epss": current,
                "increase": round(increase, 5),
            })

    spikes.sort(key=lambda s: s["increase"], reverse=True)
    if spikes:
        print(f"\n[!] EPSS Spikes Detected ({len(spikes)} CVEs):")
        for s in spikes[:20]:
            print(f"    {s['cve_id']}: {s['previous_epss']:.4f} -> {s['current_epss']:.4f} (+{s['increase']:.4f})")
    return spikes


def main():
    parser = argparse.ArgumentParser(description="EPSS Vulnerability Prioritization Tool")
    parser.add_argument("--input", help="Input CSV with vulnerability scan results")
    parser.add_argument("--output", default="epss_prioritized.csv", help="Output prioritized CSV")
    parser.add_argument("--bulk", action="store_true", help="Use bulk EPSS download instead of API")
    parser.add_argument("--detect-spikes", help="Previous results CSV for spike detection")
    parser.add_argument("--spike-threshold", type=float, default=0.2, help="EPSS increase threshold")
    parser.add_argument("--query", help="Query EPSS for specific CVE(s), comma-separated")
    args = parser.parse_args()

    if args.query:
        cves = [c.strip() for c in args.query.split(",")]
        scores = fetch_epss_api(cves)
        for cve, data in scores.items():
            pct = data["epss"] * 100
            print(f"{cve}: {pct:.2f}% exploitation probability (percentile: {data['percentile']:.4f})")
    elif args.input:
        results = prioritize_scan_results(args.input, args.output, args.bulk)
        if args.detect_spikes:
            current_scores = {r["cve_id"]: {"epss": r["epss_score"]} for r in results if r.get("cve_id")}
            detect_epss_spikes(args.detect_spikes, current_scores, args.spike_threshold)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
