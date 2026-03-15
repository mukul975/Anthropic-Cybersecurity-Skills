#!/usr/bin/env python3
"""BGP RPKI validation agent using RIPEstat and Cloudflare RPKI APIs."""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional

try:
    import requests
except ImportError:
    sys.exit("requests required: pip install requests")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

RIPESTAT_BASE = "https://stat.ripe.net/data"
CLOUDFLARE_RPKI = "https://rpki.cloudflare.com/api/v1"


def validate_prefix_rpki(prefix: str) -> dict:
    """Validate a prefix against RPKI using RIPEstat."""
    resp = requests.get(f"{RIPESTAT_BASE}/rpki-validation/data.json",
                        params={"resource": prefix}, timeout=15)
    if resp.status_code == 200:
        data = resp.json().get("data", {})
        return {
            "prefix": prefix,
            "status": data.get("status", "unknown"),
            "validating_roas": data.get("validating_roas", []),
        }
    return {"prefix": prefix, "status": "error"}


def get_roas_for_asn(asn: str) -> List[dict]:
    """Get Route Origin Authorizations for an ASN from Cloudflare RPKI."""
    resp = requests.get(f"{CLOUDFLARE_RPKI}/roas", params={"asn": asn}, timeout=15)
    if resp.status_code == 200:
        return resp.json().get("roas", [])
    return []


def get_prefix_overview(prefix: str) -> dict:
    """Get prefix routing overview from RIPEstat."""
    resp = requests.get(f"{RIPESTAT_BASE}/prefix-overview/data.json",
                        params={"resource": prefix}, timeout=15)
    if resp.status_code == 200:
        return resp.json().get("data", {})
    return {}


def check_rpki_adoption(asn: str) -> dict:
    """Check RPKI adoption status for an ASN."""
    roas = get_roas_for_asn(asn)
    resp = requests.get(f"{RIPESTAT_BASE}/announced-prefixes/data.json",
                        params={"resource": asn}, timeout=15)
    announced = []
    if resp.status_code == 200:
        announced = resp.json().get("data", {}).get("prefixes", [])
    roa_prefixes = {r.get("prefix") for r in roas}
    announced_prefixes = {p.get("prefix") for p in announced}
    covered = announced_prefixes & roa_prefixes
    coverage_pct = (len(covered) / len(announced_prefixes) * 100) if announced_prefixes else 0
    return {
        "asn": asn,
        "announced_prefixes": len(announced_prefixes),
        "roa_covered": len(covered),
        "uncovered": len(announced_prefixes - roa_prefixes),
        "coverage_pct": round(coverage_pct, 1),
        "roa_count": len(roas),
    }


def validate_multiple_prefixes(prefixes: List[str]) -> List[dict]:
    """Validate multiple prefixes against RPKI."""
    results = []
    for prefix in prefixes:
        result = validate_prefix_rpki(prefix)
        results.append(result)
        logger.info("RPKI %s: %s", prefix, result.get("status", "unknown"))
    return results


def generate_report(asn: str, prefixes: List[str]) -> dict:
    """Generate RPKI validation report for an ASN and its prefixes."""
    report = {"analysis_date": datetime.utcnow().isoformat(), "asn": asn}
    report["adoption"] = check_rpki_adoption(asn)
    report["prefix_validation"] = validate_multiple_prefixes(prefixes)
    invalid = [p for p in report["prefix_validation"] if p.get("status") == "invalid"]
    report["invalid_prefixes"] = invalid
    report["recommendations"] = []
    if report["adoption"]["coverage_pct"] < 100:
        report["recommendations"].append(
            f"Create ROAs for {report['adoption']['uncovered']} uncovered prefixes")
    if invalid:
        report["recommendations"].append(f"Investigate {len(invalid)} RPKI-invalid prefixes")
    return report


def main():
    parser = argparse.ArgumentParser(description="BGP RPKI Validation Agent")
    parser.add_argument("--asn", required=True, help="AS number (e.g., AS13335)")
    parser.add_argument("--prefixes", nargs="*", default=[], help="Prefixes to validate")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--output", default="rpki_report.json")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    report = generate_report(args.asn, args.prefixes)
    out_path = os.path.join(args.output_dir, args.output)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", out_path)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
