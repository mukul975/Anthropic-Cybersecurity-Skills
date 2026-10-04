#!/usr/bin/env python3
"""Correlate an airodump-ng CSV against an authorized-AP baseline to flag rogue
and evil-twin access points.

Pure standard library. Reads the AP table from an airodump-ng CSV capture and a
baseline CSV of sanctioned APs (columns: BSSID,SSID,channel), then classifies
every observed BSSID.

Usage:
    python agent.py --scan rfscan-01.csv --baseline authorized_aps.csv
    python agent.py --scan rfscan-01.csv --baseline authorized_aps.csv --json
    python agent.py --selftest
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys


def load_baseline(path: str) -> dict[str, dict[str, str]]:
    """Return {BSSID(upper): row} from a baseline CSV with a BSSID column."""
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or "BSSID" not in reader.fieldnames:
            raise ValueError("baseline CSV needs a header with a 'BSSID' column")
        return {r["BSSID"].strip().upper(): {k: (v or "").strip() for k, v in r.items()}
                for r in reader if r.get("BSSID")}


def parse_airodump(text: str) -> list[dict[str, str]]:
    """Parse the AP table (before the 'Station MAC' section) of an airodump CSV."""
    rows, in_aps = [], False
    for line in io.StringIO(text):
        if line.startswith("BSSID"):
            in_aps = True
            continue
        if line.startswith("Station MAC"):
            break
        if in_aps and line.strip():
            f = [c.strip() for c in line.split(",")]
            if len(f) >= 14 and f[0]:
                rows.append({
                    "BSSID": f[0].upper(),
                    "channel": f[3],
                    "power": f[8],
                    "SSID": f[13],
                })
    return rows


def classify(scan: list[dict], baseline: dict[str, dict]) -> list[dict]:
    """Return a finding per observed BSSID with a severity classification."""
    authorized_bssids = set(baseline)
    authorized_ssids = {r.get("SSID", "") for r in baseline.values() if r.get("SSID")}
    findings = []
    for ap in scan:
        bssid, ssid = ap["BSSID"], ap["SSID"]
        if bssid in authorized_bssids:
            verdict, severity = "authorized", "info"
        elif ssid and ssid in authorized_ssids:
            verdict, severity = "evil-twin", "critical"
        else:
            verdict, severity = "unknown-ap", "medium"
        findings.append({**ap, "verdict": verdict, "severity": severity})
    return findings


def _selftest() -> int:
    baseline = {"AA:BB:CC:00:11:22": {"BSSID": "AA:BB:CC:00:11:22",
                                      "SSID": "CORP-WIFI", "channel": "6"}}
    sample = (
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, "
        "Cipher, Authentication, Power, beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
        "AA:BB:CC:00:11:22, t, t, 6, 130, WPA2, CCMP, PSK, -55, 100, 0, 0.0.0.0, 9, CORP-WIFI, \n"
        "DE:AD:BE:EF:12:34, t, t, 11, 130, WPA2, CCMP, PSK, -41, 80, 0, 0.0.0.0, 9, CORP-WIFI, \n"
        "A0:11:22:33:44:55, t, t, 1, 130, OPN, , , -70, 40, 0, 0.0.0.0, 7, linksys, \n"
        "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probes\n"
    )
    findings = classify(parse_airodump(sample), baseline)
    by_verdict = {f["BSSID"]: f["verdict"] for f in findings}
    assert by_verdict["AA:BB:CC:00:11:22"] == "authorized", by_verdict
    assert by_verdict["DE:AD:BE:EF:12:34"] == "evil-twin", by_verdict
    assert by_verdict["A0:11:22:33:44:55"] == "unknown-ap", by_verdict
    print("selftest OK: authorized / evil-twin / unknown-ap classified correctly")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scan", help="airodump-ng CSV capture")
    parser.add_argument("--baseline", help="authorized-AP CSV (BSSID,SSID,channel)")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--selftest", action="store_true", help="run built-in checks and exit")
    args = parser.parse_args()

    if args.selftest:
        return _selftest()
    if not (args.scan and args.baseline):
        parser.error("--scan and --baseline are required (or use --selftest)")

    baseline = load_baseline(args.baseline)
    with open(args.scan, encoding="utf-8", errors="ignore") as fh:
        findings = classify(parse_airodump(fh.read()), baseline)

    rogue = [f for f in findings if f["verdict"] != "authorized"]
    if args.as_json:
        print(json.dumps({"total_observed": len(findings),
                          "rogue_candidates": rogue}, indent=2))
    else:
        print(f"Observed {len(findings)} AP(s); {len(rogue)} rogue candidate(s):")
        for f in sorted(rogue, key=lambda r: r["severity"]):
            print(f"  [{f['severity'].upper():8}] {f['verdict']:11} "
                  f"{f['BSSID']}  ch{f['channel']:>3}  {f['power']:>4}dBm  {f['SSID']!r}")
    return 1 if rogue else 0


if __name__ == "__main__":
    sys.exit(main())
