#!/usr/bin/env python3
"""Agent for analyzing Cobalt Strike malleable C2 profiles and JARM fingerprinting."""

import os
import json
import subprocess
import argparse
from pathlib import Path
from datetime import datetime

from malleablec2 import Profile


def extract_profile_indicators(profile_path):
    """Extract detection indicators from a malleable C2 profile."""
    with open(profile_path) as f:
        content = f.read()
    profile = Profile.from_string(content)
    indicators = {
        "file": str(profile_path),
        "source_lines": len(content.splitlines()),
        "reconstructed": str(profile),
    }
    keywords = ["sleeptime", "jitter", "useragent", "pipename", "host_stage",
                "dns_idle", "dns_sleep", "spawnto_x86", "spawnto_x64"]
    options = {}
    for kw in keywords:
        for line in content.splitlines():
            stripped = line.strip().rstrip(";").strip()
            if kw in stripped.lower() and "set " in stripped.lower():
                parts = stripped.split('"')
                if len(parts) >= 2:
                    options[kw] = parts[1]
    indicators["global_options"] = options
    uris = []
    for line in content.splitlines():
        if "set uri" in line.strip().lower():
            parts = line.strip().split('"')
            if len(parts) >= 2:
                uris.append(parts[1])
    indicators["uris"] = uris
    headers = []
    for line in content.splitlines():
        stripped = line.strip()
        if "header " in stripped.lower() and '"' in stripped:
            parts = stripped.split('"')
            if len(parts) >= 4:
                headers.append({"name": parts[1], "value": parts[3]})
    indicators["custom_headers"] = headers
    return indicators


def scan_directory_profiles(directory):
    """Scan a directory for malleable C2 profiles and extract indicators."""
    results = []
    for path in Path(directory).rglob("*.profile"):
        try:
            indicators = extract_profile_indicators(str(path))
            results.append(indicators)
        except Exception as e:
            results.append({"file": str(path), "error": str(e)})
    return results


KNOWN_CS_JARM = {
    "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1":
        "Cobalt Strike (default)",
    "07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2":
        "Cobalt Strike (Java 11)",
}


def compute_jarm_fingerprint(host, port=443):
    """Compute JARM fingerprint by invoking the salesforce/jarm scanner."""
    jarm_script = os.getenv("JARM_SCRIPT", "jarm.py")
    try:
        result = subprocess.run(
            ["python3", jarm_script, host, "-p", str(port)],
            capture_output=True, text=True, timeout=30,
        )
        for line in result.stdout.splitlines():
            if len(line.strip()) >= 62:
                return line.strip().split()[-1]
        return result.stdout.strip()
    except Exception as e:
        return f"Error: {e}"


def check_jarm_against_known(fingerprint):
    """Check a JARM fingerprint against known Cobalt Strike signatures."""
    for jarm_hash, description in KNOWN_CS_JARM.items():
        if fingerprint.strip() == jarm_hash:
            return {"match": True, "description": description, "fingerprint": fingerprint}
    return {"match": False, "fingerprint": fingerprint}


def batch_jarm_scan(targets, port=443):
    """Scan multiple targets for JARM fingerprints and check against known CS hashes."""
    results = []
    for target in targets:
        fp = compute_jarm_fingerprint(target, port)
        match = check_jarm_against_known(fp)
        match["target"] = target
        results.append(match)
    return results


def generate_snort_rules(indicators_list):
    """Generate Snort/Suricata rules from extracted profile indicators."""
    rules = []
    sid = 1000001
    for ind in indicators_list:
        for uri in ind.get("uris", []):
            rules.append(
                f'alert http $HOME_NET any -> $EXTERNAL_NET any '
                f'(msg:"CS Beacon URI {uri}"; '
                f'content:"{uri}"; http_uri; sid:{sid}; rev:1;)'
            )
            sid += 1
        ua = ind.get("global_options", {}).get("useragent", "")
        if ua:
            rules.append(
                f'alert http $HOME_NET any -> $EXTERNAL_NET any '
                f'(msg:"CS Beacon User-Agent"; '
                f'content:"{ua}"; http_header; sid:{sid}; rev:1;)'
            )
            sid += 1
    return rules


def main():
    parser = argparse.ArgumentParser(description="Cobalt Strike Malleable Profile Analyzer")
    parser.add_argument("--profile", help="Path to a single malleable C2 profile")
    parser.add_argument("--directory", help="Directory of malleable profiles")
    parser.add_argument("--jarm-targets", nargs="*", help="Hosts to JARM fingerprint")
    parser.add_argument("--output", default="cs_analysis_report.json")
    parser.add_argument("--action", choices=[
        "parse", "scan_dir", "jarm", "generate_rules", "full_analysis"
    ], default="full_analysis")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.action in ("parse", "full_analysis") and args.profile:
        indicators = extract_profile_indicators(args.profile)
        report["findings"]["profile_indicators"] = indicators
        print(f"[+] Parsed: {args.profile} ({len(indicators.get('uris', []))} URIs)")

    if args.action in ("scan_dir", "full_analysis") and args.directory:
        results = scan_directory_profiles(args.directory)
        report["findings"]["directory_scan"] = results
        print(f"[+] Scanned {len(results)} profiles in {args.directory}")

    if args.action in ("jarm", "full_analysis") and args.jarm_targets:
        jarm_results = batch_jarm_scan(args.jarm_targets)
        report["findings"]["jarm_scan"] = jarm_results
        matches = [r for r in jarm_results if r.get("match")]
        print(f"[+] JARM: {len(jarm_results)} scanned, {len(matches)} CS matches")

    if args.action in ("generate_rules", "full_analysis"):
        profiles = report["findings"].get("directory_scan", [])
        if not profiles and args.profile:
            profiles = [report["findings"].get("profile_indicators", {})]
        rules = generate_snort_rules(profiles)
        report["findings"]["snort_rules"] = rules
        print(f"[+] Generated {len(rules)} Snort rules")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
