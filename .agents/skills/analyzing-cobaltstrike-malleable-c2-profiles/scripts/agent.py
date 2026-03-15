#!/usr/bin/env python3
"""CobaltStrike Malleable C2 Profile Analyzer - parses profiles to extract C2 indicators, detection signatures, and evasion techniques"""
# For authorized security research and defensive analysis only

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    from dissect.cobaltstrike.c2profile import C2Profile
    HAS_DISSECT = True
except ImportError:
    HAS_DISSECT = False

RUN_KEY_SUSPICIOUS = ["powershell", "cmd.exe", "mshta", "rundll32", "regsvr32", "wscript", "cscript"]

KNOWN_SPOOF_TARGETS = {
    "amazon": "Amazon CDN impersonation",
    "google": "Google services impersonation",
    "microsoft": "Microsoft services impersonation",
    "slack": "Slack API impersonation",
    "cloudfront": "CloudFront CDN impersonation",
    "jquery": "jQuery CDN impersonation",
    "outlook": "Outlook Web impersonation",
    "onedrive": "OneDrive impersonation",
}


def load_data(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def parse_profile_with_dissect(profile_path):
    """Parse a .profile file using dissect.cobaltstrike C2Profile."""
    if not HAS_DISSECT:
        return None
    profile = C2Profile.from_path(profile_path)
    return profile.as_dict()


def parse_profile_regex(content):
    """Regex-based parser for malleable C2 profile when dissect is unavailable."""
    config = {}
    set_pattern = re.compile(r'set\s+(\w+)\s+"([^"]*)"', re.MULTILINE)
    for match in set_pattern.finditer(content):
        config[match.group(1)] = match.group(2)
    block_pattern = re.compile(r'(http-get|http-post|http-stager|https-certificate|dns-beacon|process-inject|post-ex)\s*\{', re.MULTILINE)
    for match in block_pattern.finditer(content):
        config.setdefault("blocks", []).append(match.group(1))
    uri_pattern = re.compile(r'set\s+uri\s+"([^"]*)"', re.MULTILINE)
    for match in uri_pattern.finditer(content):
        config.setdefault("uris", []).append(match.group(1))
    header_pattern = re.compile(r'header\s+"([^"]+)"\s+"([^"]*)"', re.MULTILINE)
    for match in header_pattern.finditer(content):
        config.setdefault("headers", []).append({"name": match.group(1), "value": match.group(2)})
    spawn_pattern = re.compile(r'set\s+spawnto_x(?:86|64)\s+"([^"]*)"', re.MULTILINE)
    for match in spawn_pattern.finditer(content):
        config.setdefault("spawn_to", []).append(match.group(1))
    return config


def analyze_profile(config):
    """Analyze parsed profile configuration for detection opportunities."""
    findings = []
    ua = config.get("useragent", config.get("user_agent", ""))
    if ua:
        findings.append({
            "type": "user_agent_identified",
            "severity": "info",
            "resource": "http-config",
            "detail": f"User-Agent: {ua[:100]}",
            "indicator": ua,
        })
        for target, desc in KNOWN_SPOOF_TARGETS.items():
            if target.lower() in ua.lower():
                findings.append({
                    "type": "service_impersonation",
                    "severity": "medium",
                    "resource": "user-agent",
                    "detail": f"{desc} detected in User-Agent string",
                })
    sleeptime = config.get("sleeptime", config.get("sleep_time", ""))
    jitter = config.get("jitter", "")
    if sleeptime:
        try:
            sleep_ms = int(sleeptime)
            if sleep_ms < 1000:
                findings.append({
                    "type": "aggressive_beaconing",
                    "severity": "high",
                    "resource": "beacon-config",
                    "detail": f"Very low sleep time: {sleep_ms}ms - aggressive C2 callback rate",
                })
        except ValueError:
            pass
    uris = config.get("uris", [])
    for uri in uris:
        findings.append({
            "type": "c2_uri",
            "severity": "high",
            "resource": "http-config",
            "detail": f"C2 URI path: {uri}",
            "indicator": uri,
        })
    headers = config.get("headers", [])
    for h in headers:
        name = h.get("name", "") if isinstance(h, dict) else str(h)
        value = h.get("value", "") if isinstance(h, dict) else ""
        if name.lower() in ("host", "cookie", "authorization"):
            findings.append({
                "type": "c2_header",
                "severity": "medium",
                "resource": "http-config",
                "detail": f"Custom header: {name}: {value[:60]}",
            })
    spawn_to = config.get("spawn_to", config.get("spawnto_x86", []))
    if isinstance(spawn_to, str):
        spawn_to = [spawn_to]
    for proc in spawn_to:
        findings.append({
            "type": "spawn_to_process",
            "severity": "high",
            "resource": "process-inject",
            "detail": f"Beacon spawns to: {proc}",
            "indicator": proc,
        })
    pipename = config.get("pipename", config.get("pipename_stager", ""))
    if pipename:
        findings.append({
            "type": "named_pipe",
            "severity": "high",
            "resource": "process-inject",
            "detail": f"Named pipe: {pipename}",
            "indicator": pipename,
        })
    dns_idle = config.get("dns_idle", "")
    if dns_idle:
        findings.append({
            "type": "dns_beacon_config",
            "severity": "medium",
            "resource": "dns-beacon",
            "detail": f"DNS idle IP: {dns_idle}",
        })
    watermark = config.get("watermark", "")
    if watermark:
        findings.append({
            "type": "watermark",
            "severity": "info",
            "resource": "beacon-config",
            "detail": f"Beacon watermark: {watermark}",
        })
    return findings


def generate_suricata_rules(findings, sid_start=9000001):
    """Generate Suricata rules from extracted indicators."""
    rules = []
    sid = sid_start
    for f in findings:
        if f["type"] == "c2_uri" and f.get("indicator"):
            uri = f["indicator"].replace('"', '\\"')
            rules.append(
                f'alert http $HOME_NET any -> $EXTERNAL_NET any '
                f'(msg:"MALWARE CobaltStrike Malleable C2 URI {uri}"; '
                f'flow:established,to_server; '
                f'http.uri; content:"{uri}"; '
                f'sid:{sid}; rev:1;)'
            )
            sid += 1
        elif f["type"] == "named_pipe" and f.get("indicator"):
            pipe = f["indicator"]
            rules.append(
                f'# Named pipe detection requires endpoint monitoring: {pipe}'
            )
    return rules


def analyze(data):
    if isinstance(data, str):
        config = parse_profile_regex(data)
    elif isinstance(data, dict):
        config = data
    else:
        config = data[0] if isinstance(data, list) and data else {}
    return analyze_profile(config)


def generate_report(input_path):
    path = Path(input_path)
    if path.suffix in (".profile", ".txt"):
        content = path.read_text(encoding="utf-8")
        config = parse_profile_regex(content)
        findings = analyze_profile(config)
    else:
        data = load_data(input_path)
        if isinstance(data, list):
            findings = []
            for profile in data:
                findings.extend(analyze_profile(profile))
        else:
            findings = analyze_profile(data)
    sev = Counter(f["severity"] for f in findings)
    iocs = [f.get("indicator", "") for f in findings if f.get("indicator")]
    rules = generate_suricata_rules(findings)
    return {
        "report": "cobaltstrike_malleable_c2_analysis",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "severity_summary": dict(sev),
        "extracted_iocs": iocs,
        "suricata_rules": rules,
        "findings": findings,
    }


def main():
    ap = argparse.ArgumentParser(description="CobaltStrike Malleable C2 Profile Analyzer")
    ap.add_argument("--input", required=True, help="Input .profile file or JSON with parsed config")
    ap.add_argument("--output", help="Output JSON report path")
    args = ap.parse_args()
    report = generate_report(args.input)
    out = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(out)


if __name__ == "__main__":
    main()
