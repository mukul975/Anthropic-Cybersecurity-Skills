#!/usr/bin/env python3
"""Web Server Log Intrusion Analyzer - Detects SQLi, LFI, XSS, and scanner activity in access logs."""

import re
import json
import logging
import argparse
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

COMBINED_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<uri>\S+) (?P<proto>[^"]*)" '
    r'(?P<status>\d+) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

SQLI_PATTERNS = [
    (r"(?i)(union\s+(all\s+)?select)", "UNION SELECT injection"),
    (r"(?i)(or\s+1\s*=\s*1)", "OR 1=1 tautology"),
    (r"(?i)('\s*or\s*')", "String-based OR injection"),
    (r"(?i)(;\s*drop\s+table)", "DROP TABLE injection"),
    (r"(?i)(sleep\s*\(\d+\))", "Time-based blind SQLi (SLEEP)"),
    (r"(?i)(benchmark\s*\(\d+)", "Time-based blind SQLi (BENCHMARK)"),
    (r"(?i)(0x[0-9a-f]{8,})", "Hex-encoded payload"),
    (r"(?i)(concat\s*\(|group_concat)", "Data extraction function"),
    (r"(?i)(information_schema)", "Schema enumeration"),
    (r"(?i)(load_file\s*\(|into\s+outfile)", "File read/write via SQL"),
]

LFI_PATTERNS = [
    (r"(\.\./){2,}", "Directory traversal"),
    (r"(?i)(/etc/passwd|/etc/shadow)", "Linux password file access"),
    (r"(?i)(/proc/self|/proc/version)", "Proc filesystem access"),
    (r"(?i)(php://filter|php://input|data://)", "PHP stream wrapper"),
    (r"(?i)(c:\\windows|c:/windows)", "Windows path traversal"),
    (r"(%00|%2500)", "Null byte injection"),
]

XSS_PATTERNS = [
    (r"(?i)(<script[^>]*>)", "Script tag injection"),
    (r"(?i)(javascript\s*:)", "JavaScript URI"),
    (r"(?i)(onerror\s*=|onload\s*=|onmouseover\s*=)", "Event handler injection"),
    (r"(?i)(alert\s*\(|prompt\s*\(|confirm\s*\()", "JS dialog function"),
]

SCANNER_UA_PATTERNS = [
    (r"(?i)nikto", "Nikto scanner"),
    (r"(?i)sqlmap", "sqlmap injection tool"),
    (r"(?i)dirbuster", "DirBuster directory scanner"),
    (r"(?i)gobuster", "Gobuster directory scanner"),
    (r"(?i)wfuzz", "Wfuzz web fuzzer"),
    (r"(?i)nmap", "Nmap scripting engine"),
    (r"(?i)masscan", "Masscan port scanner"),
    (r"(?i)zgrab", "ZGrab scanner"),
    (r"(?i)(python-requests|python-urllib|go-http-client)", "Scripted HTTP client"),
]


def parse_log_line(line):
    """Parse a single Combined Log Format line."""
    match = COMBINED_LOG_PATTERN.match(line.strip())
    if not match:
        return None
    d = match.groupdict()
    d["size"] = int(d["size"]) if d["size"] != "-" else 0
    d["status"] = int(d["status"])
    return d


def parse_log_file(log_path):
    """Parse all entries from a web server access log."""
    entries = []
    with open(log_path, "r", errors="ignore") as f:
        for line in f:
            entry = parse_log_line(line)
            if entry:
                entries.append(entry)
    logger.info("Parsed %d log entries from %s", len(entries), log_path)
    return entries


def detect_attacks(entries):
    """Scan log entries for attack signatures."""
    findings = []
    for entry in entries:
        uri = entry["uri"]
        ua = entry["ua"]
        entry_findings = []
        for pattern, desc in SQLI_PATTERNS:
            if re.search(pattern, uri):
                entry_findings.append({"type": "SQLi", "pattern": desc, "severity": "critical"})
        for pattern, desc in LFI_PATTERNS:
            if re.search(pattern, uri):
                entry_findings.append({"type": "LFI", "pattern": desc, "severity": "high"})
        for pattern, desc in XSS_PATTERNS:
            if re.search(pattern, uri):
                entry_findings.append({"type": "XSS", "pattern": desc, "severity": "high"})
        for pattern, desc in SCANNER_UA_PATTERNS:
            if re.search(pattern, ua):
                entry_findings.append({"type": "Scanner", "pattern": desc, "severity": "medium"})
        if entry_findings:
            findings.append({
                "ip": entry["ip"],
                "timestamp": entry["time"],
                "method": entry["method"],
                "uri": entry["uri"][:200],
                "status": entry["status"],
                "user_agent": entry["ua"][:150],
                "attacks": entry_findings,
            })
    logger.info("Detected %d suspicious requests", len(findings))
    return findings


def detect_brute_force(entries, threshold=50, endpoint_patterns=None):
    """Detect brute-force login attempts by IP frequency."""
    if endpoint_patterns is None:
        endpoint_patterns = ["/login", "/wp-login", "/admin/login", "/api/auth", "/signin"]
    ip_post_counts = defaultdict(int)
    for entry in entries:
        if entry["method"] == "POST":
            if any(ep in entry["uri"].lower() for ep in endpoint_patterns):
                ip_post_counts[entry["ip"]] += 1
    brute_force = []
    for ip, count in ip_post_counts.items():
        if count >= threshold:
            brute_force.append({"ip": ip, "post_count": count, "severity": "high"})
            logger.warning("Brute force: %s sent %d POST requests to login endpoints", ip, count)
    return brute_force


def enrich_with_geoip(findings, geoip_db_path):
    """Enrich findings with GeoIP location data."""
    try:
        import geoip2.database
        reader = geoip2.database.Reader(geoip_db_path)
        for finding in findings:
            try:
                response = reader.city(finding["ip"])
                finding["geo"] = {
                    "country": response.country.name,
                    "city": response.city.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                }
            except Exception:
                finding["geo"] = None
        reader.close()
    except ImportError:
        logger.warning("geoip2 not installed, skipping GeoIP enrichment")
    return findings


def summarize_attackers(findings):
    """Aggregate findings by source IP for attacker profiling."""
    ip_summary = defaultdict(lambda: {"attacks": defaultdict(int), "total": 0, "uris": set()})
    for f in findings:
        ip = f["ip"]
        ip_summary[ip]["total"] += 1
        ip_summary[ip]["uris"].add(f["uri"][:100])
        for attack in f["attacks"]:
            ip_summary[ip]["attacks"][attack["type"]] += 1
    result = []
    for ip, data in sorted(ip_summary.items(), key=lambda x: x[1]["total"], reverse=True):
        result.append({
            "ip": ip,
            "total_hits": data["total"],
            "attack_types": dict(data["attacks"]),
            "unique_uris": len(data["uris"]),
        })
    return result[:50]


def generate_report(entries, findings, brute_force, attacker_summary):
    """Generate web intrusion detection report."""
    attack_counts = defaultdict(int)
    for f in findings:
        for a in f["attacks"]:
            attack_counts[a["type"]] += 1
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_log_entries": len(entries),
        "suspicious_requests": len(findings),
        "brute_force_sources": len(brute_force),
        "attack_breakdown": dict(attack_counts),
        "top_attackers": attacker_summary[:20],
        "brute_force_details": brute_force,
        "sample_findings": findings[:30],
    }
    print(f"WEB LOG ANALYSIS: {len(findings)} suspicious, {len(brute_force)} brute force sources")
    return report


def main():
    parser = argparse.ArgumentParser(description="Web Server Log Intrusion Analyzer")
    parser.add_argument("--log-file", required=True, help="Path to access log file")
    parser.add_argument("--geoip-db", help="Path to GeoLite2-City.mmdb")
    parser.add_argument("--brute-threshold", type=int, default=50)
    parser.add_argument("--output", default="web_intrusion_report.json")
    args = parser.parse_args()

    entries = parse_log_file(args.log_file)
    findings = detect_attacks(entries)
    brute_force = detect_brute_force(entries, args.brute_threshold)
    if args.geoip_db:
        findings = enrich_with_geoip(findings, args.geoip_db)
    attacker_summary = summarize_attackers(findings)
    report = generate_report(entries, findings, brute_force, attacker_summary)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
