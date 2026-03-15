#!/usr/bin/env python3
"""ModSecurity WAF audit log analysis and rule tuning agent."""

import json
import sys
import argparse
import re
from datetime import datetime
from collections import defaultdict


SECTION_PATTERN = re.compile(r'^--([a-f0-9]+)-([A-Z])--$')

CRS_CATEGORIES = {
    "911": "Method Enforcement",
    "913": "Scanner Detection",
    "920": "Protocol Enforcement",
    "921": "Protocol Attack",
    "930": "Local File Inclusion",
    "931": "Remote File Inclusion",
    "932": "Remote Code Execution",
    "933": "PHP Injection",
    "934": "Node.js Injection",
    "941": "XSS Attack",
    "942": "SQL Injection",
    "943": "Session Fixation",
    "944": "Java Attack",
    "949": "Inbound Blocking",
    "959": "Outbound Blocking",
}


def parse_audit_log(log_path, max_entries=5000):
    """Parse ModSecurity serial audit log format."""
    entries = []
    current = {}
    current_section = None

    with open(log_path, "r", errors="replace") as f:
        for line in f:
            match = SECTION_PATTERN.match(line.strip())
            if match:
                tx_id = match.group(1)
                section = match.group(2)
                if section == "A":
                    if current and current.get("tx_id"):
                        entries.append(current)
                        if len(entries) >= max_entries:
                            break
                    current = {"tx_id": tx_id, "sections": {}}
                current_section = section
                current["sections"][section] = ""
            elif current_section and current_section in current.get("sections", {}):
                current["sections"][current_section] += line

    if current and current.get("tx_id"):
        entries.append(current)

    parsed = []
    for entry in entries:
        record = {"tx_id": entry["tx_id"]}
        section_a = entry["sections"].get("A", "")
        if section_a:
            parts = section_a.strip().split()
            if len(parts) >= 3:
                record["timestamp"] = parts[0] if parts else ""
                record["client_ip"] = parts[1] if len(parts) > 1 else ""

        section_b = entry["sections"].get("B", "")
        if section_b:
            first_line = section_b.strip().split("\n")[0]
            req_parts = first_line.split()
            if len(req_parts) >= 2:
                record["method"] = req_parts[0]
                record["uri"] = req_parts[1]

        section_h = entry["sections"].get("H", "")
        record["rules_matched"] = []
        for rule_match in re.finditer(
            r'\[id "(\d+)"\].*?\[msg "([^"]+)"\].*?\[severity "([^"]+)"\]',
            section_h
        ):
            record["rules_matched"].append({
                "rule_id": rule_match.group(1),
                "message": rule_match.group(2),
                "severity": rule_match.group(3),
            })

        anomaly = re.search(r'Inbound Anomaly Score.*?(\d+)', section_h)
        if anomaly:
            record["anomaly_score"] = int(anomaly.group(1))

        parsed.append(record)
    return parsed


def analyze_rule_frequency(entries):
    """Analyze which rules fire most frequently for tuning."""
    rule_counts = defaultdict(int)
    rule_msgs = {}
    for entry in entries:
        for rule in entry.get("rules_matched", []):
            rid = rule["rule_id"]
            rule_counts[rid] += 1
            rule_msgs[rid] = rule["message"]

    sorted_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)
    results = []
    for rid, count in sorted_rules:
        category = CRS_CATEGORIES.get(rid[:3], "Other")
        results.append({
            "rule_id": rid,
            "count": count,
            "message": rule_msgs.get(rid, ""),
            "category": category,
        })
    return results


def identify_false_positive_candidates(entries, threshold=50):
    """Identify rules that may be false positives based on frequency and pattern."""
    rule_ips = defaultdict(set)
    rule_uris = defaultdict(set)
    rule_counts = defaultdict(int)

    for entry in entries:
        for rule in entry.get("rules_matched", []):
            rid = rule["rule_id"]
            rule_counts[rid] += 1
            rule_ips[rid].add(entry.get("client_ip", ""))
            rule_uris[rid].add(entry.get("uri", ""))

    candidates = []
    for rid, count in rule_counts.items():
        if count >= threshold and len(rule_ips[rid]) > 10:
            candidates.append({
                "rule_id": rid,
                "hit_count": count,
                "unique_ips": len(rule_ips[rid]),
                "unique_uris": len(rule_uris[rid]),
                "recommendation": f"SecRuleRemoveById {rid}",
                "reason": "High frequency across many IPs — likely false positive",
            })
    return candidates


def generate_exclusion_rules(candidates):
    """Generate ModSecurity rule exclusion configuration."""
    lines = ["# Auto-generated false positive exclusions"]
    for c in candidates:
        lines.append(f"# Rule {c['rule_id']}: {c['hit_count']} hits, "
                     f"{c['unique_ips']} unique IPs")
        lines.append(f"SecRuleRemoveById {c['rule_id']}")
    return "\n".join(lines)


def analyze_attack_summary(entries):
    """Summarize detected attacks by category and severity."""
    category_counts = defaultdict(int)
    severity_counts = defaultdict(int)
    top_attackers = defaultdict(int)

    for entry in entries:
        for rule in entry.get("rules_matched", []):
            cat = CRS_CATEGORIES.get(rule["rule_id"][:3], "Other")
            category_counts[cat] += 1
            severity_counts[rule["severity"]] += 1
        if entry.get("anomaly_score", 0) >= 5:
            top_attackers[entry.get("client_ip", "")] += 1

    return {
        "by_category": dict(sorted(category_counts.items(), key=lambda x: x[1], reverse=True)),
        "by_severity": dict(severity_counts),
        "top_attackers": dict(sorted(top_attackers.items(), key=lambda x: x[1], reverse=True)[:20]),
    }


def run_audit(args):
    """Execute ModSecurity audit log analysis."""
    print(f"\n{'='*60}")
    print(f"  MODSECURITY AUDIT LOG ANALYSIS")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    report = {}

    entries = parse_audit_log(args.audit_log, args.max_entries)
    report["total_entries"] = len(entries)
    print(f"Parsed {len(entries)} audit log entries\n")

    attack_summary = analyze_attack_summary(entries)
    report["attack_summary"] = attack_summary
    print(f"--- ATTACK SUMMARY ---")
    for cat, count in list(attack_summary["by_category"].items())[:10]:
        print(f"  {cat}: {count}")
    print(f"\n  Severity: {attack_summary['by_severity']}")
    print(f"\n--- TOP ATTACKERS ---")
    for ip, count in list(attack_summary["top_attackers"].items())[:10]:
        print(f"  {ip}: {count} alerts")

    rule_freq = analyze_rule_frequency(entries)
    report["rule_frequency"] = rule_freq[:20]
    print(f"\n--- TOP FIRING RULES ---")
    for r in rule_freq[:15]:
        print(f"  [{r['rule_id']}] {r['count']}x — {r['message'][:60]}")

    if args.tune:
        fp_candidates = identify_false_positive_candidates(entries, args.fp_threshold)
        report["false_positive_candidates"] = fp_candidates
        print(f"\n--- FALSE POSITIVE CANDIDATES ({len(fp_candidates)}) ---")
        for c in fp_candidates[:10]:
            print(f"  Rule {c['rule_id']}: {c['hit_count']} hits, "
                  f"{c['unique_ips']} IPs — {c['reason']}")
        if fp_candidates:
            exclusions = generate_exclusion_rules(fp_candidates)
            report["exclusion_config"] = exclusions

    return report


def main():
    parser = argparse.ArgumentParser(description="ModSecurity Audit Log Agent")
    parser.add_argument("--audit-log", required=True,
                        help="Path to ModSecurity audit log file")
    parser.add_argument("--max-entries", type=int, default=5000,
                        help="Max log entries to parse (default: 5000)")
    parser.add_argument("--tune", action="store_true",
                        help="Identify false positive candidates for tuning")
    parser.add_argument("--fp-threshold", type=int, default=50,
                        help="Minimum hits for false positive candidate (default: 50)")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
