#!/usr/bin/env python3
"""Certificate Transparency monitoring agent for phishing detection.

Queries crt.sh for certificates matching target domains, detects lookalike
certificates, and identifies potential phishing infrastructure.
"""

import json
import os
import sys
import re
from datetime import datetime
from collections import defaultdict

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def query_crtsh(domain, wildcard=True, expired=False):
    """Query crt.sh for certificates matching a domain."""
    if not HAS_REQUESTS:
        return []
    query = f"%.{domain}" if wildcard else domain
    params = {"q": query, "output": "json"}
    if not expired:
        params["exclude"] = "expired"
    try:
        resp = requests.get("https://crt.sh/", params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except (requests.RequestException, json.JSONDecodeError) as e:
        return [{"error": str(e)}]


def find_lookalike_domains(target_domain, ct_results):
    """Identify certificates for domains that look similar to the target."""
    base = target_domain.split(".")[0].lower()
    lookalikes = []
    for cert in ct_results:
        cn = cert.get("common_name", "").lower()
        names = cert.get("name_value", "").lower().split("\n")
        for name in [cn] + names:
            name = name.strip()
            if not name or name == target_domain:
                continue
            similarity = calculate_similarity(base, name.split(".")[0])
            if similarity > 0.6 and name != target_domain:
                lookalikes.append({
                    "domain": name,
                    "similarity": round(similarity, 3),
                    "issuer": cert.get("issuer_name", ""),
                    "not_before": cert.get("not_before", ""),
                    "not_after": cert.get("not_after", ""),
                    "cert_id": cert.get("id"),
                })
    seen = set()
    unique = []
    for l in sorted(lookalikes, key=lambda x: -x["similarity"]):
        if l["domain"] not in seen:
            seen.add(l["domain"])
            unique.append(l)
    return unique


def calculate_similarity(s1, s2):
    """Calculate string similarity using Levenshtein-like ratio."""
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0
    matrix = [[0] * (len2 + 1) for _ in range(len1 + 1)]
    for i in range(len1 + 1):
        matrix[i][0] = i
    for j in range(len2 + 1):
        matrix[0][j] = j
    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i-1] == s2[j-1] else 1
            matrix[i][j] = min(matrix[i-1][j] + 1, matrix[i][j-1] + 1,
                               matrix[i-1][j-1] + cost)
    distance = matrix[len1][len2]
    return 1.0 - distance / max(len1, len2)


HOMOGLYPH_MAP = {
    "a": ["а", "@", "4"], "e": ["е", "3"], "o": ["о", "0"],
    "i": ["і", "1", "l"], "l": ["1", "i", "I"],
    "s": ["5", "$"], "t": ["7"], "g": ["9", "q"],
}


def detect_homoglyph_domains(target_domain, ct_results):
    """Detect domains using homoglyph/IDN attacks against target."""
    findings = []
    base = target_domain.split(".")[0].lower()
    for cert in ct_results:
        names = cert.get("name_value", "").lower().split("\n")
        for name in names:
            name = name.strip()
            if not name or name == target_domain:
                continue
            name_base = name.split(".")[0]
            if len(name_base) == len(base):
                diffs = sum(1 for a, b in zip(base, name_base) if a != b)
                if 0 < diffs <= 2:
                    findings.append({
                        "domain": name,
                        "char_differences": diffs,
                        "cert_id": cert.get("id"),
                        "issuer": cert.get("issuer_name", ""),
                    })
    return findings


def analyze_issuer_patterns(ct_results):
    """Analyze certificate issuer patterns for anomalies."""
    issuer_counts = defaultdict(int)
    free_cas = ["Let's Encrypt", "ZeroSSL", "Buypass"]
    for cert in ct_results:
        issuer = cert.get("issuer_name", "Unknown")
        issuer_counts[issuer] += 1
    free_ca_certs = sum(
        count for issuer, count in issuer_counts.items()
        if any(ca.lower() in issuer.lower() for ca in free_cas)
    )
    return {
        "issuers": dict(issuer_counts),
        "total_certs": len(ct_results),
        "free_ca_count": free_ca_certs,
        "free_ca_ratio": round(free_ca_certs / max(len(ct_results), 1), 3),
    }


def detect_wildcard_abuse(ct_results):
    """Detect suspicious wildcard certificate patterns."""
    wildcards = []
    for cert in ct_results:
        cn = cert.get("common_name", "")
        if cn.startswith("*."):
            wildcards.append({
                "domain": cn,
                "issuer": cert.get("issuer_name", ""),
                "not_before": cert.get("not_before", ""),
            })
    return wildcards


def generate_report(target_domain, ct_results):
    """Generate comprehensive CT monitoring report."""
    lookalikes = find_lookalike_domains(target_domain, ct_results)
    homoglyphs = detect_homoglyph_domains(target_domain, ct_results)
    issuer_analysis = analyze_issuer_patterns(ct_results)
    wildcards = detect_wildcard_abuse(ct_results)

    risk_score = 0
    risk_score += min(len(lookalikes) * 10, 40)
    risk_score += min(len(homoglyphs) * 15, 30)
    risk_score += 20 if issuer_analysis["free_ca_ratio"] > 0.8 else 0
    risk_score = min(risk_score, 100)

    return {
        "target_domain": target_domain,
        "total_certificates": len(ct_results),
        "lookalike_domains": lookalikes[:20],
        "homoglyph_domains": homoglyphs[:20],
        "issuer_analysis": issuer_analysis,
        "wildcard_certs": wildcards[:10],
        "risk_score": risk_score,
        "risk_level": "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 30 else "LOW",
    }


if __name__ == "__main__":
    print("=" * 60)
    print("Certificate Transparency Phishing Detection Agent")
    print("crt.sh queries, lookalike detection, homoglyph analysis")
    print("=" * 60)

    domain = sys.argv[1] if len(sys.argv) > 1 else None

    if not domain:
        print("\n[DEMO] Usage: python agent.py <target_domain>")
        print("  e.g. python agent.py example.com")
        sys.exit(0)

    if not HAS_REQUESTS:
        print("[!] Install requests: pip install requests")
        sys.exit(1)

    print(f"\n[*] Querying crt.sh for: {domain}")
    results = query_crtsh(domain)
    print(f"[*] Found {len(results)} certificates")

    report = generate_report(domain, results)

    print(f"\n--- Lookalike Domains ({len(report['lookalike_domains'])}) ---")
    for l in report["lookalike_domains"][:10]:
        print(f"  [{l['similarity']:.3f}] {l['domain']} (issuer: {l['issuer'][:40]})")

    print(f"\n--- Homoglyph Domains ({len(report['homoglyph_domains'])}) ---")
    for h in report["homoglyph_domains"][:10]:
        print(f"  [diff={h['char_differences']}] {h['domain']}")

    print(f"\n--- Issuer Analysis ---")
    for issuer, count in sorted(report["issuer_analysis"]["issuers"].items(),
                                 key=lambda x: -x[1])[:5]:
        print(f"  {count:4d} | {issuer[:60]}")

    print(f"\n[*] Risk Score: {report['risk_score']}/100 ({report['risk_level']})")
