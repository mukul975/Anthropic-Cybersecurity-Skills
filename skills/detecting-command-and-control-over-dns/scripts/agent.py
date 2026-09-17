#!/usr/bin/env python3
"""
DNS C2 Detection Agent

Comprehensive detection pipeline for command-and-control communications over DNS.
Combines Shannon entropy analysis, DNS beaconing detection, DGA classification,
TXT record payload inspection, and known tool signature matching.

Usage:
    python agent.py --dns-log /path/to/dns.log --format zeek
    python agent.py --dns-log /path/to/eve.json --format suricata
    python agent.py --dns-log /path/to/queries.csv --format csv
    python agent.py --mode train-dga --legit-domains legit.txt --dga-domains dga.txt
    python agent.py --mode entropy --dns-log dns.log --format zeek

Requirements:
    pip install numpy scikit-learn tldextract
"""

import argparse
import base64
import csv
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

import numpy as np

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.preprocessing import StandardScaler
    import pickle
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")
HEX_CHARS = set("0123456789abcdef")
BASE32_CHARS = set("abcdefghijklmnopqrstuvwxyz234567")

# English bigram frequencies (top 40, from Peter Norvig's analysis)
ENGLISH_BIGRAMS = {
    "th": 0.0356, "he": 0.0307, "in": 0.0243, "er": 0.0205,
    "an": 0.0199, "re": 0.0185, "on": 0.0176, "at": 0.0149,
    "en": 0.0145, "nd": 0.0135, "ti": 0.0134, "es": 0.0134,
    "or": 0.0128, "te": 0.0120, "of": 0.0117, "ed": 0.0117,
    "is": 0.0113, "it": 0.0112, "al": 0.0109, "ar": 0.0107,
    "st": 0.0105, "to": 0.0104, "nt": 0.0104, "ng": 0.0095,
    "se": 0.0093, "ha": 0.0093, "as": 0.0087, "ou": 0.0087,
    "io": 0.0083, "le": 0.0083, "ve": 0.0083, "co": 0.0079,
    "me": 0.0079, "de": 0.0076, "hi": 0.0076, "ri": 0.0073,
    "ro": 0.0073, "ic": 0.0070, "ne": 0.0069, "ea": 0.0069,
}

# Known tunneling tool signatures
TOOL_SIGNATURES = {
    "iodine": {
        "pattern": re.compile(r"^[a-z0-9]{50,}\.", re.IGNORECASE),
        "qtypes": {"NULL", "TXT", "CNAME", "MX", "A"},
        "entropy_range": (3.8, 4.2),
        "description": "Iodine DNS tunnel - IPv4 over DNS",
    },
    "dnscat2": {
        "pattern": re.compile(r"^(dnscat\.)|^[a-f0-9]{16,}\.", re.IGNORECASE),
        "qtypes": {"TXT", "CNAME", "MX", "A"},
        "entropy_range": (3.5, 4.5),
        "description": "dnscat2 encrypted C2 channel",
    },
    "dns2tcp": {
        "pattern": re.compile(r"^[a-z2-7]{20,}\.", re.IGNORECASE),
        "qtypes": {"TXT", "KEY"},
        "entropy_range": (3.6, 4.0),
        "description": "dns2tcp TCP-over-DNS tunnel",
    },
    "cobalt_strike_dns": {
        "pattern": re.compile(r"^[a-f0-9]{8,20}\.", re.IGNORECASE),
        "qtypes": {"A", "AAAA", "TXT"},
        "entropy_range": (3.2, 4.0),
        "description": "Cobalt Strike DNS beacon",
    },
    "sliver_dns": {
        "pattern": re.compile(r"^[a-z0-9]{30,}\.", re.IGNORECASE),
        "qtypes": {"A", "TXT"},
        "entropy_range": (3.5, 4.2),
        "description": "Sliver C2 DNS implant",
    },
}

# Common legitimate high-entropy domains to whitelist
WHITELIST_PATTERNS = [
    re.compile(r".*\.in-addr\.arpa$"),
    re.compile(r".*\.ip6\.arpa$"),
    re.compile(r".*\._domainkey\..*"),
    re.compile(r".*\._dmarc\..*"),
    re.compile(r".*\._spf\..*"),
    re.compile(r".*\.akadns\.net$"),
    re.compile(r".*\.akamaiedge\.net$"),
    re.compile(r".*\.cloudfront\.net$"),
    re.compile(r".*\.googleapis\.com$"),
    re.compile(r".*\.windows\.net$"),
    re.compile(r".*\.azure-dns\..*"),
    re.compile(r".*\.1e100\.net$"),
]


# ---------------------------------------------------------------------------
# Core Functions
# ---------------------------------------------------------------------------

def shannon_entropy(data):
    """Calculate Shannon entropy of a string in bits per character."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def extract_subdomain(fqdn):
    """Extract subdomain and base domain from FQDN."""
    fqdn = fqdn.lower().rstrip(".")
    if HAS_TLDEXTRACT:
        ext = tldextract.extract(fqdn)
        subdomain = ext.subdomain or ""
        base = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        return subdomain, base
    else:
        parts = fqdn.split(".")
        if len(parts) > 2:
            return ".".join(parts[:-2]), ".".join(parts[-2:])
        return "", fqdn


def is_whitelisted(fqdn):
    """Check if domain matches a known-legitimate pattern."""
    for pattern in WHITELIST_PATTERNS:
        if pattern.match(fqdn.lower()):
            return True
    return False


def parse_timestamp(ts_str):
    """Parse various timestamp formats."""
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    try:
        return datetime.utcfromtimestamp(float(ts_str))
    except (ValueError, OverflowError, OSError):
        return None


# ---------------------------------------------------------------------------
# Log Parsers
# ---------------------------------------------------------------------------

def parse_zeek_dns_log(filepath):
    """Parse Zeek dns.log (tab-separated format)."""
    queries = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        headers = None
        for line in f:
            line = line.strip()
            if line.startswith("#fields"):
                headers = line.split("\t")[1:]
                continue
            if line.startswith("#") or not line:
                continue

            fields = line.split("\t")
            if headers and len(fields) >= len(headers):
                record = dict(zip(headers, fields))
            elif len(fields) >= 10:
                record = {
                    "ts": fields[0],
                    "id.orig_h": fields[2],
                    "query": fields[9] if len(fields) > 9 else "",
                    "qtype_name": fields[13] if len(fields) > 13 else "",
                    "answers": fields[21] if len(fields) > 21 else "",
                }
            else:
                continue

            ts = record.get("ts", "")
            src_ip = record.get("id.orig_h", "")
            query = record.get("query", "")
            qtype = record.get("qtype_name", record.get("qtype", ""))
            answers = record.get("answers", "")

            if query and query != "-":
                queries.append({
                    "timestamp": ts,
                    "src_ip": src_ip,
                    "query": query,
                    "qtype": qtype,
                    "answers": answers,
                })

    return queries


def parse_suricata_eve(filepath):
    """Parse Suricata EVE JSON log for DNS events."""
    queries = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "dns":
                continue

            dns = event.get("dns", {})
            query = dns.get("rrname", dns.get("query", ""))
            qtype = dns.get("rrtype", dns.get("type", ""))
            src_ip = event.get("src_ip", "")
            ts = event.get("timestamp", "")

            answers_list = dns.get("answers", [])
            answers = ""
            if isinstance(answers_list, list):
                answers = ",".join(
                    a.get("rdata", "") for a in answers_list if isinstance(a, dict)
                )

            if query:
                queries.append({
                    "timestamp": ts,
                    "src_ip": src_ip,
                    "query": query,
                    "qtype": str(qtype),
                    "answers": answers,
                })

    return queries


def parse_csv_dns(filepath):
    """Parse CSV DNS log with columns: timestamp, src_ip, query, qtype, answers."""
    queries = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            query = row.get("query", row.get("domain", row.get("qname", "")))
            if query:
                queries.append({
                    "timestamp": row.get("timestamp", row.get("ts", "")),
                    "src_ip": row.get("src_ip", row.get("source", row.get("client_ip", ""))),
                    "query": query,
                    "qtype": row.get("qtype", row.get("type", row.get("qtype_name", ""))),
                    "answers": row.get("answers", row.get("answer", "")),
                })
    return queries


def load_dns_queries(filepath, fmt="zeek"):
    """Load DNS queries from log file."""
    parsers = {
        "zeek": parse_zeek_dns_log,
        "suricata": parse_suricata_eve,
        "csv": parse_csv_dns,
    }
    parser = parsers.get(fmt)
    if not parser:
        print(f"[ERROR] Unknown format '{fmt}'. Supported: {', '.join(parsers.keys())}")
        return []
    return parser(filepath)


# ---------------------------------------------------------------------------
# Entropy Analysis
# ---------------------------------------------------------------------------

def analyze_entropy(queries, entropy_threshold=3.5, length_threshold=30):
    """Analyze DNS queries for tunneling indicators via entropy and subdomain length."""
    results = []

    for q in queries:
        fqdn = q.get("query", "").lower().rstrip(".")
        if not fqdn or is_whitelisted(fqdn):
            continue

        subdomain, base_domain = extract_subdomain(fqdn)
        if not subdomain:
            continue

        flat = subdomain.replace(".", "")
        if not flat:
            continue

        entropy = shannon_entropy(flat)
        length = len(flat)
        label_count = subdomain.count(".") + 1

        score = 0.0
        flags = []

        # Entropy scoring
        if entropy > 4.0:
            score += (entropy - 3.5) * 30
            flags.append(f"very_high_entropy:{entropy:.2f}")
        elif entropy > entropy_threshold:
            score += (entropy - entropy_threshold) * 25
            flags.append(f"high_entropy:{entropy:.2f}")

        # Length scoring
        if length > 50:
            score += (length - 30) * 0.8
            flags.append(f"very_long_subdomain:{length}")
        elif length > length_threshold:
            score += (length - length_threshold) * 0.5
            flags.append(f"long_subdomain:{length}")

        # Label count
        if label_count > 5:
            score += label_count * 3
            flags.append(f"many_labels:{label_count}")

        # Encoding detection
        hex_ratio = sum(1 for c in flat if c in HEX_CHARS) / len(flat)
        if hex_ratio > 0.85 and length > 20:
            score += 20
            flags.append("hex_encoded")

        b32_ratio = sum(1 for c in flat if c in BASE32_CHARS) / len(flat)
        if b32_ratio > 0.95 and length > 20 and hex_ratio <= 0.85:
            score += 15
            flags.append("base32_encoded")

        # Tool signature matching
        for tool_name, sig in TOOL_SIGNATURES.items():
            if sig["pattern"].match(fqdn):
                qtype = q.get("qtype", "").upper()
                if not qtype or qtype in sig["qtypes"]:
                    ent_low, ent_high = sig["entropy_range"]
                    if ent_low <= entropy <= ent_high or entropy > ent_high:
                        score += 25
                        flags.append(f"tool_sig:{tool_name}")
                        break

        if flags:
            results.append({
                "fqdn": fqdn,
                "subdomain": subdomain,
                "base_domain": base_domain,
                "entropy": round(entropy, 4),
                "subdomain_length": length,
                "label_count": label_count,
                "score": round(score, 2),
                "flags": flags,
                "src_ip": q.get("src_ip", ""),
                "timestamp": q.get("timestamp", ""),
                "qtype": q.get("qtype", ""),
            })

    results.sort(key=lambda x: x["score"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Beaconing Detection
# ---------------------------------------------------------------------------

def detect_beaconing(queries, min_queries=10, max_jitter_pct=25,
                     min_interval=10, max_interval=7200):
    """Detect periodic DNS beaconing patterns."""
    groups = defaultdict(list)

    for q in queries:
        src_ip = q.get("src_ip", "")
        fqdn = q.get("query", "").lower().rstrip(".")
        ts = parse_timestamp(q.get("timestamp", ""))
        if not ts or not src_ip or not fqdn:
            continue

        _, base_domain = extract_subdomain(fqdn)
        if is_whitelisted(fqdn):
            continue
        groups[(src_ip, base_domain)].append(ts)

    beacons = []

    for (src_ip, base_domain), timestamps in groups.items():
        if len(timestamps) < min_queries:
            continue

        timestamps.sort()
        intervals = np.array([
            (timestamps[i+1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)
        ])

        # Remove zero/negative intervals
        intervals = intervals[intervals > 0]
        if len(intervals) < min_queries - 1:
            continue

        mean_int = float(np.mean(intervals))
        std_int = float(np.std(intervals))
        median_int = float(np.median(intervals))

        if mean_int < min_interval or mean_int > max_interval:
            continue

        cv = (std_int / mean_int * 100) if mean_int > 0 else 100
        if cv > max_jitter_pct:
            continue

        time_span = (timestamps[-1] - timestamps[0]).total_seconds()
        hours = time_span / 3600

        score = 0.0
        flags = []

        if cv < 5:
            score += 40
            flags.append(f"very_low_jitter:CV={cv:.1f}%")
        elif cv < 15:
            score += 30
            flags.append(f"low_jitter:CV={cv:.1f}%")
        else:
            score += 15
            flags.append(f"moderate_jitter:CV={cv:.1f}%")

        if hours > 24:
            score += 20
            flags.append(f"persistent:{hours:.1f}h")
        elif hours > 4:
            score += 10
            flags.append(f"sustained:{hours:.1f}h")

        if len(timestamps) > 100:
            score += 15
            flags.append(f"high_volume:{len(timestamps)}")
        elif len(timestamps) > 50:
            score += 10

        common_intervals = [60, 120, 300, 600, 900, 1800, 3600]
        for ci in common_intervals:
            if abs(mean_int - ci) < ci * 0.1:
                score += 10
                flags.append(f"common_c2_interval:~{ci}s")
                break

        beacons.append({
            "src_ip": src_ip,
            "base_domain": base_domain,
            "query_count": len(timestamps),
            "mean_interval": round(mean_int, 2),
            "median_interval": round(median_int, 2),
            "std_interval": round(std_int, 2),
            "jitter_cv": round(cv, 2),
            "first_seen": timestamps[0].isoformat(),
            "last_seen": timestamps[-1].isoformat(),
            "duration_hours": round(hours, 2),
            "score": round(score, 1),
            "flags": flags,
        })

    beacons.sort(key=lambda x: x["score"], reverse=True)
    return beacons


# ---------------------------------------------------------------------------
# TXT Record Analysis
# ---------------------------------------------------------------------------

def analyze_txt_records(queries):
    """Analyze TXT record queries and responses for C2 payload indicators."""
    findings = []

    # Filter TXT queries
    txt_queries = [
        q for q in queries
        if q.get("qtype", "").upper() in ("TXT", "16")
    ]

    if not txt_queries:
        return findings

    # Group by base domain
    domain_groups = defaultdict(list)
    for q in txt_queries:
        fqdn = q.get("query", "").lower().rstrip(".")
        if is_whitelisted(fqdn):
            continue
        _, base_domain = extract_subdomain(fqdn)
        domain_groups[base_domain].append(q)

    for base_domain, group in domain_groups.items():
        count = len(group)
        src_ips = set(q.get("src_ip", "") for q in group)

        indicators = []

        # Volume anomaly
        if count > 50:
            indicators.append({
                "type": "high_txt_volume",
                "detail": f"{count} TXT queries to {base_domain}",
                "severity": "high",
            })
        elif count > 20:
            indicators.append({
                "type": "elevated_txt_volume",
                "detail": f"{count} TXT queries to {base_domain}",
                "severity": "medium",
            })

        # Check answer content
        for q in group:
            answer = q.get("answers", "")
            if not answer or answer == "-":
                continue

            # Large TXT response
            if len(answer) > 500:
                indicators.append({
                    "type": "oversized_txt_response",
                    "detail": f"TXT response length: {len(answer)}",
                    "severity": "high",
                })

            # High entropy in response
            ent = shannon_entropy(answer)
            if ent > 4.5 and len(answer) > 100:
                indicators.append({
                    "type": "high_entropy_txt",
                    "detail": f"TXT response entropy: {ent:.3f}",
                    "severity": "high",
                })

            # Base64 pattern in response
            b64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
            if b64_pattern.search(answer):
                indicators.append({
                    "type": "base64_in_txt",
                    "detail": "Base64-encoded content in TXT response",
                    "severity": "high",
                })

                # Try to decode and check for executable
                try:
                    match = b64_pattern.search(answer)
                    decoded = base64.b64decode(match.group())
                    if decoded[:2] == b'MZ':
                        indicators.append({
                            "type": "pe_in_txt",
                            "detail": "PE executable found in decoded TXT response",
                            "severity": "critical",
                        })
                    if decoded[:4] == b'\x7fELF':
                        indicators.append({
                            "type": "elf_in_txt",
                            "detail": "ELF executable found in decoded TXT response",
                            "severity": "critical",
                        })
                    decoded_str = decoded.decode("utf-8", errors="ignore")
                    ps_patterns = [
                        r"Invoke-Expression", r"IEX\s*\(", r"DownloadString",
                        r"FromBase64String", r"New-Object\s+System\.Net",
                    ]
                    for pat in ps_patterns:
                        if re.search(pat, decoded_str, re.IGNORECASE):
                            indicators.append({
                                "type": "powershell_stager_in_txt",
                                "detail": f"PowerShell pattern in decoded TXT: {pat}",
                                "severity": "critical",
                            })
                            break
                except Exception:
                    pass

        if indicators:
            findings.append({
                "base_domain": base_domain,
                "txt_query_count": count,
                "source_ips": sorted(src_ips),
                "indicators": indicators,
                "max_severity": max(
                    (i["severity"] for i in indicators),
                    key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s, 0)
                ),
                "sample_queries": [q["query"] for q in group[:5]],
            })

    findings.sort(
        key=lambda x: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
            x["max_severity"], 0),
        reverse=True,
    )
    return findings


# ---------------------------------------------------------------------------
# DGA Classification
# ---------------------------------------------------------------------------

DGA_FEATURE_COLUMNS = [
    "length", "entropy", "digit_ratio", "vowel_ratio", "consonant_ratio",
    "max_consonant_run", "distinct_chars", "distinct_ratio",
    "english_bigram_score", "label_count", "hex_ratio",
    "transition_ratio", "repeat_ratio", "special_count",
]


def extract_domain_features(domain):
    """Extract numerical features from a domain for DGA classification."""
    domain = domain.lower().strip(".")
    parts = domain.split(".")
    analysis_str = ".".join(parts[:-1]) if len(parts) > 1 else domain
    flat = analysis_str.replace(".", "")
    length = len(flat)

    if length == 0:
        return None

    entropy = shannon_entropy(flat)

    digit_count = sum(1 for c in flat if c.isdigit())
    vowel_count = sum(1 for c in flat if c in VOWELS)
    consonant_count = sum(1 for c in flat if c in CONSONANTS)

    max_consonant_run = 0
    current_run = 0
    for c in flat:
        if c in CONSONANTS:
            current_run += 1
            max_consonant_run = max(max_consonant_run, current_run)
        else:
            current_run = 0

    distinct_chars = len(set(flat))
    bigrams = [flat[i:i+2] for i in range(len(flat) - 1)]
    english_score = (
        sum(ENGLISH_BIGRAMS.get(bg, 0) for bg in bigrams) / len(bigrams)
        if bigrams else 0
    )

    hex_ratio = sum(1 for c in flat if c in HEX_CHARS) / length
    transitions = sum(
        1 for i in range(1, len(flat))
        if flat[i].isdigit() != flat[i-1].isdigit()
    )
    repeats = sum(1 for i in range(1, len(flat)) if flat[i] == flat[i-1]) if length > 1 else 0

    return {
        "domain": domain,
        "length": length,
        "entropy": round(entropy, 4),
        "digit_ratio": round(digit_count / length, 4),
        "vowel_ratio": round(vowel_count / length, 4),
        "consonant_ratio": round(consonant_count / length, 4),
        "max_consonant_run": max_consonant_run,
        "distinct_chars": distinct_chars,
        "distinct_ratio": round(distinct_chars / length, 4),
        "english_bigram_score": round(english_score, 6),
        "label_count": len(parts),
        "hex_ratio": round(hex_ratio, 4),
        "transition_ratio": round(transitions / max(length - 1, 1), 4),
        "repeat_ratio": round(repeats / max(length - 1, 1), 4),
        "special_count": sum(1 for c in flat if c == '-'),
    }


def features_to_vector(features):
    """Convert feature dict to numpy array."""
    return np.array([features[col] for col in DGA_FEATURE_COLUMNS])


def train_dga_model(legit_domains, dga_domains, model_type="random_forest",
                    output_model=None):
    """Train and evaluate a DGA classification model."""
    if not HAS_SKLEARN:
        print("[ERROR] scikit-learn required: pip install scikit-learn")
        return None, None, None

    print(f"[*] Extracting features from {len(legit_domains)} legitimate "
          f"and {len(dga_domains)} DGA domains...")

    X_legit = [features_to_vector(f) for d in legit_domains
               if (f := extract_domain_features(d)) is not None]
    X_dga = [features_to_vector(f) for d in dga_domains
             if (f := extract_domain_features(d)) is not None]

    if len(X_legit) < 100 or len(X_dga) < 100:
        print(f"[ERROR] Insufficient data: {len(X_legit)} legit, {len(X_dga)} DGA")
        return None, None, None

    print(f"    Features extracted: {len(X_legit)} legit, {len(X_dga)} DGA")

    X = np.vstack([np.array(X_legit), np.array(X_dga)])
    y = np.array([0] * len(X_legit) + [1] * len(X_dga))

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    if model_type == "gradient_boosting":
        model = GradientBoostingClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            min_samples_split=10, random_state=42,
        )
    else:
        model = RandomForestClassifier(
            n_estimators=200, max_depth=15, min_samples_split=5,
            random_state=42, n_jobs=-1,
        )

    print(f"[*] Training {model_type} classifier...")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=["legitimate", "dga"],
                                   output_dict=True)
    cm = confusion_matrix(y_test, y_pred)
    cv_scores = cross_val_score(model, X_scaled, y, cv=5, scoring="f1")

    metrics = {
        "model_type": model_type,
        "train_size": len(X_train),
        "test_size": len(X_test),
        "accuracy": round(report["accuracy"], 4),
        "dga_precision": round(report["dga"]["precision"], 4),
        "dga_recall": round(report["dga"]["recall"], 4),
        "dga_f1": round(report["dga"]["f1-score"], 4),
        "legit_precision": round(report["legitimate"]["precision"], 4),
        "legit_recall": round(report["legitimate"]["recall"], 4),
        "confusion_matrix": cm.tolist(),
        "cv_f1_mean": round(float(cv_scores.mean()), 4),
        "cv_f1_std": round(float(cv_scores.std()), 4),
        "feature_importance": {
            k: round(float(v), 4)
            for k, v in zip(DGA_FEATURE_COLUMNS, model.feature_importances_)
        },
    }

    print("[+] Model trained successfully")
    print(f"    Accuracy:      {metrics['accuracy']}")
    print(f"    DGA F1:        {metrics['dga_f1']}")
    print(f"    DGA Recall:    {metrics['dga_recall']}")
    print(f"    CV F1 (5-fold): {metrics['cv_f1_mean']} +/- {metrics['cv_f1_std']}")

    top_feats = sorted(metrics["feature_importance"].items(),
                       key=lambda x: x[1], reverse=True)[:5]
    print(f"    Top features:  {', '.join(f'{k}={v:.3f}' for k, v in top_feats)}")

    if output_model:
        with open(output_model, "wb") as f:
            pickle.dump({"model": model, "scaler": scaler, "metrics": metrics}, f)
        print(f"[+] Model saved to {output_model}")

    return model, scaler, metrics


def classify_domains_dga(domains, model, scaler, threshold=0.65):
    """Classify domains as DGA or legitimate."""
    results = []
    for domain in domains:
        feats = extract_domain_features(domain)
        if feats is None:
            continue

        vec = features_to_vector(feats).reshape(1, -1)
        vec_scaled = scaler.transform(vec)
        prob = model.predict_proba(vec_scaled)[0]

        if prob[1] >= threshold:
            results.append({
                "domain": domain,
                "prediction": "dga" if prob[1] >= 0.5 else "legitimate",
                "dga_probability": round(float(prob[1]), 4),
                "confidence": "high" if prob[1] > 0.85 else "medium",
                "entropy": feats["entropy"],
                "length": feats["length"],
            })

    results.sort(key=lambda x: x["dga_probability"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(entropy_results, beacons, txt_findings, dga_results,
                 total_queries, unique_domains):
    """Print unified DNS C2 detection report."""
    print("=" * 80)
    print("  DNS C2 DETECTION ANALYSIS REPORT")
    print("=" * 80)
    print(f"  Generated:      {datetime.utcnow().isoformat()}Z")
    print(f"  Total Queries:  {total_queries:,}")
    print(f"  Unique Domains: {unique_domains:,}")
    print()

    # Entropy section
    print("  ENTROPY ANALYSIS")
    print("  " + "-" * 76)
    print(f"  Suspicious queries: {len(entropy_results)}")

    if entropy_results:
        # Group by base domain
        domain_agg = defaultdict(lambda: {"count": 0, "max_ent": 0, "max_score": 0, "ips": set()})
        for r in entropy_results:
            bd = r["base_domain"]
            domain_agg[bd]["count"] += 1
            domain_agg[bd]["max_ent"] = max(domain_agg[bd]["max_ent"], r["entropy"])
            domain_agg[bd]["max_score"] = max(domain_agg[bd]["max_score"], r["score"])
            domain_agg[bd]["ips"].add(r["src_ip"])

        sorted_domains = sorted(domain_agg.items(), key=lambda x: x[1]["max_score"], reverse=True)
        for domain, data in sorted_domains[:10]:
            severity = "CRITICAL" if data["max_score"] > 60 else "HIGH" if data["max_score"] > 30 else "MEDIUM"
            print(f"\n    [{severity}] {domain}")
            print(f"      Suspicious queries: {data['count']}  Max entropy: {data['max_ent']:.3f}")
            print(f"      Source IPs: {', '.join(sorted(data['ips']))}")

            # Show tool signature if matched
            for r in entropy_results:
                if r["base_domain"] == domain:
                    tool_flags = [f for f in r["flags"] if f.startswith("tool_sig:")]
                    if tool_flags:
                        print(f"      Tool match: {tool_flags[0].split(':')[1]}")
                    break
    print()

    # Beaconing section
    print("  BEACONING DETECTION")
    print("  " + "-" * 76)
    print(f"  Beacon patterns: {len(beacons)}")
    for b in beacons[:10]:
        severity = "CRITICAL" if b["score"] > 70 else "HIGH" if b["score"] > 50 else "MEDIUM"
        print(f"\n    [{severity}] {b['src_ip']} -> {b['base_domain']}")
        print(f"      Score: {b['score']}  Queries: {b['query_count']}  "
              f"Interval: {b['mean_interval']:.1f}s +/- {b['std_interval']:.1f}s")
        print(f"      Jitter: {b['jitter_cv']:.1f}%  Duration: {b['duration_hours']:.1f}h")
        print(f"      Flags: {', '.join(b['flags'])}")
    print()

    # TXT record section
    print("  TXT RECORD ANALYSIS")
    print("  " + "-" * 76)
    print(f"  Suspicious TXT patterns: {len(txt_findings)}")
    for finding in txt_findings[:10]:
        print(f"\n    [{finding['max_severity'].upper()}] {finding['base_domain']}")
        print(f"      TXT queries: {finding['txt_query_count']}  "
              f"Sources: {', '.join(finding['source_ips'][:3])}")
        for ind in finding["indicators"][:3]:
            print(f"      - {ind['type']}: {ind['detail']}")
    print()

    # DGA section
    if dga_results:
        print("  DGA CLASSIFICATION")
        print("  " + "-" * 76)
        high_conf = [r for r in dga_results if r["confidence"] == "high"]
        med_conf = [r for r in dga_results if r["confidence"] == "medium"]
        print(f"  High confidence DGA: {len(high_conf)}")
        print(f"  Medium confidence:   {len(med_conf)}")
        for r in dga_results[:15]:
            print(f"    [{r['confidence'].upper()}] {r['domain']}  "
                  f"(prob: {r['dga_probability']:.3f}, ent: {r['entropy']:.2f})")
        print()

    # Recommendations
    print("  RECOMMENDED ACTIONS")
    print("  " + "-" * 76)
    action_num = 1

    critical_domains = set()
    for r in entropy_results:
        if r["score"] > 60:
            critical_domains.add(r["base_domain"])
    for b in beacons:
        if b["score"] > 70:
            critical_domains.add(b["base_domain"])
    for f in txt_findings:
        if f["max_severity"] == "critical":
            critical_domains.add(f["base_domain"])

    if critical_domains:
        print(f"  {action_num}. [CRITICAL] Block in DNS RPZ/firewall: "
              f"{', '.join(sorted(critical_domains)[:5])}")
        action_num += 1

    critical_ips = set()
    for r in entropy_results[:5]:
        if r["score"] > 60 and r["src_ip"]:
            critical_ips.add(r["src_ip"])
    for b in beacons[:5]:
        if b["score"] > 70:
            critical_ips.add(b["src_ip"])

    if critical_ips:
        print(f"  {action_num}. [CRITICAL] Isolate and investigate hosts: "
              f"{', '.join(sorted(critical_ips)[:5])}")
        action_num += 1

    if dga_results:
        high_dga = [r["domain"] for r in dga_results if r["confidence"] == "high"]
        if high_dga:
            print(f"  {action_num}. [HIGH] Block {len(high_dga)} high-confidence DGA domains")
            action_num += 1

    if txt_findings:
        print(f"  {action_num}. [HIGH] Review {len(txt_findings)} domains with suspicious TXT activity")
        action_num += 1

    print(f"  {action_num}. [MEDIUM] Deploy Zeek/Suricata DNS tunneling signatures")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="DNS C2 Detection Agent - Tunneling, DGA, Beaconing, TXT Payload Analysis"
    )
    parser.add_argument("--dns-log", help="Path to DNS log file")
    parser.add_argument("--format", choices=["zeek", "suricata", "csv"],
                        default="zeek", help="DNS log format")
    parser.add_argument("--mode", choices=["full", "entropy", "beacon", "txt",
                                           "dga-classify", "train-dga"],
                        default="full", help="Analysis mode")

    # Thresholds
    parser.add_argument("--entropy-threshold", type=float, default=3.5,
                        help="Shannon entropy threshold for suspicious queries")
    parser.add_argument("--length-threshold", type=int, default=30,
                        help="Subdomain length threshold")
    parser.add_argument("--beacon-min-queries", type=int, default=10,
                        help="Minimum queries for beacon detection")
    parser.add_argument("--beacon-max-jitter", type=float, default=25,
                        help="Maximum jitter CV%% for beacon detection")
    parser.add_argument("--dga-threshold", type=float, default=0.65,
                        help="DGA probability threshold for reporting")

    # DGA training
    parser.add_argument("--legit-domains", help="File with legitimate domains (one per line)")
    parser.add_argument("--dga-domains", help="File with DGA domains (one per line)")
    parser.add_argument("--model-type", choices=["random_forest", "gradient_boosting"],
                        default="random_forest", help="ML model type for DGA")
    parser.add_argument("--dga-model", help="Path to saved DGA model (pickle)")

    # Output
    parser.add_argument("--output", default="dns_c2_report.json",
                        help="Output path for JSON report")
    parser.add_argument("--output-model", default="dga_model.pkl",
                        help="Output path for trained DGA model")

    args = parser.parse_args()

    print("[*] DNS C2 Detection Agent")
    print(f"    Mode: {args.mode}")
    print()

    # DGA training mode
    if args.mode == "train-dga":
        if not args.legit_domains or not args.dga_domains:
            print("[ERROR] --legit-domains and --dga-domains required for training")
            sys.exit(1)

        with open(args.legit_domains) as f:
            legit = [line.strip() for line in f if line.strip()]
        with open(args.dga_domains) as f:
            dga = [line.strip() for line in f if line.strip()]

        print(f"[*] Loaded {len(legit)} legitimate and {len(dga)} DGA domains")
        model, scaler, metrics = train_dga_model(
            legit, dga, args.model_type, args.output_model
        )
        if metrics:
            with open(args.output, "w") as f:
                json.dump(metrics, f, indent=2)
            print(f"[+] Metrics saved to {args.output}")
        return

    # Analysis modes require DNS log
    if not args.dns_log:
        print("[ERROR] --dns-log required for analysis")
        sys.exit(1)

    print(f"[*] Loading DNS queries from {args.dns_log} (format: {args.format})...")
    queries = load_dns_queries(args.dns_log, args.format)
    print(f"    Loaded {len(queries):,} queries")

    if not queries:
        print("[ERROR] No queries loaded. Check file path and format.")
        sys.exit(1)

    unique_domains = len(set(q.get("query", "") for q in queries))
    print(f"    Unique domains: {unique_domains:,}")
    print()

    entropy_results = []
    beacons = []
    txt_findings = []
    dga_results = []

    # Entropy analysis
    if args.mode in ("full", "entropy"):
        print("[*] Running entropy analysis...")
        entropy_results = analyze_entropy(
            queries, args.entropy_threshold, args.length_threshold
        )
        print(f"    Suspicious queries: {len(entropy_results)}")

    # Beaconing detection
    if args.mode in ("full", "beacon"):
        print("[*] Running beacon detection...")
        beacons = detect_beaconing(
            queries, args.beacon_min_queries, args.beacon_max_jitter
        )
        print(f"    Beacon patterns: {len(beacons)}")

    # TXT record analysis
    if args.mode in ("full", "txt"):
        print("[*] Running TXT record analysis...")
        txt_findings = analyze_txt_records(queries)
        print(f"    Suspicious TXT patterns: {len(txt_findings)}")

    # DGA classification
    if args.mode in ("full", "dga-classify"):
        model = None
        scaler = None

        if args.dga_model and os.path.exists(args.dga_model):
            print(f"[*] Loading DGA model from {args.dga_model}...")
            with open(args.dga_model, "rb") as f:
                saved = pickle.load(f)
            model = saved["model"]
            scaler = saved["scaler"]
        elif HAS_SKLEARN:
            print("[*] No DGA model provided, using feature-based heuristic scoring")
        else:
            print("[WARN] scikit-learn not available, skipping DGA classification")

        if model and scaler:
            domains = list(set(q.get("query", "").lower().rstrip(".")
                              for q in queries if q.get("query")))
            print(f"[*] Classifying {len(domains)} unique domains...")
            dga_results = classify_domains_dga(domains, model, scaler, args.dga_threshold)
            print(f"    DGA candidates: {len(dga_results)}")

    print()

    # Print report
    print_report(entropy_results, beacons, txt_findings, dga_results,
                 len(queries), unique_domains)

    # Save JSON report
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_queries": len(queries),
        "unique_domains": unique_domains,
        "entropy_analysis": {
            "threshold": args.entropy_threshold,
            "suspicious_count": len(entropy_results),
            "results": entropy_results[:100],
        },
        "beaconing": {
            "min_queries": args.beacon_min_queries,
            "max_jitter_pct": args.beacon_max_jitter,
            "patterns_detected": len(beacons),
            "results": beacons[:50],
        },
        "txt_analysis": {
            "suspicious_count": len(txt_findings),
            "results": txt_findings[:50],
        },
        "dga_classification": {
            "threshold": args.dga_threshold,
            "candidates": len(dga_results),
            "results": dga_results[:100],
        },
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")
    print("[*] Done.")


if __name__ == "__main__":
    main()
