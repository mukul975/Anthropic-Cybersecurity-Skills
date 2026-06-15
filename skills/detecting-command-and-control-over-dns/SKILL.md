---
name: detecting-command-and-control-over-dns
description: 'Detects command-and-control (C2) communications tunneled through DNS
  protocol including DNS tunneling tools (Iodine, dnscat2, dns2tcp, Cobalt Strike
  DNS beacon), domain generation algorithms (DGA), encoded payload delivery via TXT/CNAME
  records, and DNS beaconing patterns. Covers Shannon entropy analysis of query subdomains,
  statistical anomaly detection, ML-based DGA classification, passive DNS correlation,
  and Zeek/Suricata signature development. Activates for requests involving DNS-based
  C2 detection, DNS tunnel identification, suspicious DNS traffic investigation, or
  DGA domain classification.

  '
domain: cybersecurity
subdomain: network-security
tags:
- dns
- c2
- tunneling
- dga
- network-forensics
- threat-detection
version: 1.0.0
author: mukul975
license: Apache-2.0
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
mitre_attack:
- T1046
- T1040
- T1557
- T1071
- T1095
---

# Detecting Command and Control Over DNS

## When to Use

- Investigating suspected DNS tunneling used for C2 communication or data exfiltration
- Analyzing DNS query logs for signs of encoded payloads in subdomain strings
- Classifying domains as DGA-generated vs. legitimate using statistical or ML methods
- Detecting DNS beaconing patterns (regular intervals, consistent query sizes)
- Hunting for Iodine, dnscat2, dns2tcp, Cobalt Strike DNS, or Sliver DNS traffic
- Monitoring TXT record abuse for command delivery or staged payload download
- Building DNS anomaly detection rules for SOC/SIEM deployment

**Do not use** for general DNS performance monitoring or DNS configuration auditing; use DNS health monitoring tools for those. For HTTP/HTTPS-based C2 detection, use network traffic analysis skills focused on web protocols.

**DISCLAIMER**: DNS tunneling tools referenced in this skill (Iodine, dnscat2, dns2tcp) are dual-use. They have legitimate uses (bypassing captive portals, security research) and malicious uses (C2 channels, exfiltration). Only deploy detection in networks you are authorized to monitor. Testing tunneling tools requires explicit authorization.

## Prerequisites

- DNS query logs from recursive resolver, Zeek/Bro, Suricata, or passive DNS tap
- Python 3.9+ with `numpy`, `scikit-learn`, `pandas`, `tldextract`, and `dnspython`
- Zeek (formerly Bro) with dns.log output or Suricata with DNS EVE JSON logging
- SIEM access (Splunk, Elastic, Microsoft Sentinel) for log correlation
- Passive DNS database access (CIRCL pDNS, Farsight DNSDB, or internal) for enrichment
- Wireshark/tshark for packet-level DNS inspection
- Known-good domain whitelist (Alexa/Tranco top 1M or Majestic Million)

## Workflow

### Step 1: Collect and Parse DNS Query Logs

Ingest DNS traffic from network sensors and parse into analyzable format:

```bash
# Zeek - extract dns.log fields
# Default Zeek dns.log columns:
# ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto trans_id rtt query
# qclass qclass_name qtype qtype_name rcode rcode_name AA TC RD RA Z
# answers TTLs rejected

# Filter for potentially suspicious record types
cat dns.log | zeek-cut ts id.orig_h query qtype_name answers rcode_name | \
    grep -E "TXT|NULL|CNAME|MX" > suspicious_qtypes.log

# Extract unique queried domains
cat dns.log | zeek-cut query | sort -u > unique_domains.txt

# Suricata EVE JSON - extract DNS events
cat eve.json | jq -r 'select(.event_type=="dns") |
    [.timestamp, .src_ip, .dns.rrname, .dns.rrtype, .dns.rcode] |
    @tsv' > dns_events.tsv

# tshark - extract DNS queries from pcap
tshark -r capture.pcap -T fields \
    -e frame.time -e ip.src -e ip.dst \
    -e dns.qry.name -e dns.qry.type \
    -e dns.resp.type -e dns.txt \
    -Y "dns" > dns_queries.tsv

# Count queries per domain (find high-volume destinations)
cat dns.log | zeek-cut query | \
    awk -F. '{print $(NF-1)"."$NF}' | \
    sort | uniq -c | sort -rn | head -50
```

### Step 2: Shannon Entropy Analysis of DNS Queries

Calculate entropy of subdomain strings to identify encoded/encrypted data:

```python
#!/usr/bin/env python3
"""Shannon entropy analysis for DNS query subdomains."""

import math
import csv
import sys
from collections import Counter

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False


def shannon_entropy(data):
    """Calculate Shannon entropy of a string (bits per character)."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return entropy


def extract_subdomain(fqdn):
    """Extract the subdomain portion from a fully qualified domain name."""
    if HAS_TLDEXTRACT:
        ext = tldextract.extract(fqdn)
        if ext.subdomain:
            return ext.subdomain, f"{ext.domain}.{ext.suffix}"
        return "", f"{ext.domain}.{ext.suffix}"
    else:
        # Fallback: assume last two labels are domain + TLD
        parts = fqdn.rstrip(".").split(".")
        if len(parts) > 2:
            return ".".join(parts[:-2]), ".".join(parts[-2:])
        return "", fqdn


def analyze_dns_entropy(queries, entropy_threshold=3.5, length_threshold=30):
    """
    Analyze DNS queries for tunneling indicators using entropy.

    Thresholds (tunable per environment):
      - entropy_threshold: Shannon entropy above this flags as suspicious (3.5-4.0 typical)
      - length_threshold: Subdomain length above this flags as suspicious (30-50 chars)

    Returns list of flagged queries with scores.
    """
    results = []

    for query_record in queries:
        fqdn = query_record.get("query", "").lower().rstrip(".")
        if not fqdn:
            continue

        subdomain, base_domain = extract_subdomain(fqdn)
        if not subdomain:
            continue

        # Remove dots from subdomain for entropy calculation
        subdomain_flat = subdomain.replace(".", "")
        if not subdomain_flat:
            continue

        entropy = shannon_entropy(subdomain_flat)
        length = len(subdomain_flat)
        label_count = subdomain.count(".") + 1

        # Scoring: higher = more suspicious
        score = 0.0
        flags = []

        if entropy > entropy_threshold:
            score += (entropy - entropy_threshold) * 25
            flags.append(f"high_entropy:{entropy:.2f}")

        if length > length_threshold:
            score += (length - length_threshold) * 0.5
            flags.append(f"long_subdomain:{length}")

        if label_count > 4:
            score += label_count * 2
            flags.append(f"many_labels:{label_count}")

        # Check for hex/base32/base64 encoding patterns
        hex_ratio = sum(1 for c in subdomain_flat if c in "0123456789abcdef") / max(len(subdomain_flat), 1)
        if hex_ratio > 0.85 and length > 20:
            score += 20
            flags.append("hex_encoded")

        b32_chars = set("abcdefghijklmnopqrstuvwxyz234567")
        b32_ratio = sum(1 for c in subdomain_flat if c in b32_chars) / max(len(subdomain_flat), 1)
        if b32_ratio > 0.95 and length > 20:
            score += 15
            flags.append("base32_encoded")

        # Only report if at least one flag triggered
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
                "src_ip": query_record.get("src_ip", ""),
                "timestamp": query_record.get("timestamp", ""),
                "qtype": query_record.get("qtype", ""),
            })

    # Sort by score descending
    results.sort(key=lambda x: x["score"], reverse=True)
    return results


# Thresholds for known tunneling tools
TOOL_SIGNATURES = {
    "iodine": {
        "subdomain_pattern": r"^[a-z0-9]{50,}$",  # Long hex-like subdomains
        "common_qtypes": ["NULL", "TXT", "CNAME", "MX", "A"],
        "typical_entropy": (3.8, 4.2),
        "description": "Iodine DNS tunnel - IPv4 over DNS, uses NULL/TXT records",
    },
    "dnscat2": {
        "subdomain_pattern": r"^dnscat\.|^[a-f0-9]{16,}",
        "common_qtypes": ["TXT", "CNAME", "MX", "A"],
        "typical_entropy": (3.5, 4.5),
        "description": "dnscat2 encrypted C2 channel over DNS",
    },
    "dns2tcp": {
        "subdomain_pattern": r"^[a-z2-7]{20,}",  # Base32 encoding
        "common_qtypes": ["TXT", "KEY"],
        "typical_entropy": (3.6, 4.0),
        "description": "dns2tcp tunnel - TCP over DNS using TXT/KEY records",
    },
    "cobalt_strike_dns": {
        "subdomain_pattern": r"^[a-f0-9]{12,}\.",
        "common_qtypes": ["A", "AAAA", "TXT"],
        "typical_entropy": (3.2, 4.0),
        "description": "Cobalt Strike DNS beacon - encoded commands in A/TXT records",
    },
}


def print_entropy_report(results, top_n=25):
    """Print formatted entropy analysis report."""
    print("=" * 80)
    print("  DNS ENTROPY ANALYSIS - TUNNELING DETECTION")
    print("=" * 80)
    print(f"  Suspicious queries found: {len(results)}")
    print()

    if not results:
        print("  No suspicious queries detected.")
        return

    # Group by base domain
    domain_groups = {}
    for r in results:
        bd = r["base_domain"]
        if bd not in domain_groups:
            domain_groups[bd] = {"count": 0, "max_entropy": 0, "max_score": 0, "queries": []}
        domain_groups[bd]["count"] += 1
        domain_groups[bd]["max_entropy"] = max(domain_groups[bd]["max_entropy"], r["entropy"])
        domain_groups[bd]["max_score"] = max(domain_groups[bd]["max_score"], r["score"])
        domain_groups[bd]["queries"].append(r)

    # Sort domains by total suspicious query count
    sorted_domains = sorted(domain_groups.items(), key=lambda x: x[1]["count"], reverse=True)

    print("  TOP SUSPICIOUS BASE DOMAINS")
    print("  " + "-" * 76)
    print(f"  {'Domain':<35} {'Queries':>8} {'Max Ent':>8} {'Max Score':>10}")
    print("  " + "-" * 76)
    for domain, data in sorted_domains[:20]:
        print(f"  {domain:<35} {data['count']:>8} {data['max_entropy']:>8.3f} {data['max_score']:>10.1f}")
    print()

    print(f"  TOP {top_n} HIGHEST-SCORING QUERIES")
    print("  " + "-" * 76)
    for r in results[:top_n]:
        print(f"  Score: {r['score']:.1f}  Entropy: {r['entropy']:.3f}  Len: {r['subdomain_length']}")
        print(f"    FQDN:   {r['fqdn'][:75]}")
        print(f"    Flags:  {', '.join(r['flags'])}")
        print(f"    Source: {r['src_ip']}  Type: {r['qtype']}")
        print()
```

### Step 3: TXT Record Payload Detection

Identify C2 commands or staged payloads delivered via DNS TXT records:

```python
#!/usr/bin/env python3
"""DNS TXT record payload detection for C2 command delivery."""

import base64
import re
import math
from collections import Counter


def shannon_entropy(data):
    """Calculate Shannon entropy."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def analyze_txt_record(txt_data, domain=""):
    """
    Analyze a DNS TXT record response for C2 payload indicators.

    Indicators:
      - High entropy content (encoded/encrypted payloads)
      - Base64-encoded executable content
      - PowerShell stager patterns
      - Unusually large TXT records (>255 bytes per string, multiple strings)
      - Known C2 framework patterns
    """
    findings = {
        "domain": domain,
        "txt_length": len(txt_data),
        "entropy": shannon_entropy(txt_data),
        "suspicious": False,
        "indicators": [],
        "decoded_preview": None,
    }

    # Length check - legitimate TXT records are typically short (SPF, DKIM, verification)
    if len(txt_data) > 500:
        findings["indicators"].append({
            "type": "oversized_txt",
            "detail": f"TXT record length {len(txt_data)} exceeds normal threshold (500)",
            "severity": "medium",
        })

    # High entropy - suggests encoded/encrypted payload
    if findings["entropy"] > 4.5 and len(txt_data) > 100:
        findings["indicators"].append({
            "type": "high_entropy_payload",
            "detail": f"Entropy {findings['entropy']:.3f} suggests encoded data",
            "severity": "high",
        })

    # Base64 detection
    b64_pattern = re.compile(r'^[A-Za-z0-9+/]{40,}={0,2}$')
    if b64_pattern.match(txt_data.strip()):
        findings["indicators"].append({
            "type": "base64_encoded",
            "detail": "Content matches base64 pattern",
            "severity": "high",
        })
        try:
            decoded = base64.b64decode(txt_data.strip())
            preview = decoded[:200]

            # Check for PE header (MZ)
            if preview[:2] == b'MZ':
                findings["indicators"].append({
                    "type": "pe_executable",
                    "detail": "Decoded base64 contains PE executable (MZ header)",
                    "severity": "critical",
                })

            # Check for ELF header
            if preview[:4] == b'\x7fELF':
                findings["indicators"].append({
                    "type": "elf_executable",
                    "detail": "Decoded base64 contains ELF executable",
                    "severity": "critical",
                })

            # Check for PowerShell patterns
            decoded_str = decoded.decode("utf-8", errors="ignore")
            ps_patterns = [
                r"Invoke-Expression",
                r"IEX\s*\(",
                r"New-Object\s+System\.Net",
                r"DownloadString",
                r"FromBase64String",
                r"Start-Process",
                r"\-enc\s",
                r"powershell\s.*\-e\s",
            ]
            for pattern in ps_patterns:
                if re.search(pattern, decoded_str, re.IGNORECASE):
                    findings["indicators"].append({
                        "type": "powershell_stager",
                        "detail": f"Decoded content contains PowerShell pattern: {pattern}",
                        "severity": "critical",
                    })
                    break

            findings["decoded_preview"] = repr(preview[:100])

        except Exception:
            pass

    # Known C2 TXT patterns
    cobalt_pattern = re.compile(r'^[a-f0-9]{32,}$', re.IGNORECASE)
    if cobalt_pattern.match(txt_data.strip()):
        findings["indicators"].append({
            "type": "hex_encoded_payload",
            "detail": "Pure hex string in TXT record - possible Cobalt Strike beacon config",
            "severity": "high",
        })

    # Multiple concatenated base64 blocks (common in staged delivery)
    b64_blocks = re.findall(r'[A-Za-z0-9+/]{50,}={0,2}', txt_data)
    if len(b64_blocks) > 3:
        findings["indicators"].append({
            "type": "multi_block_payload",
            "detail": f"{len(b64_blocks)} base64 blocks found - possible staged payload",
            "severity": "high",
        })

    # Check for known legitimate TXT patterns to reduce false positives
    legitimate_patterns = [
        r'^v=spf1\s',           # SPF record
        r'^v=DKIM1',            # DKIM record
        r'^v=DMARC1',           # DMARC record
        r'^google-site-verification=',
        r'^MS=',                # Microsoft domain verification
        r'^docusign=',
        r'^apple-domain-verification=',
        r'^facebook-domain-verification=',
        r'^_globalsign-domain-verification=',
    ]
    for pattern in legitimate_patterns:
        if re.match(pattern, txt_data, re.IGNORECASE):
            findings["indicators"] = []
            findings["legitimate"] = True
            return findings

    findings["suspicious"] = len(findings["indicators"]) > 0
    return findings


def analyze_txt_records_bulk(records):
    """Analyze a batch of DNS TXT records."""
    results = []
    for record in records:
        domain = record.get("domain", record.get("query", ""))
        txt_data = record.get("txt", record.get("answer", ""))
        if txt_data:
            finding = analyze_txt_record(txt_data, domain)
            if finding["suspicious"]:
                results.append(finding)

    results.sort(
        key=lambda x: max((i.get("severity_score", 0) for i in x["indicators"]),
                          default=0),
        reverse=True,
    )
    return results
```

### Step 4: DGA Domain Classification with Machine Learning

Train a classifier to distinguish DGA-generated domains from legitimate ones:

```python
#!/usr/bin/env python3
"""
DGA domain classification using character-level feature extraction and ML.

Features extracted per domain:
  - Shannon entropy of the domain string
  - Domain length
  - Digit ratio, consonant ratio, vowel ratio
  - Longest consecutive consonant sequence
  - N-gram frequency deviation from English
  - Number of distinct characters
  - Presence of dictionary words
"""

import math
import re
import string
from collections import Counter

import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.preprocessing import StandardScaler
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


# English language character bigram frequencies (normalized, top bigrams)
# Source: Peter Norvig's English letter frequency analysis
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

VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


def extract_domain_features(domain):
    """Extract numerical features from a domain name for ML classification."""
    domain = domain.lower().strip(".")

    # Remove TLD for analysis (focus on SLD + subdomain)
    parts = domain.split(".")
    if len(parts) > 1:
        analysis_str = ".".join(parts[:-1])  # Drop TLD
    else:
        analysis_str = domain

    # Remove dots for character analysis
    flat = analysis_str.replace(".", "")
    length = len(flat)

    if length == 0:
        return None

    # 1. Shannon entropy
    entropy = 0.0
    counter = Counter(flat)
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)

    # 2. Character ratios
    digit_count = sum(1 for c in flat if c.isdigit())
    vowel_count = sum(1 for c in flat if c in VOWELS)
    consonant_count = sum(1 for c in flat if c in CONSONANTS)
    special_count = sum(1 for c in flat if c == '-')

    digit_ratio = digit_count / length
    vowel_ratio = vowel_count / length
    consonant_ratio = consonant_count / length

    # 3. Longest consecutive consonant run
    max_consonant_run = 0
    current_run = 0
    for c in flat:
        if c in CONSONANTS:
            current_run += 1
            max_consonant_run = max(max_consonant_run, current_run)
        else:
            current_run = 0

    # 4. Distinct character count and ratio
    distinct_chars = len(set(flat))
    distinct_ratio = distinct_chars / length

    # 5. Bigram frequency deviation from English
    bigrams = [flat[i:i+2] for i in range(len(flat) - 1)]
    if bigrams:
        english_score = sum(
            ENGLISH_BIGRAMS.get(bg, 0) for bg in bigrams
        ) / len(bigrams)
    else:
        english_score = 0

    # 6. Number of labels (dots + 1)
    label_count = len(parts)

    # 7. Hex character ratio (common in DGA)
    hex_chars = set("0123456789abcdef")
    hex_ratio = sum(1 for c in flat if c in hex_chars) / length

    # 8. Digit-letter transitions (DGA domains mix digits and letters)
    transitions = 0
    for i in range(1, len(flat)):
        if (flat[i].isdigit() != flat[i-1].isdigit()):
            transitions += 1
    transition_ratio = transitions / max(length - 1, 1)

    # 9. Repeated character ratio
    if length > 1:
        repeats = sum(1 for i in range(1, len(flat)) if flat[i] == flat[i-1])
        repeat_ratio = repeats / (length - 1)
    else:
        repeat_ratio = 0

    return {
        "domain": domain,
        "length": length,
        "entropy": round(entropy, 4),
        "digit_ratio": round(digit_ratio, 4),
        "vowel_ratio": round(vowel_ratio, 4),
        "consonant_ratio": round(consonant_ratio, 4),
        "max_consonant_run": max_consonant_run,
        "distinct_chars": distinct_chars,
        "distinct_ratio": round(distinct_ratio, 4),
        "english_bigram_score": round(english_score, 6),
        "label_count": label_count,
        "hex_ratio": round(hex_ratio, 4),
        "transition_ratio": round(transition_ratio, 4),
        "repeat_ratio": round(repeat_ratio, 4),
        "special_count": special_count,
    }


FEATURE_COLUMNS = [
    "length", "entropy", "digit_ratio", "vowel_ratio", "consonant_ratio",
    "max_consonant_run", "distinct_chars", "distinct_ratio",
    "english_bigram_score", "label_count", "hex_ratio",
    "transition_ratio", "repeat_ratio", "special_count",
]


def features_to_vector(features):
    """Convert feature dict to numpy array."""
    return np.array([features[col] for col in FEATURE_COLUMNS])


def train_dga_classifier(legitimate_domains, dga_domains, model_type="random_forest"):
    """
    Train a DGA classifier on labeled domain lists.

    Args:
        legitimate_domains: list of known-good domain strings
        dga_domains: list of known DGA domain strings
        model_type: 'random_forest' or 'gradient_boosting'

    Returns:
        trained model, scaler, and evaluation metrics
    """
    if not HAS_SKLEARN:
        print("[ERROR] scikit-learn required: pip install scikit-learn")
        return None, None, None

    # Extract features
    X_legit = []
    X_dga = []

    for d in legitimate_domains:
        feats = extract_domain_features(d)
        if feats:
            X_legit.append(features_to_vector(feats))

    for d in dga_domains:
        feats = extract_domain_features(d)
        if feats:
            X_dga.append(features_to_vector(feats))

    if not X_legit or not X_dga:
        print("[ERROR] Insufficient feature data")
        return None, None, None

    X = np.vstack([np.array(X_legit), np.array(X_dga)])
    y = np.array([0] * len(X_legit) + [1] * len(X_dga))

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train model
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

    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=["legitimate", "dga"],
                                   output_dict=True)
    cm = confusion_matrix(y_test, y_pred)

    # Cross-validation
    cv_scores = cross_val_score(model, X_scaled, y, cv=5, scoring="f1")

    metrics = {
        "accuracy": report["accuracy"],
        "precision_dga": report["dga"]["precision"],
        "recall_dga": report["dga"]["recall"],
        "f1_dga": report["dga"]["f1-score"],
        "precision_legit": report["legitimate"]["precision"],
        "recall_legit": report["legitimate"]["recall"],
        "confusion_matrix": cm.tolist(),
        "cv_f1_mean": cv_scores.mean(),
        "cv_f1_std": cv_scores.std(),
        "feature_importance": dict(zip(
            FEATURE_COLUMNS,
            [round(float(x), 4) for x in model.feature_importances_]
        )),
    }

    print(f"[+] Model trained: {model_type}")
    print(f"    Accuracy:     {metrics['accuracy']:.4f}")
    print(f"    DGA F1:       {metrics['f1_dga']:.4f}")
    print(f"    DGA Recall:   {metrics['recall_dga']:.4f}")
    print(f"    CV F1 (5-fold): {metrics['cv_f1_mean']:.4f} +/- {metrics['cv_f1_std']:.4f}")
    print(f"    Top features: ", end="")
    top_feats = sorted(metrics["feature_importance"].items(), key=lambda x: x[1], reverse=True)[:5]
    print(", ".join(f"{k}={v:.3f}" for k, v in top_feats))

    return model, scaler, metrics


def classify_domains(domains, model, scaler):
    """Classify a list of domains as legitimate or DGA using a trained model."""
    results = []
    for domain in domains:
        feats = extract_domain_features(domain)
        if feats is None:
            continue

        vec = features_to_vector(feats).reshape(1, -1)
        vec_scaled = scaler.transform(vec)

        prediction = model.predict(vec_scaled)[0]
        probability = model.predict_proba(vec_scaled)[0]

        results.append({
            "domain": domain,
            "prediction": "dga" if prediction == 1 else "legitimate",
            "confidence": round(float(max(probability)), 4),
            "dga_probability": round(float(probability[1]), 4),
            "features": feats,
        })

    return results
```

### Step 5: DNS Beaconing Pattern Detection

Identify periodic DNS query patterns indicative of C2 check-ins:

```python
#!/usr/bin/env python3
"""DNS beaconing detection - identifies periodic C2 check-in patterns."""

import math
from collections import defaultdict
from datetime import datetime, timedelta

import numpy as np


def parse_timestamp(ts_str):
    """Parse various timestamp formats to datetime."""
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

    # Try epoch timestamp
    try:
        ts_float = float(ts_str)
        return datetime.utcfromtimestamp(ts_float)
    except (ValueError, OverflowError, OSError):
        pass

    return None


def detect_beaconing(dns_queries, min_queries=10, max_jitter_pct=25,
                     min_interval_sec=10, max_interval_sec=7200):
    """
    Detect DNS beaconing by analyzing inter-query timing intervals.

    Beaconing indicators:
      - Regular inter-query intervals (low standard deviation)
      - Consistent query sizes
      - Single source IP to single domain over extended period
      - Low jitter (variation in timing)

    Args:
        dns_queries: list of dicts with 'src_ip', 'query', 'timestamp'
        min_queries: minimum queries to analyze (default 10)
        max_jitter_pct: maximum coefficient of variation for beacon (default 25%)
        min_interval_sec: minimum beacon interval to detect (default 10s)
        max_interval_sec: maximum beacon interval to detect (default 7200s / 2hr)

    Returns:
        list of detected beacon patterns with confidence scores
    """
    # Group queries by (source IP, base domain)
    groups = defaultdict(list)

    for q in dns_queries:
        src_ip = q.get("src_ip", "")
        fqdn = q.get("query", "").lower().rstrip(".")
        ts_str = q.get("timestamp", "")

        ts = parse_timestamp(ts_str)
        if not ts or not src_ip or not fqdn:
            continue

        # Extract base domain (last 2 labels)
        parts = fqdn.split(".")
        if len(parts) >= 2:
            base_domain = ".".join(parts[-2:])
        else:
            base_domain = fqdn

        groups[(src_ip, base_domain)].append(ts)

    beacons = []

    for (src_ip, base_domain), timestamps in groups.items():
        if len(timestamps) < min_queries:
            continue

        # Sort timestamps and compute intervals
        timestamps.sort()
        intervals = [
            (timestamps[i+1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)
        ]

        if not intervals:
            continue

        intervals = np.array(intervals)

        # Filter out zero intervals (duplicate timestamps)
        intervals = intervals[intervals > 0]
        if len(intervals) < min_queries - 1:
            continue

        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        median_interval = np.median(intervals)

        # Skip if interval is outside detection range
        if mean_interval < min_interval_sec or mean_interval > max_interval_sec:
            continue

        # Coefficient of variation (jitter)
        cv = (std_interval / mean_interval * 100) if mean_interval > 0 else 100

        # Time span of activity
        time_span = (timestamps[-1] - timestamps[0]).total_seconds()
        hours_active = time_span / 3600

        # Beacon scoring
        score = 0.0
        flags = []

        # Low jitter = strong beacon indicator
        if cv < 5:
            score += 40
            flags.append(f"very_low_jitter:CV={cv:.1f}%")
        elif cv < 15:
            score += 30
            flags.append(f"low_jitter:CV={cv:.1f}%")
        elif cv < max_jitter_pct:
            score += 15
            flags.append(f"moderate_jitter:CV={cv:.1f}%")
        else:
            continue  # Too much jitter, not a beacon

        # Long duration increases confidence
        if hours_active > 24:
            score += 20
            flags.append(f"persistent:{hours_active:.1f}h")
        elif hours_active > 4:
            score += 10
            flags.append(f"sustained:{hours_active:.1f}h")

        # High query count increases confidence
        if len(timestamps) > 100:
            score += 15
            flags.append(f"high_volume:{len(timestamps)}")
        elif len(timestamps) > 50:
            score += 10
            flags.append(f"moderate_volume:{len(timestamps)}")

        # Common C2 intervals (60s, 120s, 300s, 600s, 900s, 1800s, 3600s)
        common_intervals = [60, 120, 300, 600, 900, 1800, 3600]
        for ci in common_intervals:
            if abs(mean_interval - ci) < ci * 0.1:  # Within 10% of common interval
                score += 10
                flags.append(f"common_c2_interval:~{ci}s")
                break

        beacons.append({
            "src_ip": src_ip,
            "base_domain": base_domain,
            "query_count": len(timestamps),
            "mean_interval_sec": round(mean_interval, 2),
            "median_interval_sec": round(median_interval, 2),
            "std_interval_sec": round(std_interval, 2),
            "jitter_cv_pct": round(cv, 2),
            "first_seen": timestamps[0].isoformat(),
            "last_seen": timestamps[-1].isoformat(),
            "duration_hours": round(hours_active, 2),
            "score": round(score, 1),
            "flags": flags,
        })

    beacons.sort(key=lambda x: x["score"], reverse=True)
    return beacons


def print_beacon_report(beacons, top_n=20):
    """Print formatted beacon detection report."""
    print("=" * 80)
    print("  DNS BEACONING DETECTION REPORT")
    print("=" * 80)
    print(f"  Beacon patterns detected: {len(beacons)}")
    print()

    if not beacons:
        print("  No beaconing patterns detected.")
        return

    print(f"  TOP {min(top_n, len(beacons))} BEACON CANDIDATES")
    print("  " + "-" * 76)

    for b in beacons[:top_n]:
        print(f"  Score: {b['score']:.1f}  |  {b['src_ip']} -> {b['base_domain']}")
        print(f"    Queries: {b['query_count']}  "
              f"Interval: {b['mean_interval_sec']:.1f}s +/- {b['std_interval_sec']:.1f}s  "
              f"Jitter: {b['jitter_cv_pct']:.1f}%")
        print(f"    Active: {b['duration_hours']:.1f}h  "
              f"({b['first_seen']} to {b['last_seen']})")
        print(f"    Flags: {', '.join(b['flags'])}")
        print()
```

### Step 6: Integrated DNS C2 Detection Pipeline

Combine all detection methods into a unified analysis:

```
DNS C2 Detection Pipeline Architecture:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ┌────────────────────────────────────────────────────────┐
  │                  DATA SOURCES                          │
  │  Zeek dns.log  |  Suricata EVE  |  Recursive Resolver │
  │  Passive DNS   |  PCAP capture  |  EDR DNS telemetry  │
  └───────────────────────┬────────────────────────────────┘
                          │
  ┌───────────────────────▼────────────────────────────────┐
  │              PREPROCESSING                             │
  │  Parse timestamps | Extract subdomains | Normalize     │
  │  FQDN | Resolve base domain | Lookup in whitelist     │
  └───────────────────────┬────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          │               │               │
  ┌───────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
  │  ENTROPY     │ │  BEACONING  │ │  DGA        │
  │  ANALYSIS    │ │  DETECTION  │ │  CLASSIFIER │
  │              │ │             │ │             │
  │ Shannon ent. │ │ Interval    │ │ ML model    │
  │ Subdomain    │ │ analysis    │ │ Random      │
  │ length       │ │ Jitter/CV   │ │ Forest or   │
  │ Encoding     │ │ Duration    │ │ Gradient    │
  │ patterns     │ │ Periodicity │ │ Boosting    │
  └───────┬──────┘ └──────┬──────┘ └──────┬──────┘
          │               │               │
  ┌───────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
  │ TXT RECORD   │ │  TOOL       │ │  PASSIVE    │
  │ PAYLOAD      │ │  SIGNATURE  │ │  DNS        │
  │ ANALYSIS     │ │  MATCHING   │ │  ENRICHMENT │
  │              │ │             │ │             │
  │ Base64 decode│ │ Iodine      │ │ First seen  │
  │ PE/ELF detect│ │ dnscat2     │ │ Registrar   │
  │ PS stager    │ │ dns2tcp     │ │ Age check   │
  │ Size anomaly │ │ Cobalt DNS  │ │ Reputation  │
  └───────┬──────┘ └──────┬──────┘ └──────┬──────┘
          │               │               │
  ┌───────▼───────────────▼───────────────▼────────────────┐
  │                CORRELATION ENGINE                       │
  │  Combine scores from all detectors                     │
  │  Weighted scoring: entropy(30%) + beacon(25%) +        │
  │    DGA(20%) + TXT payload(15%) + signature(10%)        │
  │  Threshold: score > 60 = alert, > 40 = investigate     │
  └───────────────────────┬────────────────────────────────┘
                          │
  ┌───────────────────────▼────────────────────────────────┐
  │                ALERTING & RESPONSE                     │
  │  Generate SIEM alert with all evidence                 │
  │  Block domain in DNS firewall / RPZ                    │
  │  Isolate endpoint via EDR                              │
  │  Create incident ticket with IOCs                      │
  └────────────────────────────────────────────────────────┘
```

### Step 7: SIEM Detection Rules

Deploy detection queries in your SIEM platform:

```
Splunk SPL - DNS Tunneling Detection:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- High entropy subdomain queries
index=dns sourcetype="bro:dns:json" OR sourcetype="suricata:dns"
| eval subdomain=mvindex(split(query,"."),0)
| eval sub_len=len(subdomain)
| where sub_len > 30
| eval char_counts=mvmap(split(subdomain,""),1)
| lookup dns_entropy_lookup subdomain OUTPUT entropy
| where entropy > 3.5
| stats count as query_count dc(query) as unique_queries
    avg(sub_len) as avg_sub_len values(query) as sample_queries
    by src_ip, domain
| where query_count > 20
| sort -query_count

-- DNS TXT record abuse
index=dns (qtype="TXT" OR qtype_name="TXT")
  NOT (query="*._domainkey.*" OR query="*._dmarc.*" OR query="*._spf.*")
| stats count as txt_queries dc(query) as unique_txt_queries
    values(query) as domains
    by src_ip
| where txt_queries > 50
| sort -txt_queries

-- DNS beaconing (regular interval queries)
index=dns sourcetype="bro:dns:json"
| bin _time span=60s
| stats count by src_ip, query, _time
| streamstats window=10 current=t avg(count) as avg_count stdev(count) as std_count by src_ip, query
| eval cv = if(avg_count>0, (std_count/avg_count)*100, 100)
| where cv < 20 AND avg_count > 0
| stats count as beacon_windows avg(cv) as avg_jitter
    min(_time) as first_seen max(_time) as last_seen
    by src_ip, query
| where beacon_windows > 10
| sort -beacon_windows

-- Unusual record type volume (NULL, KEY, SRV for tunneling)
index=dns (qtype_name="NULL" OR qtype_name="KEY" OR qtype_name="SRV"
    OR qtype_name="CNAME" OR qtype_name="MX")
  NOT qtype_name="A" NOT qtype_name="AAAA" NOT qtype_name="PTR"
| stats count by src_ip, qtype_name, query
| where count > 10
| sort -count
```

```
Elastic KQL - DNS C2 Detection:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- Long subdomain queries (potential tunneling)
dns.question.name: * and not dns.question.name: *.in-addr.arpa
| where length(dns.question.subdomain) > 40

-- High volume DNS to single domain
event.dataset: "zeek.dns" or event.dataset: "suricata.dns"
| stats count by source.ip, dns.question.registered_domain
| where count > 500

-- TXT record queries to non-standard domains
dns.question.type: "TXT"
  and not dns.question.name: (*._domainkey.* or *._dmarc.* or *._spf.*)
```

```
Zeek Script - DNS Tunneling Indicator:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# dns_tunnel_detect.zeek
@load base/protocols/dns

module DNSTunnel;

export {
    redef enum Notice::Type += {
        DNS_Tunneling_Suspected,
        DNS_High_Entropy_Query,
        DNS_Excessive_TXT_Queries,
    };

    const entropy_threshold = 3.5 &redef;
    const subdomain_length_threshold = 40 &redef;
    const txt_query_threshold = 50 &redef;
    const tracking_interval = 5min &redef;
}

global txt_query_tracker: table[addr] of count &create_expire=5min &default=0;
global domain_query_tracker: table[addr, string] of count &create_expire=10min &default=0;

function shannon_entropy(s: string): double
{
    local counts: table[string] of count;
    local total = |s|;

    if (total == 0) return 0.0;

    for (i in s)
        {
        local c = s[i];
        if (c !in counts) counts[c] = 0;
        ++counts[c];
        }

    local ent = 0.0;
    for (ch, cnt in counts)
        {
        local p = cnt * 1.0 / total;
        ent -= p * log2(p);
        }

    return ent;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count,
                  qclass: count)
{
    if (|query| == 0) return;

    # Track TXT queries
    if (qtype == 16)  # TXT
    {
        ++txt_query_tracker[c$id$orig_h];
        if (txt_query_tracker[c$id$orig_h] == txt_query_threshold)
        {
            NOTICE([
                $note=DNS_Excessive_TXT_Queries,
                $conn=c,
                $msg=fmt("Host %s made %d TXT queries in tracking window",
                         c$id$orig_h, txt_query_threshold),
                $identifier=cat(c$id$orig_h),
            ]);
        }
    }

    # Extract subdomain and check entropy
    local parts = split_string(query, /\./);
    if (|parts| < 3) return;

    # Subdomain = everything except last two labels
    local subdomain = "";
    local i = 0;
    for (idx in parts)
    {
        if (i < |parts| - 2)
            subdomain += parts[idx];
        ++i;
    }

    if (|subdomain| > subdomain_length_threshold)
    {
        local ent = shannon_entropy(subdomain);
        if (ent > entropy_threshold)
        {
            NOTICE([
                $note=DNS_High_Entropy_Query,
                $conn=c,
                $msg=fmt("High entropy DNS query: entropy=%.2f len=%d query=%s",
                         ent, |subdomain|, query),
                $identifier=cat(c$id$orig_h, query),
            ]);
        }
    }
}
```

### Step 8: Suricata Rules for Known DNS C2 Tools

```
# suricata-dns-c2.rules
# DNS Tunneling and C2 Detection Rules

# Iodine DNS tunnel detection
alert dns any any -> any any (msg:"ET TROJAN Iodine DNS Tunnel Activity - NULL Query"; \
    dns.query; content:"."; pcre:"/^[a-z0-9]{50,}\.[a-z0-9.-]+$/i"; \
    dns_query; content:"|00 0a|"; \
    classtype:trojan-activity; sid:2030001; rev:1;)

# dnscat2 DNS tunnel detection
alert dns any any -> any any (msg:"ET TROJAN dnscat2 DNS Tunnel - Handshake"; \
    dns.query; content:"dnscat."; nocase; fast_pattern; \
    classtype:trojan-activity; sid:2030002; rev:1;)

alert dns any any -> any any (msg:"ET TROJAN dnscat2 DNS Tunnel - Data Channel"; \
    dns.query; pcre:"/^[a-f0-9]{16,}\./i"; \
    dns_query; content:"|00 10|"; \
    classtype:trojan-activity; sid:2030003; rev:1;)

# Cobalt Strike DNS beacon
alert dns any any -> any any (msg:"ET TROJAN Cobalt Strike DNS Beacon - A Record"; \
    dns.query; pcre:"/^[a-f0-9]{12,}\.[a-z0-9.-]+$/i"; \
    threshold:type both, track by_src, count 20, seconds 60; \
    classtype:trojan-activity; sid:2030004; rev:1;)

# Generic DNS tunneling - high volume TXT queries to single domain
alert dns any any -> any any (msg:"ET POLICY Excessive TXT DNS Queries - Possible Tunneling"; \
    dns_query; content:"|00 10|"; \
    threshold:type threshold, track by_src, count 50, seconds 300; \
    classtype:policy-violation; sid:2030005; rev:1;)

# Long subdomain query (generic tunneling indicator)
alert dns any any -> any any (msg:"ET POLICY Unusually Long DNS Subdomain - Possible Tunneling"; \
    dns.query; pcre:"/^[a-z0-9-]{52,}\./i"; \
    threshold:type limit, track by_src, count 1, seconds 60; \
    classtype:policy-violation; sid:2030006; rev:1;)

# DNS query for known C2 TXT payload staging
alert dns any any -> any any (msg:"ET TROJAN DNS TXT Record Staged Payload Request"; \
    dns_query; content:"|00 10|"; \
    dns.query; pcre:"/^(stage|payload|cmd|exec|download|update|config)\d*\./i"; \
    classtype:trojan-activity; sid:2030007; rev:1;)
```

## Key Concepts

| Term | Definition |
|------|------------|
| **DNS Tunneling** | Technique of encoding data within DNS queries and responses to create a covert communication channel, bypassing firewalls that allow DNS traffic |
| **Shannon Entropy** | Information theory metric measuring randomness in a string; legitimate domains typically have entropy below 3.5, while encoded tunnel data exceeds 3.8-4.5 |
| **Domain Generation Algorithm (DGA)** | Malware technique that algorithmically generates thousands of pseudo-random domain names for C2 rendezvous, making domain-based blocking impractical |
| **DNS Beaconing** | Regular, periodic DNS queries from a compromised host to a C2 domain, identifiable by consistent inter-query intervals and low timing jitter |
| **TXT Record Abuse** | Using DNS TXT records to deliver encoded C2 commands or staged payloads, exploiting the large payload capacity (up to 65535 bytes across multiple strings) |
| **Iodine** | Open-source DNS tunneling tool that tunnels IPv4 traffic through DNS using NULL, TXT, or CNAME records, commonly used to bypass captive portals |
| **dnscat2** | Encrypted C2 tool that creates a command channel over DNS, supporting file transfer, port forwarding, and shell access through DNS queries |
| **Cobalt Strike DNS Beacon** | Commercial C2 framework's DNS communication mode that uses A, AAAA, and TXT records to receive tasks and return results via DNS resolution |
| **Passive DNS (pDNS)** | Database of historical DNS resolution data collected by monitoring DNS traffic; used to identify infrastructure reuse and domain history |
| **Response Policy Zone (RPZ)** | DNS firewall mechanism that allows real-time blocking of malicious domains by injecting override responses at the recursive resolver level |
| **Coefficient of Variation** | Standard deviation divided by mean, expressed as percentage; used to measure beacon jitter -- lower CV indicates more regular (suspicious) timing |
| **NXDOMAIN** | DNS response code indicating the queried domain does not exist; high NXDOMAIN rates from a host suggest DGA activity where most generated domains are unregistered |

## Tools & Systems

- **Zeek (Bro)**: Network security monitor that produces structured dns.log with query/response details for offline analysis
- **Suricata**: IDS/IPS with DNS protocol parsing and signature-based detection of tunneling patterns
- **tshark/Wireshark**: Packet capture and analysis tools for deep DNS protocol inspection
- **tldextract**: Python library for accurate domain/subdomain extraction using the Public Suffix List
- **dnspython**: Python DNS toolkit for programmatic query resolution and record parsing
- **scikit-learn**: ML library used to train DGA classifiers (Random Forest, Gradient Boosting)
- **Farsight DNSDB / CIRCL pDNS**: Passive DNS databases for historical domain resolution lookups
- **DNS Response Policy Zone (RPZ)**: Recursive resolver feature for real-time DNS blocking of identified C2 domains
- **Splunk / Elastic**: SIEM platforms for DNS log aggregation, entropy calculation, and beacon detection queries

## Common Scenarios

### Scenario: Investigating Suspected DNS Tunneling from an Internal Host

**Context**: The SOC receives an alert from the DNS firewall showing a single internal host (10.1.5.42) making 15,000+ DNS queries to the domain `c8a3f1e2.tunnelsvc.example.com` in the past hour. All queries are TXT type with long, random-looking subdomains. Normal DNS volume for this host is ~200 queries/hour.

**Approach**:
1. Extract all DNS queries from 10.1.5.42 for the past 24 hours from Zeek dns.log
2. Run entropy analysis on subdomain strings -- expect Shannon entropy > 4.0 for encoded tunnel data
3. Check query timing intervals for beaconing pattern (likely sub-second for active tunnel)
4. Examine TXT record responses for size anomalies (tunnel tools use maximum-size TXT responses)
5. Compare subdomain patterns against known tool signatures (Iodine, dnscat2, dns2tcp)
6. Query passive DNS for `tunnelsvc.example.com` registration date, nameserver, and historical resolutions
7. If confirmed, add domain to DNS RPZ blocklist and isolate endpoint via EDR
8. Capture full packet trace for forensic analysis of tunnel payload content

**Pitfalls**:
- Blocking the domain before capturing evidence (need packet captures for forensics)
- Assuming all high-entropy DNS is malicious (CDN subdomains like Akamai can have high entropy)
- Not checking for multiple tunnel domains (attacker may have fallback C2 channels)
- Missing the initial compromise vector by focusing only on the DNS channel
- Not checking other hosts for similar patterns (lateral movement may have already occurred)

### Scenario: Building a DGA Detection Model for SOC Deployment

**Context**: The threat intelligence team identified that a botnet family active in the industry uses DGA for C2 domain generation. The SOC needs an automated way to classify DNS queries as potentially DGA-generated and alert on matches.

**Approach**:
1. Collect training data: Tranco/Alexa top 1M for legitimate domains, DGArchive or OSINT feeds for known DGA domains
2. Extract character-level features: entropy, length, digit ratio, consonant sequences, bigram scores
3. Train Random Forest and Gradient Boosting classifiers, evaluate with 5-fold cross-validation
4. Deploy the model as a scoring enrichment in the SIEM (Splunk ML Toolkit or Elastic ML)
5. Set threshold: DGA probability > 0.85 generates alert, > 0.65 generates investigation ticket
6. Create a whitelist of known high-entropy legitimate domains (CDNs, cloud services) to reduce false positives
7. Retrain monthly with new DGA samples from threat intel feeds

**Pitfalls**:
- Training only on one DGA family and missing others (dictionary-based DGAs like Suppobox have low entropy)
- Not whitelisting CDN and cloud service domains that have randomized subdomains
- Setting the threshold too low, overwhelming the SOC with false positives
- Not accounting for punycode/internationalized domain names in feature extraction
- Deploying without a feedback loop for analysts to flag false positives for model retraining

## Output Format

```
DNS C2 DETECTION ANALYSIS REPORT
====================================
Analysis Period: 2026-03-15 00:00 to 2026-03-19 23:59
Data Source:     Zeek dns.log (gateway sensor)
Total Queries:   14,283,501
Unique Domains:  892,041
Hosts Analyzed:  3,847

ENTROPY ANALYSIS
Queries with entropy > 3.5:       2,847 (0.02%)
Queries with subdomain > 40 chars: 1,203 (0.008%)
Suspicious base domains:           12

  [CRITICAL] tunnelsvc.example[.]com
    Queries: 15,247  Source: 10.1.5.42  Avg Entropy: 4.21
    Avg Subdomain Length: 63  Record Types: TXT (98%), A (2%)
    Tool Signature: dnscat2 (hex prefix pattern match)

  [HIGH] update-cdn.malicious[.]net
    Queries: 3,891  Source: 10.1.12.7  Avg Entropy: 3.87
    Avg Subdomain Length: 48  Record Types: A (60%), TXT (40%)
    Tool Signature: Cobalt Strike DNS beacon (interval pattern)

BEACONING DETECTION
Beacon patterns detected:          4

  Score: 85.0  10.1.5.42 -> tunnelsvc.example[.]com
    Interval: 0.5s +/- 0.1s  Jitter: 8.2%  Duration: 18.4h
    Queries: 15,247  Flags: very_low_jitter, persistent, high_volume

  Score: 72.0  10.1.12.7 -> update-cdn.malicious[.]net
    Interval: 60.2s +/- 3.1s  Jitter: 5.1%  Duration: 72.1h
    Queries: 3,891  Flags: very_low_jitter, persistent, common_c2_interval:~60s

DGA CLASSIFICATION
Domains classified:                892,041
DGA predictions (>0.85 conf):      47
DGA predictions (0.65-0.85):       183

  [HIGH] a8f3k2m1x9.com  (DGA prob: 0.97, entropy: 3.92)
  [HIGH] j7t2p5q8w3.net  (DGA prob: 0.95, entropy: 4.01)
  [HIGH] m3x8k1f6y2.org  (DGA prob: 0.94, entropy: 3.88)

TXT RECORD ANALYSIS
Suspicious TXT responses:          8
Base64 payloads detected:          3
PowerShell stager patterns:        1

  [CRITICAL] cmd.staging[.]example.com
    TXT Length: 4,096  Entropy: 5.82
    Finding: Base64-encoded PowerShell stager with IEX pattern

RECOMMENDED ACTIONS
[CRITICAL] Block tunnelsvc.example[.]com and update-cdn.malicious[.]net in DNS RPZ
[CRITICAL] Isolate hosts 10.1.5.42 and 10.1.12.7 for forensic investigation
[HIGH]     Block 47 high-confidence DGA domains in DNS firewall
[HIGH]     Investigate cmd.staging[.]example.com TXT payload staging
[MEDIUM]   Review 183 moderate-confidence DGA domains with threat intel
[MEDIUM]   Deploy Suricata rules for dnscat2 and Cobalt Strike DNS signatures
```
