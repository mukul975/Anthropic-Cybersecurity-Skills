# DNS C2 Detection Scripts

Full analysis scripts referenced from `SKILL.md` Steps 2-5. Each is standalone Python 3.9+.

## Step 2: Shannon Entropy Analysis of DNS Queries

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

## Step 3: TXT Record Payload Detection

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

## Step 4: DGA Domain Classification with Machine Learning

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

## Step 5: DNS Beaconing Pattern Detection

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
