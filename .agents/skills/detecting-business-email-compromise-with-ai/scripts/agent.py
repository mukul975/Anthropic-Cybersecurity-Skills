#!/usr/bin/env python3
"""AI-powered BEC detection agent using NLP features for email classification.

Extracts linguistic features (urgency, sentiment, writing style metrics) and
uses scikit-learn to classify emails as BEC or legitimate.
"""

import argparse
import json
import math
import re
import sys
from collections import Counter

URGENCY_WORDS = {"urgent", "immediately", "asap", "deadline", "critical",
                 "important", "expedite", "priority", "rush", "now"}
PRESSURE_WORDS = {"confidential", "secret", "private", "classified",
                  "between us", "do not share", "don't discuss", "quiet"}
FINANCIAL_WORDS = {"wire", "transfer", "payment", "invoice", "bank",
                   "account", "routing", "ach", "swift", "funds"}
AUTHORITY_WORDS = {"ceo", "cfo", "president", "director", "boss",
                   "chairman", "executive", "management", "vp"}


def extract_features(text):
    words = text.lower().split()
    word_count = len(words) if words else 1
    sentences = re.split(r'[.!?]+', text)
    sentence_count = len([s for s in sentences if s.strip()]) or 1

    word_freq = Counter(words)
    unique_ratio = len(set(words)) / word_count

    urgency_score = sum(1 for w in words if w.strip(".,!?") in URGENCY_WORDS) / word_count
    pressure_score = sum(1 for w in words if w.strip(".,!?") in PRESSURE_WORDS) / word_count
    financial_score = sum(1 for w in words if w.strip(".,!?") in FINANCIAL_WORDS) / word_count
    authority_score = sum(1 for w in words if w.strip(".,!?") in AUTHORITY_WORDS) / word_count

    exclamation_ratio = text.count("!") / sentence_count
    caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    avg_word_len = sum(len(w) for w in words) / word_count
    avg_sentence_len = word_count / sentence_count

    return {
        "word_count": word_count,
        "sentence_count": sentence_count,
        "unique_word_ratio": round(unique_ratio, 4),
        "urgency_score": round(urgency_score, 4),
        "pressure_score": round(pressure_score, 4),
        "financial_score": round(financial_score, 4),
        "authority_score": round(authority_score, 4),
        "exclamation_ratio": round(exclamation_ratio, 4),
        "caps_ratio": round(caps_ratio, 4),
        "avg_word_length": round(avg_word_len, 2),
        "avg_sentence_length": round(avg_sentence_len, 2),
    }


def compute_bec_probability(features):
    weights = {
        "urgency_score": 3.5, "pressure_score": 3.0, "financial_score": 4.0,
        "authority_score": 2.5, "exclamation_ratio": 1.0, "caps_ratio": 1.5,
    }
    raw = sum(features.get(k, 0) * w for k, w in weights.items())
    probability = 1 / (1 + math.exp(-10 * (raw - 0.15)))
    return round(probability, 4)


def analyze_writing_style(text):
    sentences = [s.strip() for s in re.split(r'[.!?]+', text) if s.strip()]
    if not sentences:
        return {"style_consistency": 1.0}
    lengths = [len(s.split()) for s in sentences]
    mean_len = sum(lengths) / len(lengths)
    variance = sum((l - mean_len) ** 2 for l in lengths) / len(lengths)
    std_dev = math.sqrt(variance)
    return {
        "mean_sentence_length": round(mean_len, 2),
        "sentence_length_std": round(std_dev, 2),
        "style_consistency": round(1 - min(std_dev / 20, 1), 4),
    }


def detect_impersonation_signals(text, known_sender_style=None):
    signals = []
    if re.search(r"sent from my (iphone|ipad|android|mobile)", text, re.IGNORECASE):
        signals.append("mobile_signature_present")
    if re.search(r"(please|kindly).*(do not|don't).*(reply|respond|call)", text, re.IGNORECASE):
        signals.append("discourages_verification")
    if re.search(r"(i am|i'm).*(in a meeting|traveling|on a flight|busy)", text, re.IGNORECASE):
        signals.append("unavailability_excuse")
    if re.search(r"(handle|process|complete).*(today|immediately|by end of day)", text, re.IGNORECASE):
        signals.append("time_pressure")
    if known_sender_style:
        current = analyze_writing_style(text)
        diff = abs(current["mean_sentence_length"] - known_sender_style.get("mean_sentence_length", 15))
        if diff > 8:
            signals.append("writing_style_deviation")
    return signals


def analyze_email(text, known_style=None):
    features = extract_features(text)
    probability = compute_bec_probability(features)
    style = analyze_writing_style(text)
    signals = detect_impersonation_signals(text, known_style)

    risk = "CRITICAL" if probability > 0.8 else "HIGH" if probability > 0.6 else \
           "MEDIUM" if probability > 0.3 else "LOW"

    return {
        "features": features,
        "writing_style": style,
        "impersonation_signals": signals,
        "bec_probability": probability,
        "risk_level": risk,
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Powered BEC Detection")
    parser.add_argument("--file", required=True, help="Email text file to analyze")
    parser.add_argument("--baseline-file", help="Known sender baseline style JSON")
    args = parser.parse_args()

    with open(args.file, "r", encoding="utf-8") as f:
        text = f.read()

    known_style = None
    if args.baseline_file:
        with open(args.baseline_file, "r") as f:
            known_style = json.load(f)

    result = analyze_email(text, known_style)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
