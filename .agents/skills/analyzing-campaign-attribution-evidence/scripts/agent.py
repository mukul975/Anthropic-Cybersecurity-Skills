#!/usr/bin/env python3
"""Campaign attribution analysis agent using Diamond Model and ACH methodology.

Evaluates attribution evidence including infrastructure overlaps, TTP consistency,
malware code similarity, timing patterns, and language artifacts.
"""

import json
import os
import sys
import hashlib
import re
from collections import defaultdict
from datetime import datetime


DIAMOND_DIMENSIONS = {
    "adversary": "Threat actor identity, group attribution",
    "capability": "Malware, exploits, tools used",
    "infrastructure": "C2 servers, domains, IP addresses",
    "victim": "Targeted sectors, regions, organizations",
}

EVIDENCE_WEIGHTS = {
    "infrastructure_overlap": 0.25,
    "ttp_consistency": 0.30,
    "malware_code_similarity": 0.25,
    "timing_pattern": 0.10,
    "language_artifact": 0.10,
}

CONFIDENCE_LEVELS = {
    (0.8, 1.0): "HIGH - Strong attribution confidence",
    (0.5, 0.8): "MEDIUM - Moderate attribution, further analysis recommended",
    (0.2, 0.5): "LOW - Weak attribution, insufficient evidence",
    (0.0, 0.2): "NEGLIGIBLE - No meaningful attribution possible",
}


def diamond_model_analysis(adversary=None, capability=None, infrastructure=None, victim=None):
    """Structure evidence using the Diamond Model of Intrusion Analysis."""
    model = {
        "adversary": {
            "identified": adversary is not None,
            "details": adversary or "Unknown",
        },
        "capability": {
            "tools": capability.get("tools", []) if capability else [],
            "exploits": capability.get("exploits", []) if capability else [],
            "malware": capability.get("malware", []) if capability else [],
        },
        "infrastructure": {
            "c2_servers": infrastructure.get("c2", []) if infrastructure else [],
            "domains": infrastructure.get("domains", []) if infrastructure else [],
            "ip_addresses": infrastructure.get("ips", []) if infrastructure else [],
        },
        "victim": {
            "sectors": victim.get("sectors", []) if victim else [],
            "regions": victim.get("regions", []) if victim else [],
        },
        "pivot_opportunities": [],
    }
    if infrastructure and infrastructure.get("c2"):
        model["pivot_opportunities"].append("Pivot from C2 infrastructure to related campaigns")
    if capability and capability.get("malware"):
        model["pivot_opportunities"].append("Pivot from malware samples to shared infrastructure")
    return model


def evaluate_infrastructure_overlap(campaign_infra, known_actor_infra):
    """Score infrastructure overlap between campaign and known actor."""
    campaign_set = set(campaign_infra)
    known_set = set(known_actor_infra)
    if not campaign_set or not known_set:
        return 0.0, []
    overlap = campaign_set & known_set
    score = len(overlap) / max(len(campaign_set), len(known_set))
    return round(score, 4), sorted(overlap)


def evaluate_ttp_consistency(campaign_ttps, actor_ttps):
    """Score TTP consistency using MITRE ATT&CK technique overlap."""
    campaign_set = set(campaign_ttps)
    actor_set = set(actor_ttps)
    if not campaign_set or not actor_set:
        return 0.0, []
    overlap = campaign_set & actor_set
    jaccard = len(overlap) / len(campaign_set | actor_set)
    return round(jaccard, 4), sorted(overlap)


def evaluate_malware_similarity(sample_features, known_features):
    """Score malware code similarity based on feature comparison."""
    if not sample_features or not known_features:
        return 0.0
    matches = 0
    total = max(len(sample_features), len(known_features))
    for feature in sample_features:
        if feature in known_features:
            matches += 1
    return round(matches / total, 4) if total > 0 else 0.0


def evaluate_timing_pattern(campaign_timestamps, actor_timezone_offset=None):
    """Analyze operational timing to infer timezone/working hours."""
    if not campaign_timestamps:
        return {"score": 0.0, "working_hours": None, "timezone_guess": None}
    hours = []
    for ts in campaign_timestamps:
        try:
            if isinstance(ts, str):
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            else:
                dt = ts
            adjusted = dt.hour + (actor_timezone_offset or 0)
            hours.append(adjusted % 24)
        except (ValueError, TypeError):
            continue
    if not hours:
        return {"score": 0.0}
    work_hours = sum(1 for h in hours if 8 <= h <= 18)
    work_ratio = work_hours / len(hours)
    avg_hour = sum(hours) / len(hours)
    return {
        "score": round(work_ratio, 4),
        "average_hour_utc": round(avg_hour, 1),
        "work_hour_ratio": round(work_ratio, 4),
        "sample_size": len(hours),
    }


def evaluate_language_artifacts(strings_list):
    """Detect language artifacts in malware strings or documents."""
    language_indicators = {
        "Russian": [r"[а-яА-Я]{3,}", r"codepage.*1251", r"locale.*ru"],
        "Chinese": [r"[\u4e00-\u9fff]{2,}", r"codepage.*936", r"GB2312"],
        "Korean": [r"[\uac00-\ud7af]{2,}", r"codepage.*949", r"EUC-KR"],
        "Farsi": [r"[\u0600-\u06ff]{3,}", r"codepage.*1256"],
        "English": [r"\b(the|and|for|with)\b"],
    }
    detections = defaultdict(int)
    for s in strings_list:
        for lang, patterns in language_indicators.items():
            for pattern in patterns:
                if re.search(pattern, s, re.IGNORECASE):
                    detections[lang] += 1
    total = sum(detections.values()) or 1
    scored = {lang: round(count / total, 4) for lang, count in detections.items()}
    return scored


def ach_analysis(hypotheses, evidence_items):
    """Analysis of Competing Hypotheses (ACH) for attribution."""
    matrix = {}
    for hyp in hypotheses:
        hyp_name = hyp["name"]
        matrix[hyp_name] = {"consistent": 0, "inconsistent": 0, "neutral": 0, "score": 0}
        for evidence in evidence_items:
            ev_name = evidence["name"]
            consistency = evidence.get("hypotheses", {}).get(hyp_name, "neutral")
            if consistency == "consistent":
                matrix[hyp_name]["consistent"] += evidence.get("weight", 1)
            elif consistency == "inconsistent":
                matrix[hyp_name]["inconsistent"] += evidence.get("weight", 1)
            else:
                matrix[hyp_name]["neutral"] += evidence.get("weight", 1)
        c = matrix[hyp_name]["consistent"]
        i = matrix[hyp_name]["inconsistent"]
        matrix[hyp_name]["score"] = round((c - i) / (c + i + 0.01), 4)
    return matrix


def compute_attribution_score(scores):
    """Compute weighted attribution confidence score."""
    total = 0.0
    for evidence_type, weight in EVIDENCE_WEIGHTS.items():
        score = scores.get(evidence_type, 0.0)
        total += score * weight
    confidence = "UNKNOWN"
    for (low, high), label in CONFIDENCE_LEVELS.items():
        if low <= total < high:
            confidence = label
            break
    return round(total, 4), confidence


def generate_attribution_report(campaign_name, candidate_actor, evidence):
    """Generate structured attribution assessment report."""
    scores = {}
    details = {}

    infra_score, infra_overlap = evaluate_infrastructure_overlap(
        evidence.get("campaign_infra", []), evidence.get("actor_infra", []))
    scores["infrastructure_overlap"] = infra_score
    details["infrastructure_overlap"] = infra_overlap

    ttp_score, ttp_overlap = evaluate_ttp_consistency(
        evidence.get("campaign_ttps", []), evidence.get("actor_ttps", []))
    scores["ttp_consistency"] = ttp_score
    details["ttp_consistency"] = ttp_overlap

    malware_score = evaluate_malware_similarity(
        evidence.get("sample_features", []), evidence.get("known_features", []))
    scores["malware_code_similarity"] = malware_score

    timing = evaluate_timing_pattern(
        evidence.get("timestamps", []), evidence.get("tz_offset"))
    scores["timing_pattern"] = timing.get("score", 0.0)
    details["timing"] = timing

    lang = evaluate_language_artifacts(evidence.get("strings", []))
    scores["language_artifact"] = max(lang.values()) if lang else 0.0
    details["language_artifacts"] = lang

    total_score, confidence = compute_attribution_score(scores)

    return {
        "campaign": campaign_name,
        "candidate_actor": candidate_actor,
        "attribution_score": total_score,
        "confidence_level": confidence,
        "evidence_scores": scores,
        "evidence_details": details,
    }


if __name__ == "__main__":
    print("=" * 60)
    print("Campaign Attribution Evidence Analysis Agent")
    print("Diamond Model, ACH, TTP/infrastructure/malware scoring")
    print("=" * 60)

    demo_evidence = {
        "campaign_infra": ["185.220.101.1", "evil-domain.com", "c2.attacker.net"],
        "actor_infra": ["185.220.101.1", "c2.attacker.net", "other-domain.org"],
        "campaign_ttps": ["T1566.001", "T1059.001", "T1053.005", "T1071.001", "T1041"],
        "actor_ttps": ["T1566.001", "T1059.001", "T1053.005", "T1071.001", "T1021.001", "T1003.001"],
        "sample_features": ["xor_0x55", "mutex_Global\\QWE", "ua_Mozilla5", "rc4_key"],
        "known_features": ["xor_0x55", "mutex_Global\\QWE", "ua_Mozilla5", "aes_cbc"],
        "timestamps": ["2024-03-15T06:30:00Z", "2024-03-15T07:15:00Z",
                        "2024-03-16T08:00:00Z", "2024-03-16T09:45:00Z"],
        "tz_offset": 3,
        "strings": ["Привет мир", "connect to server", "upload file"],
    }

    report = generate_attribution_report("Operation DarkShadow", "APT29", demo_evidence)

    print(f"\n[*] Campaign: {report['campaign']}")
    print(f"[*] Candidate: {report['candidate_actor']}")
    print(f"[*] Attribution Score: {report['attribution_score']}")
    print(f"[*] Confidence: {report['confidence_level']}")
    print("\n--- Evidence Scores ---")
    for ev, score in report["evidence_scores"].items():
        weight = EVIDENCE_WEIGHTS.get(ev, 0)
        print(f"  {ev:30s} score={score:.4f}  weight={weight}")
    print(f"\n[*] Full report:\n{json.dumps(report, indent=2, default=str)}")
