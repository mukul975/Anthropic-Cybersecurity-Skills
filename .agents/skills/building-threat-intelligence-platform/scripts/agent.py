#!/usr/bin/env python3
"""Threat intelligence platform builder.

Core TIP components: STIX/TAXII ingestion, indicator lifecycle management,
confidence scoring, sharing groups, and intelligence dissemination.
"""

import sys
import json
import datetime
import hashlib
import re
import uuid


STIX_INDICATOR_TYPES = {
    "ipv4-addr": "[ipv4-addr:value = '{}']",
    "domain-name": "[domain-name:value = '{}']",
    "url": "[url:value = '{}']",
    "file-sha256": "[file:hashes.'SHA-256' = '{}']",
    "file-md5": "[file:hashes.MD5 = '{}']",
    "email-addr": "[email-addr:value = '{}']",
}

TLP_DEFINITIONS = {
    "TLP:CLEAR": {"color": "white", "sharing": "Unlimited", "code": 0},
    "TLP:GREEN": {"color": "green", "sharing": "Community", "code": 1},
    "TLP:AMBER": {"color": "amber", "sharing": "Organization", "code": 2},
    "TLP:AMBER+STRICT": {"color": "amber", "sharing": "Need-to-know only", "code": 3},
    "TLP:RED": {"color": "red", "sharing": "Named recipients only", "code": 4},
}


def classify_indicator(value):
    """Classify indicator type from raw value."""
    if re.match(r"^[0-9]{1,3}(\\.[0-9]{1,3}){3}$", value):
        return "ipv4-addr"
    if re.match(r"^[a-fA-F0-9]{64}$", value):
        return "file-sha256"
    if re.match(r"^[a-fA-F0-9]{32}$", value):
        return "file-md5"
    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", value):
        return "domain-name"
    if value.startswith("http://") or value.startswith("https://"):
        return "url"
    if "@" in value:
        return "email-addr"
    return "unknown"


def create_stix_indicator(value, indicator_type=None, confidence=50, tlp="TLP:AMBER"):
    """Create a STIX 2.1 Indicator object."""
    if not indicator_type:
        indicator_type = classify_indicator(value)
    pattern_template = STIX_INDICATOR_TYPES.get(indicator_type)
    if not pattern_template:
        return {"error": "Unsupported indicator type: " + indicator_type}

    now = datetime.datetime.utcnow().isoformat(timespec="milliseconds") + "Z"
    indicator_id = "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_URL, value))

    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": now,
        "modified": now,
        "name": "{}: {}".format(indicator_type, value),
        "pattern": pattern_template.format(value),
        "pattern_type": "stix",
        "valid_from": now,
        "confidence": confidence,
        "labels": ["malicious-activity"],
        "object_marking_refs": [tlp_to_marking_ref(tlp)],
    }
    return indicator


def tlp_to_marking_ref(tlp):
    """Convert TLP label to STIX marking definition ID."""
    tlp_refs = {
        "TLP:CLEAR": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "TLP:AMBER+STRICT": "marking-definition--826578e1-40a3-4b46-a8d8-b9931fdd750e",
        "TLP:RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
    }
    return tlp_refs.get(tlp, tlp_refs["TLP:AMBER"])


def calculate_indicator_score(sources_count, age_days, confirmed_sightings, false_positives):
    """Calculate indicator confidence score (0-100)."""
    source_score = min(sources_count * 15, 40)
    age_penalty = min(age_days * 0.5, 30)
    sighting_score = min(confirmed_sightings * 10, 30)
    fp_penalty = min(false_positives * 15, 30)
    score = source_score - age_penalty + sighting_score - fp_penalty
    return max(0, min(100, round(score)))


def build_stix_bundle(indicators):
    """Build STIX 2.1 Bundle from list of indicators."""
    bundle = {
        "type": "bundle",
        "id": "bundle--" + str(uuid.uuid4()),
        "objects": indicators,
    }
    return bundle


def generate_tip_report(indicators, platform_name="Internal TIP"):
    """Generate TIP status report."""
    type_counts = {}
    for ind in indicators:
        itype = ind.get("name", "").split(":")[0] if ":" in ind.get("name", "") else "unknown"
        type_counts[itype] = type_counts.get(itype, 0) + 1

    return {
        "platform": platform_name,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "total_indicators": len(indicators),
        "type_breakdown": type_counts,
        "avg_confidence": round(
            sum(i.get("confidence", 0) for i in indicators) / max(len(indicators), 1), 1
        ),
    }


if __name__ == "__main__":
    print("=" * 60)
    print("Threat Intelligence Platform Builder")
    print("STIX 2.1 indicators, scoring, TLP marking, bundle export")
    print("=" * 60)

    demo_values = [
        "198.51.100.42",
        "evil-domain.example.com",
        "a" * 64,
        "https://evil.example.com/payload.exe",
        "attacker@evil.example.com",
    ]

    indicators = []
    for val in demo_values:
        ind = create_stix_indicator(val, confidence=75, tlp="TLP:AMBER")
        if "error" not in ind:
            indicators.append(ind)

    print("\n--- Indicators Created ---")
    for ind in indicators:
        print("  {} [confidence={}]".format(ind["name"], ind["confidence"]))
        print("    Pattern: {}".format(ind["pattern"]))

    bundle = build_stix_bundle(indicators)
    print("\nSTIX Bundle: {} ({} objects)".format(bundle["id"], len(bundle["objects"])))

    score = calculate_indicator_score(sources_count=3, age_days=5, confirmed_sightings=2, false_positives=0)
    print("\nSample score calculation: {}".format(score))

    report = generate_tip_report(indicators)
    print("\n--- Platform Report ---")
    for k, v in report.items():
        print("  {}: {}".format(k, v))

    print("\n" + json.dumps({"indicators_created": len(indicators)}, indent=2))
