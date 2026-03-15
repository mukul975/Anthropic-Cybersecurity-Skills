#!/usr/bin/env python3
"""MISP Threat Intelligence Sharing agent - creates events, manages attributes, searches IOCs, and validates sharing configuration via PyMISP"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

try:
    from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPTag
    HAS_PYMISP = True
except ImportError:
    HAS_PYMISP = False

MISP_ATTRIBUTE_TYPES = {
    "ip-dst", "ip-src", "domain", "hostname", "url", "md5", "sha1",
    "sha256", "filename", "email-src", "email-dst", "mutex", "regkey",
    "user-agent", "vulnerability", "link", "text", "comment",
}

TLP_TAGS = {
    "white": "tlp:white",
    "green": "tlp:green",
    "amber": "tlp:amber",
    "amber+strict": "tlp:amber+strict",
    "red": "tlp:red",
}


def load_data(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def connect_misp(url, api_key, ssl=True):
    """Initialize PyMISP connection."""
    if not HAS_PYMISP:
        return None, "pymisp not installed (pip install pymisp)"
    misp = PyMISP(url, api_key, ssl=ssl)
    return misp, "connected"


def create_event_from_data(misp, event_data):
    """Create a MISP event with attributes and tags."""
    event = MISPEvent()
    event.info = event_data.get("info", "Untitled Event")
    event.distribution = event_data.get("distribution", 1)  # 0=org, 1=community, 2=connected, 3=all
    event.threat_level_id = event_data.get("threat_level", 2)  # 1=high, 2=medium, 3=low, 4=undefined
    event.analysis = event_data.get("analysis", 0)  # 0=initial, 1=ongoing, 2=complete
    for attr in event_data.get("attributes", []):
        attr_type = attr.get("type", "text")
        value = attr.get("value", "")
        category = attr.get("category", "")
        to_ids = attr.get("to_ids", True)
        comment = attr.get("comment", "")
        if attr_type in MISP_ATTRIBUTE_TYPES and value:
            event.add_attribute(type=attr_type, value=value, category=category,
                                to_ids=to_ids, comment=comment)
    for tag_name in event_data.get("tags", []):
        event.add_tag(tag_name)
    tlp = event_data.get("tlp", "").lower()
    if tlp in TLP_TAGS:
        event.add_tag(TLP_TAGS[tlp])
    if misp:
        result = misp.add_event(event)
        return result
    return event.to_dict()


def validate_event_quality(event_data):
    """Validate event data quality for sharing readiness."""
    findings = []
    eid = event_data.get("id", event_data.get("info", "unknown"))
    if not event_data.get("info"):
        findings.append({
            "type": "missing_event_info",
            "severity": "high",
            "resource": str(eid),
            "detail": "Event lacks descriptive info/title",
        })
    attrs = event_data.get("attributes", event_data.get("Attribute", []))
    if not attrs:
        findings.append({
            "type": "no_attributes",
            "severity": "high",
            "resource": str(eid),
            "detail": "Event has no IOC attributes",
        })
    attr_types = Counter(a.get("type", "unknown") for a in attrs)
    if len(attr_types) == 1 and len(attrs) > 1:
        findings.append({
            "type": "single_attribute_type",
            "severity": "low",
            "resource": str(eid),
            "detail": f"All {len(attrs)} attributes are type '{list(attr_types.keys())[0]}' - consider enriching",
        })
    tags = event_data.get("tags", event_data.get("Tag", []))
    tag_names = [t.get("name", t) if isinstance(t, dict) else t for t in tags]
    has_tlp = any("tlp:" in t.lower() for t in tag_names)
    if not has_tlp:
        findings.append({
            "type": "missing_tlp_tag",
            "severity": "high",
            "resource": str(eid),
            "detail": "Event lacks TLP classification tag",
        })
    has_mitre = any("mitre-attack" in t.lower() or "attack-pattern" in t.lower() for t in tag_names)
    if not has_mitre and len(attrs) > 0:
        findings.append({
            "type": "missing_mitre_mapping",
            "severity": "medium",
            "resource": str(eid),
            "detail": "Event lacks MITRE ATT&CK technique mapping",
        })
    dist = event_data.get("distribution", -1)
    if dist == 3:
        findings.append({
            "type": "unrestricted_distribution",
            "severity": "medium",
            "resource": str(eid),
            "detail": "Event set to 'All communities' distribution - verify this is intentional",
        })
    for attr in attrs:
        val = attr.get("value", "")
        atype = attr.get("type", "")
        if atype in ("ip-dst", "ip-src") and val in ("127.0.0.1", "0.0.0.0", "10.0.0.1", "192.168.1.1"):
            findings.append({
                "type": "private_ip_ioc",
                "severity": "high",
                "resource": str(eid),
                "detail": f"Private/localhost IP '{val}' used as IOC - will generate false positives",
            })
        if atype in ("md5", "sha1", "sha256") and len(val) < 32:
            findings.append({
                "type": "invalid_hash_length",
                "severity": "high",
                "resource": str(eid),
                "detail": f"Hash attribute '{val}' is too short for type {atype}",
            })
    return findings


def validate_sharing_config(config):
    """Validate MISP sharing and feed configuration."""
    findings = []
    servers = config.get("sync_servers", [])
    if not servers:
        findings.append({
            "type": "no_sync_servers",
            "severity": "medium",
            "resource": "misp_config",
            "detail": "No synchronization servers configured for intelligence sharing",
        })
    for srv in servers:
        if not srv.get("pull", False) and not srv.get("push", False):
            findings.append({
                "type": "inactive_sync_server",
                "severity": "medium",
                "resource": srv.get("name", srv.get("url", "")),
                "detail": "Sync server has neither pull nor push enabled",
            })
    feeds = config.get("feeds", [])
    enabled_feeds = [f for f in feeds if f.get("enabled", False)]
    if not enabled_feeds:
        findings.append({
            "type": "no_active_feeds",
            "severity": "medium",
            "resource": "misp_config",
            "detail": "No active threat intelligence feeds configured",
        })
    return findings


def analyze(data):
    findings = []
    events = data.get("events", [data] if "info" in data or "Attribute" in data else [])
    if isinstance(data, list):
        events = data
    for evt in events:
        findings.extend(validate_event_quality(evt))
    if "sync_servers" in data or "feeds" in data:
        findings.extend(validate_sharing_config(data))
    return findings


def generate_report(input_path):
    data = load_data(input_path)
    findings = analyze(data)
    sev = Counter(f["severity"] for f in findings)
    cats = Counter(f["type"] for f in findings)
    return {
        "report": "misp_threat_intelligence_sharing",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "severity_summary": dict(sev),
        "finding_categories": dict(cats),
        "findings": findings,
    }


def main():
    ap = argparse.ArgumentParser(description="MISP Threat Intelligence Sharing Agent")
    ap.add_argument("--input", required=True, help="Input JSON with MISP events or config")
    ap.add_argument("--output", help="Output JSON report path")
    ap.add_argument("--misp-url", help="MISP instance URL for live operations")
    ap.add_argument("--api-key", help="MISP API key")
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
