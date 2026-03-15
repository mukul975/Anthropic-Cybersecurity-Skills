#!/usr/bin/env python3
"""Threat Actor Profiling from OSINT Agent - Builds threat actor profiles using open-source intelligence."""

import json
import logging
import argparse
from datetime import datetime

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def fetch_mitre_attack_data():
    """Fetch MITRE ATT&CK enterprise data."""
    resp = requests.get(MITRE_ATTACK_URL, timeout=60)
    resp.raise_for_status()
    bundle = resp.json()
    logger.info("Fetched ATT&CK bundle with %d objects", len(bundle.get("objects", [])))
    return bundle


def extract_group_info(bundle, group_name):
    """Extract threat group information from ATT&CK STIX bundle."""
    groups = [o for o in bundle["objects"] if o.get("type") == "intrusion-set"]
    target_group = None
    for g in groups:
        aliases = [g.get("name", "").lower()] + [a.lower() for a in g.get("aliases", [])]
        if group_name.lower() in aliases:
            target_group = g
            break
    if not target_group:
        logger.warning("Group '%s' not found. Available: %s", group_name, [g["name"] for g in groups[:20]])
        return None
    return {
        "name": target_group.get("name"),
        "aliases": target_group.get("aliases", []),
        "description": target_group.get("description", "")[:500],
        "stix_id": target_group.get("id"),
        "created": target_group.get("created"),
        "modified": target_group.get("modified"),
        "external_references": [{"source": r.get("source_name"), "url": r.get("url")}
                                 for r in target_group.get("external_references", []) if r.get("url")],
    }


def extract_group_techniques(bundle, group_stix_id):
    """Extract techniques used by a threat group via relationships."""
    relationships = [o for o in bundle["objects"] if o.get("type") == "relationship"
                     and o.get("source_ref") == group_stix_id and o.get("relationship_type") == "uses"]
    technique_map = {}
    for obj in bundle["objects"]:
        if obj.get("type") == "attack-pattern":
            technique_map[obj["id"]] = obj
    techniques = []
    for rel in relationships:
        target_id = rel.get("target_ref", "")
        tech = technique_map.get(target_id)
        if tech:
            ext_refs = tech.get("external_references", [])
            tech_id = next((r.get("external_id") for r in ext_refs if r.get("source_name") == "mitre-attack"), "")
            kill_chain = [p.get("phase_name") for p in tech.get("kill_chain_phases", [])]
            techniques.append({"technique_id": tech_id, "name": tech.get("name"), "tactics": kill_chain,
                               "description": rel.get("description", "")[:200]})
    logger.info("Found %d techniques for group", len(techniques))
    return techniques


def extract_group_malware_tools(bundle, group_stix_id):
    """Extract malware and tools associated with the group."""
    relationships = [o for o in bundle["objects"] if o.get("type") == "relationship"
                     and o.get("source_ref") == group_stix_id and o.get("relationship_type") == "uses"]
    obj_map = {o["id"]: o for o in bundle["objects"] if o.get("type") in ("malware", "tool")}
    items = []
    for rel in relationships:
        target = obj_map.get(rel.get("target_ref"))
        if target:
            items.append({"name": target.get("name"), "type": target.get("type"),
                          "description": target.get("description", "")[:200]})
    return items


def search_alienvault_otx(group_name, otx_key=None):
    """Search AlienVault OTX for threat actor intelligence."""
    headers = {}
    if otx_key:
        headers["X-OTX-API-KEY"] = otx_key
    try:
        resp = requests.get(f"https://otx.alienvault.com/api/v1/pulses/search",
                            params={"q": group_name, "limit": 10}, headers=headers, timeout=15)
        if resp.status_code == 200:
            pulses = resp.json().get("results", [])
            return [{"name": p.get("name"), "created": p.get("created"), "tags": p.get("tags", []),
                      "indicator_count": len(p.get("indicators", []))} for p in pulses]
    except requests.RequestException as e:
        logger.warning("OTX search failed: %s", e)
    return []


def build_tactic_coverage(techniques):
    """Analyze tactic coverage across the kill chain."""
    tactic_map = {}
    for tech in techniques:
        for tactic in tech.get("tactics", []):
            if tactic not in tactic_map:
                tactic_map[tactic] = []
            tactic_map[tactic].append(tech["technique_id"])
    return {tactic: {"count": len(techs), "techniques": techs} for tactic, techs in tactic_map.items()}


def generate_report(group_info, techniques, malware_tools, otx_results, tactic_coverage):
    """Generate threat actor profile report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "threat_actor_profile": group_info,
        "mitre_techniques": techniques,
        "malware_and_tools": malware_tools,
        "tactic_coverage": tactic_coverage,
        "osint_intelligence": otx_results,
        "summary": {
            "technique_count": len(techniques),
            "tool_count": len(malware_tools),
            "tactics_covered": len(tactic_coverage),
            "osint_reports": len(otx_results),
        },
    }
    name = group_info.get("name", "Unknown") if group_info else "Unknown"
    print(f"THREAT ACTOR PROFILE: {name}, {len(techniques)} techniques, "
          f"{len(malware_tools)} tools, {len(tactic_coverage)} tactics")
    return report


def main():
    parser = argparse.ArgumentParser(description="Threat Actor Profiling from OSINT")
    parser.add_argument("--group", required=True, help="Threat actor group name (e.g., APT29)")
    parser.add_argument("--otx-key", help="AlienVault OTX API key")
    parser.add_argument("--output", default="threat_actor_profile.json")
    args = parser.parse_args()

    bundle = fetch_mitre_attack_data()
    group_info = extract_group_info(bundle, args.group)
    techniques, malware_tools = [], []
    if group_info:
        techniques = extract_group_techniques(bundle, group_info["stix_id"])
        malware_tools = extract_group_malware_tools(bundle, group_info["stix_id"])
    otx_results = search_alienvault_otx(args.group, args.otx_key)
    tactic_coverage = build_tactic_coverage(techniques)
    report = generate_report(group_info, techniques, malware_tools, otx_results, tactic_coverage)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
