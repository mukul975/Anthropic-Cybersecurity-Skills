#!/usr/bin/env python3
"""MITRE ATT&CK Navigator layer generation and threat actor TTP mapping agent."""

import json
import sys
import argparse
from datetime import datetime

try:
    from attackcti import attack_client
except ImportError:
    print("Install: pip install attackcti")
    sys.exit(1)


def get_attack_client():
    """Initialize ATT&CK STIX/TAXII client."""
    return attack_client()


def list_threat_groups(client):
    """List all threat groups in ATT&CK."""
    groups = client.get_groups()
    results = []
    for g in groups:
        aliases = g.get("aliases", [])
        results.append({
            "name": g.get("name", ""),
            "id": g.get("external_references", [{}])[0].get("external_id", "")
                  if g.get("external_references") else "",
            "aliases": aliases,
            "description": g.get("description", "")[:200],
        })
    return sorted(results, key=lambda x: x["name"])


def get_group_techniques(client, group_name):
    """Get all techniques used by a specific threat group."""
    groups = client.get_groups()
    target_group = None
    for g in groups:
        if g.get("name", "").lower() == group_name.lower():
            target_group = g
            break
        aliases = [a.lower() for a in g.get("aliases", [])]
        if group_name.lower() in aliases:
            target_group = g
            break

    if not target_group:
        return {"error": f"Group '{group_name}' not found"}

    group_stix_id = target_group["id"]
    techniques = client.get_techniques_used_by_group(target_group)

    results = []
    for tech in techniques:
        ext_refs = tech.get("external_references", [])
        tech_id = ""
        url = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break
        results.append({
            "technique_id": tech_id,
            "name": tech.get("name", ""),
            "description": tech.get("description", "")[:150],
            "url": url,
            "platforms": tech.get("x_mitre_platforms", []),
        })

    return {
        "group_name": target_group.get("name", ""),
        "group_id": target_group.get("external_references", [{}])[0].get("external_id", ""),
        "technique_count": len(results),
        "techniques": results,
    }


def generate_navigator_layer(group_data, color="#ff6666"):
    """Generate ATT&CK Navigator layer JSON from group technique data."""
    techniques = []
    for tech in group_data.get("techniques", []):
        tid = tech.get("technique_id", "")
        if not tid:
            continue
        techniques.append({
            "techniqueID": tid,
            "score": 1,
            "color": color,
            "comment": tech.get("name", ""),
            "enabled": True,
        })

    layer = {
        "name": f"{group_data.get('group_name', 'Unknown')} TTPs",
        "versions": {
            "attack": "15",
            "navigator": "5.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": f"Techniques used by {group_data.get('group_name', '')} "
                        f"({group_data.get('group_id', '')})",
        "filters": {"platforms": ["Windows", "Linux", "macOS", "Cloud"]},
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", color],
            "minValue": 0,
            "maxValue": 1,
        },
        "legendItems": [
            {"label": f"{group_data.get('group_name', '')} techniques", "color": color},
        ],
        "metadata": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
    }
    return layer


def compare_groups(client, group_names):
    """Compare techniques across multiple threat groups."""
    all_techniques = {}
    group_techs = {}
    for name in group_names:
        data = get_group_techniques(client, name)
        if "error" in data:
            continue
        techs = {t["technique_id"] for t in data.get("techniques", [])}
        group_techs[data.get("group_name", name)] = techs
        for t in data.get("techniques", []):
            all_techniques[t["technique_id"]] = t["name"]

    shared = set.intersection(*group_techs.values()) if group_techs else set()
    unique_per_group = {}
    for name, techs in group_techs.items():
        unique_per_group[name] = techs - set.union(*(v for k, v in group_techs.items() if k != name))

    return {
        "groups_compared": list(group_techs.keys()),
        "total_unique_techniques": len(set.union(*group_techs.values())) if group_techs else 0,
        "shared_techniques": [{"id": t, "name": all_techniques.get(t, "")} for t in shared],
        "shared_count": len(shared),
        "unique_per_group": {k: len(v) for k, v in unique_per_group.items()},
    }


def run_audit(args):
    """Execute threat actor TTP mapping audit."""
    print(f"\n{'='*60}")
    print(f"  MITRE ATT&CK THREAT ACTOR TTP ANALYSIS")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    client = get_attack_client()
    report = {}

    if args.list_groups:
        groups = list_threat_groups(client)
        report["groups"] = groups
        print(f"--- THREAT GROUPS ({len(groups)}) ---")
        for g in groups[:30]:
            print(f"  {g['id']}: {g['name']}")

    if args.group:
        data = get_group_techniques(client, args.group)
        report["group_techniques"] = data
        print(f"--- {data.get('group_name','')} ({data.get('group_id','')}) ---")
        print(f"  Techniques: {data.get('technique_count', 0)}")
        for t in data.get("techniques", [])[:20]:
            print(f"  {t['technique_id']}: {t['name']}")

        if args.layer_output:
            layer = generate_navigator_layer(data)
            with open(args.layer_output, "w") as f:
                json.dump(layer, f, indent=2)
            report["layer_file"] = args.layer_output
            print(f"\n  Navigator layer saved to {args.layer_output}")

    if args.compare:
        comparison = compare_groups(client, args.compare)
        report["comparison"] = comparison
        print(f"\n--- GROUP COMPARISON ---")
        print(f"  Groups: {comparison['groups_compared']}")
        print(f"  Total unique techniques: {comparison['total_unique_techniques']}")
        print(f"  Shared: {comparison['shared_count']}")
        for t in comparison["shared_techniques"][:10]:
            print(f"    {t['id']}: {t['name']}")

    return report


def main():
    parser = argparse.ArgumentParser(description="MITRE ATT&CK TTP Mapping Agent")
    parser.add_argument("--group", help="Threat group name to analyze (e.g., APT29)")
    parser.add_argument("--list-groups", action="store_true", help="List all ATT&CK groups")
    parser.add_argument("--compare", nargs="+", help="Compare multiple groups")
    parser.add_argument("--layer-output", help="Save Navigator layer JSON to file")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
