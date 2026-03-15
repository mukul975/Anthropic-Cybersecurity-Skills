#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Actor TTP Analysis Script

Queries the MITRE ATT&CK STIX data to:
- Map threat actor groups to their known techniques
- Generate ATT&CK Navigator layers for visualization
- Perform detection gap analysis
- Compare TTPs across multiple threat groups
- Identify high-priority detection opportunities

Requirements:
    pip install attackcti mitreattack-python stix2 requests

Usage:
    python process.py --group APT29 --output apt29_layer.json
    python process.py --compare APT28 APT29 "Lazarus Group"
    python process.py --gap-analysis --detections detections.json --group APT29
"""

import argparse
import json
import sys
from collections import defaultdict
from typing import Optional

try:
    from attackcti import attack_client
except ImportError:
    print("ERROR: attackcti not installed. Run: pip install attackcti")
    sys.exit(1)


class ATTACKAnalyzer:
    """Analyze threat actor TTPs using MITRE ATT&CK."""

    def __init__(self):
        print("[*] Initializing ATT&CK client (querying MITRE TAXII server)...")
        self.lift = attack_client()
        self.groups_cache = None
        self.techniques_cache = None

    def _get_groups(self):
        if self.groups_cache is None:
            self.groups_cache = self.lift.get_groups()
        return self.groups_cache

    def _get_techniques(self):
        if self.techniques_cache is None:
            self.techniques_cache = self.lift.get_enterprise_techniques()
        return self.techniques_cache

    def find_group(self, name: str) -> Optional[dict]:
        """Find a threat group by name or alias."""
        groups = self._get_groups()
        for group in groups:
            if name.lower() == group.get("name", "").lower():
                return group
            aliases = group.get("aliases", [])
            if any(name.lower() == a.lower() for a in aliases):
                return group
        return None

    def get_group_techniques(self, group_name: str) -> dict:
        """Get all techniques used by a threat group."""
        group = self.find_group(group_name)
        if not group:
            print(f"[-] Group '{group_name}' not found")
            return {}

        group_id = ""
        for ref in group.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                group_id = ref.get("external_id", "")
                break

        if not group_id:
            print(f"[-] No ATT&CK ID found for {group_name}")
            return {}

        techniques = self.lift.get_techniques_used_by_group(group_id)
        technique_map = {}

        for tech in techniques:
            tech_id = ""
            for ref in tech.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tech_id = ref.get("external_id", "")
                    break

            if not tech_id:
                continue

            tactics = [
                phase.get("phase_name", "")
                for phase in tech.get("kill_chain_phases", [])
            ]

            technique_map[tech_id] = {
                "name": tech.get("name", ""),
                "tactics": tactics,
                "description": tech.get("description", "")[:500],
                "platforms": tech.get("x_mitre_platforms", []),
                "data_sources": tech.get("x_mitre_data_sources", []),
            }

        print(f"[+] {group_name} ({group_id}): {len(technique_map)} techniques")
        return technique_map

    def create_navigator_layer(self, group_name: str, technique_map: dict,
                                color: str = "#ff6666") -> dict:
        """Generate ATT&CK Navigator layer JSON."""
        techniques_list = []
        for tech_id, info in technique_map.items():
            for tactic in info["tactics"]:
                techniques_list.append({
                    "techniqueID": tech_id,
                    "tactic": tactic,
                    "color": color,
                    "comment": info["name"],
                    "enabled": True,
                    "score": 100,
                    "metadata": [
                        {"name": "group", "value": group_name},
                        {"name": "platforms", "value": ", ".join(info["platforms"])},
                    ],
                })

        layer = {
            "name": f"{group_name} TTP Coverage",
            "versions": {
                "attack": "16.1",
                "navigator": "5.1.0",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": f"Techniques attributed to {group_name}",
            "filters": {
                "platforms": [
                    "Linux", "macOS", "Windows", "Cloud",
                    "Azure AD", "Office 365", "SaaS", "Google Workspace",
                ]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
                "showAggregateScores": False,
                "countUnscored": False,
            },
            "hideDisabled": False,
            "techniques": techniques_list,
            "gradient": {
                "colors": ["#ffffff", color],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": f"Used by {group_name}", "color": color},
                {"label": "Not observed", "color": "#ffffff"},
            ],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
            "selectVisibleTechniques": False,
        }

        return layer

    def compare_groups(self, group_names: list) -> dict:
        """Compare TTPs across multiple threat groups."""
        group_techs = {}
        for name in group_names:
            techs = self.get_group_techniques(name)
            group_techs[name] = set(techs.keys())

        if len(group_techs) < 2:
            print("[-] Need at least 2 groups for comparison")
            return {}

        all_techniques = set.union(*group_techs.values())
        common_to_all = set.intersection(*group_techs.values())

        comparison = {
            "groups": group_names,
            "total_unique_techniques": len(all_techniques),
            "common_to_all": sorted(common_to_all),
            "common_count": len(common_to_all),
            "per_group": {},
        }

        for name, techs in group_techs.items():
            others = set.union(*[t for n, t in group_techs.items() if n != name])
            unique = techs - others

            comparison["per_group"][name] = {
                "total": len(techs),
                "unique": sorted(unique),
                "unique_count": len(unique),
                "overlap_percentage": round(
                    len(techs.intersection(others)) / len(techs) * 100, 1
                ) if techs else 0,
            }

        # Technique frequency across groups
        tech_freq = defaultdict(list)
        for name, techs in group_techs.items():
            for t in techs:
                tech_freq[t].append(name)

        comparison["technique_frequency"] = {
            t: {"count": len(g), "groups": g}
            for t, g in sorted(tech_freq.items(), key=lambda x: -len(x[1]))
        }

        return comparison

    def gap_analysis(self, group_name: str,
                     detected_techniques: set) -> dict:
        """Analyze detection gaps for a specific threat group."""
        actor_techs = self.get_group_techniques(group_name)
        actor_tech_ids = set(actor_techs.keys())

        covered = actor_tech_ids.intersection(detected_techniques)
        gaps = actor_tech_ids - detected_techniques

        gap_details = []
        for tech_id in sorted(gaps):
            info = actor_techs.get(tech_id, {})
            gap_details.append({
                "technique_id": tech_id,
                "name": info.get("name", ""),
                "tactics": info.get("tactics", []),
                "data_sources": info.get("data_sources", []),
                "platforms": info.get("platforms", []),
            })

        analysis = {
            "group": group_name,
            "total_actor_techniques": len(actor_tech_ids),
            "detected": len(covered),
            "gaps": len(gaps),
            "coverage_percentage": round(
                len(covered) / len(actor_tech_ids) * 100, 1
            ) if actor_tech_ids else 0,
            "detected_techniques": sorted(covered),
            "gap_details": gap_details,
            "recommended_data_sources": self._recommend_data_sources(gap_details),
        }

        return analysis

    def _recommend_data_sources(self, gaps: list) -> list:
        """Recommend data sources that would close the most gaps."""
        ds_coverage = defaultdict(list)
        for gap in gaps:
            for ds in gap.get("data_sources", []):
                ds_coverage[ds].append(gap["technique_id"])

        recommendations = [
            {"data_source": ds, "covers_techniques": techs, "count": len(techs)}
            for ds, techs in sorted(ds_coverage.items(), key=lambda x: -len(x[1]))
        ]

        return recommendations[:10]

    def tactic_breakdown(self, group_name: str) -> dict:
        """Break down threat actor techniques by tactic."""
        techs = self.get_group_techniques(group_name)
        tactic_map = defaultdict(list)

        for tech_id, info in techs.items():
            for tactic in info["tactics"]:
                tactic_map[tactic].append({
                    "id": tech_id,
                    "name": info["name"],
                })

        tactic_order = [
            "reconnaissance", "resource-development", "initial-access",
            "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery",
            "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact",
        ]

        breakdown = {}
        for tactic in tactic_order:
            if tactic in tactic_map:
                breakdown[tactic] = {
                    "count": len(tactic_map[tactic]),
                    "techniques": tactic_map[tactic],
                }

        return breakdown


def main():
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK Threat Actor TTP Analyzer"
    )
    parser.add_argument("--group", help="Threat group name (e.g., APT29)")
    parser.add_argument("--compare", nargs="+", help="Compare multiple groups")
    parser.add_argument(
        "--gap-analysis", action="store_true", help="Perform detection gap analysis"
    )
    parser.add_argument(
        "--detections",
        help="JSON file with detected technique IDs",
    )
    parser.add_argument("--breakdown", action="store_true", help="Tactic breakdown")
    parser.add_argument("--output", default="attack_layer.json", help="Output file")

    args = parser.parse_args()
    analyzer = ATTACKAnalyzer()

    if args.compare:
        comparison = analyzer.compare_groups(args.compare)
        print(json.dumps(comparison, indent=2))
        with open(args.output, "w") as f:
            json.dump(comparison, f, indent=2)

    elif args.group and args.gap_analysis:
        detected = set()
        if args.detections:
            with open(args.detections) as f:
                detected = set(json.load(f))

        analysis = analyzer.gap_analysis(args.group, detected)
        print(json.dumps(analysis, indent=2))
        with open(args.output, "w") as f:
            json.dump(analysis, f, indent=2)

    elif args.group and args.breakdown:
        breakdown = analyzer.tactic_breakdown(args.group)
        print(json.dumps(breakdown, indent=2))

    elif args.group:
        tech_map = analyzer.get_group_techniques(args.group)
        layer = analyzer.create_navigator_layer(args.group, tech_map)
        with open(args.output, "w") as f:
            json.dump(layer, f, indent=2)
        print(f"[+] Navigator layer saved to {args.output}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
