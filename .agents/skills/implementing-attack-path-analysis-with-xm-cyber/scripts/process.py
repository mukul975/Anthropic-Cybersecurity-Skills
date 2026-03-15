#!/usr/bin/env python3
"""
Attack Path Analysis and Choke Point Prioritization Tool

Processes attack path data from exposure management platforms
to identify and prioritize choke points for remediation.

Requirements:
    pip install pandas networkx matplotlib

Usage:
    python process.py analyze --input attack_paths.json --output choke_points.csv
    python process.py visualize --input attack_paths.json --output graph.png
    python process.py report --input attack_paths.json
"""

import argparse
import json
import sys
from collections import defaultdict

import networkx as nx
import pandas as pd


class AttackPathAnalyzer:
    """Analyze attack paths and identify choke points."""

    def __init__(self):
        self.graph = nx.DiGraph()
        self.critical_assets = set()
        self.choke_points = []

    def load_attack_paths(self, data):
        """Load attack path data into a directed graph."""
        for path in data.get("attack_paths", []):
            nodes = path.get("nodes", [])
            for i in range(len(nodes) - 1):
                src = nodes[i]
                dst = nodes[i + 1]
                self.graph.add_node(src["id"], **src)
                self.graph.add_node(dst["id"], **dst)
                self.graph.add_edge(
                    src["id"], dst["id"],
                    technique=path.get("technique", "unknown"),
                    path_id=path.get("path_id", "")
                )

        for asset in data.get("critical_assets", []):
            self.critical_assets.add(asset["id"])
            if asset["id"] in self.graph:
                self.graph.nodes[asset["id"]]["is_critical"] = True
                self.graph.nodes[asset["id"]]["tier"] = asset.get("tier", 3)

        print(f"[+] Loaded {self.graph.number_of_nodes()} nodes, "
              f"{self.graph.number_of_edges()} edges")
        print(f"    Critical assets: {len(self.critical_assets)}")

    def find_choke_points(self):
        """Identify choke points using betweenness centrality
        weighted by paths to critical assets."""
        betweenness = nx.betweenness_centrality(self.graph)

        node_path_counts = defaultdict(lambda: {"paths": 0, "assets": set()})

        for critical_asset in self.critical_assets:
            if critical_asset not in self.graph:
                continue
            for source in self.graph.nodes():
                if source == critical_asset:
                    continue
                if source in self.critical_assets:
                    continue
                try:
                    for path in nx.all_simple_paths(
                        self.graph, source, critical_asset, cutoff=8
                    ):
                        for node in path[1:-1]:
                            node_path_counts[node]["paths"] += 1
                            node_path_counts[node]["assets"].add(critical_asset)
                except nx.NetworkXNoPath:
                    continue

        self.choke_points = []
        for node_id, counts in node_path_counts.items():
            if counts["paths"] < 2:
                continue

            node_data = self.graph.nodes.get(node_id, {})
            self.choke_points.append({
                "entity_id": node_id,
                "entity_name": node_data.get("name", node_id),
                "entity_type": node_data.get("type", "unknown"),
                "exposure_category": node_data.get("exposure_category", "unknown"),
                "paths_through": counts["paths"],
                "critical_assets_at_risk": len(counts["assets"]),
                "assets_list": list(counts["assets"]),
                "betweenness_centrality": round(betweenness.get(node_id, 0), 4),
                "risk_score": round(
                    counts["paths"] * len(counts["assets"]) *
                    (1 + betweenness.get(node_id, 0)),
                    2
                ),
                "remediation": node_data.get("remediation", "Review and fix"),
                "fix_complexity": node_data.get("fix_complexity", "medium"),
            })

        self.choke_points.sort(key=lambda x: x["risk_score"], reverse=True)
        print(f"[+] Identified {len(self.choke_points)} choke points")
        return self.choke_points

    def generate_remediation_plan(self):
        """Generate prioritized remediation plan from choke points."""
        if not self.choke_points:
            self.find_choke_points()

        plan = []
        for i, cp in enumerate(self.choke_points, 1):
            if cp["risk_score"] >= 100 or cp["critical_assets_at_risk"] >= 3:
                priority = "P1-Emergency"
                sla = "48 hours"
            elif cp["risk_score"] >= 50 or cp["critical_assets_at_risk"] >= 2:
                priority = "P2-Critical"
                sla = "7 days"
            elif cp["risk_score"] >= 20:
                priority = "P3-High"
                sla = "14 days"
            else:
                priority = "P4-Medium"
                sla = "30 days"

            plan.append({
                "rank": i,
                "entity": cp["entity_name"],
                "type": cp["entity_type"],
                "category": cp["exposure_category"],
                "paths_eliminated": cp["paths_through"],
                "assets_protected": cp["critical_assets_at_risk"],
                "risk_score": cp["risk_score"],
                "priority": priority,
                "sla": sla,
                "complexity": cp["fix_complexity"],
                "remediation": cp["remediation"],
            })

        return pd.DataFrame(plan)

    def print_summary(self):
        """Print analysis summary."""
        if not self.choke_points:
            self.find_choke_points()

        total_nodes = self.graph.number_of_nodes()
        total_edges = self.graph.number_of_edges()
        total_choke = len(self.choke_points)

        print(f"\n{'=' * 70}")
        print("ATTACK PATH ANALYSIS SUMMARY")
        print(f"{'=' * 70}")
        print(f"Total entities:       {total_nodes}")
        print(f"Total attack edges:   {total_edges}")
        print(f"Critical assets:      {len(self.critical_assets)}")
        print(f"Choke points found:   {total_choke}")
        print(f"Choke point ratio:    {total_choke / max(total_nodes, 1) * 100:.1f}%")

        if self.choke_points:
            print(f"\nTop 10 Choke Points:")
            for i, cp in enumerate(self.choke_points[:10], 1):
                print(f"  {i}. {cp['entity_name']}")
                print(f"     Type: {cp['entity_type']} | "
                      f"Category: {cp['exposure_category']}")
                print(f"     Paths: {cp['paths_through']} | "
                      f"Assets at risk: {cp['critical_assets_at_risk']} | "
                      f"Risk: {cp['risk_score']}")

            categories = defaultdict(int)
            for cp in self.choke_points:
                categories[cp["exposure_category"]] += 1
            print(f"\nChoke Points by Category:")
            for cat, count in sorted(categories.items(),
                                     key=lambda x: x[1], reverse=True):
                print(f"  {cat}: {count}")


def main():
    parser = argparse.ArgumentParser(
        description="Attack Path Analysis and Choke Point Prioritization"
    )
    subparsers = parser.add_subparsers(dest="command")

    analyze_p = subparsers.add_parser("analyze", help="Analyze attack paths")
    analyze_p.add_argument("--input", required=True, help="Attack paths JSON file")
    analyze_p.add_argument("--output", default="choke_points.csv")

    report_p = subparsers.add_parser("report", help="Generate summary report")
    report_p.add_argument("--input", required=True, help="Attack paths JSON file")

    plan_p = subparsers.add_parser("plan", help="Generate remediation plan")
    plan_p.add_argument("--input", required=True, help="Attack paths JSON file")
    plan_p.add_argument("--output", default="remediation_plan.csv")

    args = parser.parse_args()
    analyzer = AttackPathAnalyzer()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    with open(args.input) as f:
        data = json.load(f)
    analyzer.load_attack_paths(data)

    if args.command == "analyze":
        choke_points = analyzer.find_choke_points()
        df = pd.DataFrame(choke_points)
        df.to_csv(args.output, index=False)
        print(f"[+] Choke points saved to {args.output}")
        analyzer.print_summary()
    elif args.command == "report":
        analyzer.print_summary()
    elif args.command == "plan":
        plan_df = analyzer.generate_remediation_plan()
        plan_df.to_csv(args.output, index=False)
        print(plan_df.to_string(index=False))
        print(f"\n[+] Remediation plan saved to {args.output}")


if __name__ == "__main__":
    main()
