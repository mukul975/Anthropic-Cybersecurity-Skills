#!/usr/bin/env python3
"""
Campaign Attribution Evidence Analysis Script

Implements structured attribution analysis:
- Analysis of Competing Hypotheses (ACH) matrix
- Infrastructure overlap scoring
- TTP similarity comparison using ATT&CK
- Evidence weighting and confidence assessment

Requirements:
    pip install attackcti stix2 requests

Usage:
    python process.py --evidence evidence.json --hypotheses actors.json --output report.json
    python process.py --compare-ttps --campaign campaign_techs.json --actor APT29
"""

import argparse
import json
import sys
from collections import defaultdict


class AttributionEngine:
    """Structured attribution analysis using ACH methodology."""

    def __init__(self):
        self.evidence = []
        self.hypotheses = {}

    def load_evidence(self, filepath):
        with open(filepath) as f:
            self.evidence = json.load(f)

    def add_evidence(self, category, description, value, confidence):
        self.evidence.append({
            "id": len(self.evidence),
            "category": category,
            "description": description,
            "value": value,
            "confidence": confidence,
        })

    def add_hypothesis(self, actor_name, supporting_info=""):
        self.hypotheses[actor_name] = {
            "info": supporting_info,
            "assessments": {},
            "score": 0,
        }

    def evaluate(self, evidence_id, actor_name, assessment):
        """Evaluate evidence against hypothesis: C=consistent, I=inconsistent, N=neutral."""
        weight = self.evidence[evidence_id]["confidence"]
        self.hypotheses[actor_name]["assessments"][evidence_id] = assessment

        if assessment == "C":
            self.hypotheses[actor_name]["score"] += weight
        elif assessment == "I":
            self.hypotheses[actor_name]["score"] -= weight * 2

    def generate_ach_matrix(self):
        matrix = {"evidence": [], "hypotheses": {}}
        for e in self.evidence:
            matrix["evidence"].append({
                "id": e["id"],
                "category": e["category"],
                "description": e["description"],
            })

        for actor, data in self.hypotheses.items():
            matrix["hypotheses"][actor] = {
                "assessments": data["assessments"],
                "score": data["score"],
                "consistent": sum(1 for a in data["assessments"].values() if a == "C"),
                "inconsistent": sum(1 for a in data["assessments"].values() if a == "I"),
                "neutral": sum(1 for a in data["assessments"].values() if a == "N"),
            }

        return matrix

    def rank(self):
        ranked = sorted(
            self.hypotheses.items(), key=lambda x: x[1]["score"], reverse=True
        )
        results = []
        for name, data in ranked:
            incon = sum(1 for a in data["assessments"].values() if a == "I")
            confidence = "HIGH" if data["score"] >= 80 and incon == 0 else \
                        "MODERATE" if data["score"] >= 40 else "LOW"
            results.append({
                "actor": name,
                "score": data["score"],
                "confidence": confidence,
                "inconsistent_count": incon,
            })
        return results


def compare_ttp_similarity(campaign_techs, actor_techs):
    campaign_set = set(campaign_techs)
    actor_set = set(actor_techs)
    common = campaign_set & actor_set

    jaccard = len(common) / len(campaign_set | actor_set) if (campaign_set | actor_set) else 0
    return {
        "common": sorted(common),
        "jaccard_similarity": round(jaccard, 3),
        "campaign_coverage": round(len(common) / len(campaign_set) * 100, 1) if campaign_set else 0,
    }


def main():
    parser = argparse.ArgumentParser(description="Campaign Attribution Analysis")
    parser.add_argument("--evidence", help="Evidence JSON file")
    parser.add_argument("--hypotheses", help="Hypotheses JSON file")
    parser.add_argument("--compare-ttps", action="store_true")
    parser.add_argument("--campaign", help="Campaign techniques JSON")
    parser.add_argument("--actor", help="Actor name for ATT&CK lookup")
    parser.add_argument("--output", default="attribution_report.json")

    args = parser.parse_args()
    engine = AttributionEngine()

    if args.evidence and args.hypotheses:
        engine.load_evidence(args.evidence)
        with open(args.hypotheses) as f:
            hyps = json.load(f)
        for h in hyps:
            engine.add_hypothesis(h["name"], h.get("info", ""))
            for eid, assessment in h.get("evaluations", {}).items():
                engine.evaluate(int(eid), h["name"], assessment)

        matrix = engine.generate_ach_matrix()
        rankings = engine.rank()
        report = {"ach_matrix": matrix, "rankings": rankings}
        print(json.dumps(report, indent=2))

        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)

    elif args.compare_ttps and args.campaign:
        with open(args.campaign) as f:
            campaign_techs = json.load(f)

        if args.actor:
            try:
                from attackcti import attack_client
                lift = attack_client()
                groups = lift.get_groups()
                group = next(
                    (g for g in groups if args.actor.lower() in g.get("name", "").lower()),
                    None,
                )
                if group:
                    gid = group["external_references"][0]["external_id"]
                    techs = lift.get_techniques_used_by_group(gid)
                    actor_techs = [
                        t["external_references"][0]["external_id"]
                        for t in techs if t.get("external_references")
                    ]
                    result = compare_ttp_similarity(campaign_techs, actor_techs)
                    print(json.dumps(result, indent=2))
            except ImportError:
                print("[-] attackcti not installed")


if __name__ == "__main__":
    main()
