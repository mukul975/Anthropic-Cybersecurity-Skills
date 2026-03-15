#!/usr/bin/env python3
"""
NIST CSF 2.0 Maturity Assessment Automation

Automates maturity scoring across all 6 CSF functions, gap analysis
between current and target profiles, and improvement roadmap generation.
"""

import json
import csv
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

# CSF 2.0 Category structure
CSF_CATEGORIES = {
    "GV": {
        "name": "Govern",
        "categories": {
            "GV.OC": "Organizational Context",
            "GV.RM": "Risk Management Strategy",
            "GV.RR": "Roles, Responsibilities, and Authorities",
            "GV.PO": "Policy",
            "GV.OV": "Oversight",
            "GV.SC": "Cybersecurity Supply Chain Risk Management",
        }
    },
    "ID": {
        "name": "Identify",
        "categories": {
            "ID.AM": "Asset Management",
            "ID.RA": "Risk Assessment",
            "ID.IM": "Improvement",
        }
    },
    "PR": {
        "name": "Protect",
        "categories": {
            "PR.AA": "Identity Management, Authentication, and Access Control",
            "PR.AT": "Awareness and Training",
            "PR.DS": "Data Security",
            "PR.PS": "Platform Security",
            "PR.IR": "Technology Infrastructure Resilience",
        }
    },
    "DE": {
        "name": "Detect",
        "categories": {
            "DE.CM": "Continuous Monitoring",
            "DE.AE": "Adverse Event Analysis",
        }
    },
    "RS": {
        "name": "Respond",
        "categories": {
            "RS.MA": "Incident Management",
            "RS.AN": "Incident Analysis",
            "RS.CO": "Incident Response Reporting and Communication",
            "RS.MI": "Incident Mitigation",
        }
    },
    "RC": {
        "name": "Recover",
        "categories": {
            "RC.RP": "Incident Recovery Plan Execution",
        }
    },
}

TIER_DESCRIPTIONS = {
    1: "Partial - Ad hoc, reactive, limited awareness",
    2: "Risk-Informed - Approved practices, inconsistent application",
    3: "Repeatable - Formal policies, consistent implementation",
    4: "Adaptive - Continuous improvement, real-time adaptation",
}


@dataclass
class CategoryAssessment:
    category_id: str
    category_name: str
    function_id: str
    current_tier: int
    target_tier: int
    evidence: str = ""
    strengths: list = field(default_factory=list)
    gaps: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)

    @property
    def gap_size(self) -> int:
        return max(0, self.target_tier - self.current_tier)

    @property
    def gap_priority(self) -> str:
        gap = self.gap_size
        if gap >= 2:
            return "Critical"
        elif gap == 1 and self.target_tier >= 3:
            return "High"
        elif gap == 1:
            return "Medium"
        else:
            return "On Target"


@dataclass
class ImprovementInitiative:
    initiative_id: str
    category_id: str
    title: str
    description: str
    current_tier: int
    target_tier: int
    timeframe: str  # Quick Win, Medium-Term, Long-Term
    effort: str     # Low, Medium, High
    impact: str     # Low, Medium, High
    owner: str = ""
    estimated_cost: str = ""
    status: str = "Planned"


class NISTCSFAssessment:
    """Conducts NIST CSF 2.0 maturity assessment."""

    def __init__(self, output_dir: str = "./nist_csf_output",
                 organization: str = "Organization"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.organization = organization
        self.assessments: list[CategoryAssessment] = []
        self.initiatives: list[ImprovementInitiative] = []

    def assess_maturity(self, scores: list[dict]) -> list[CategoryAssessment]:
        """Score each CSF category against implementation tiers."""
        print("\n" + "=" * 70)
        print(f"NIST CSF 2.0 MATURITY ASSESSMENT - {self.organization}")
        print("=" * 70)

        for score_data in scores:
            assessment = CategoryAssessment(**score_data)
            self.assessments.append(assessment)

        # Display by function
        for func_id, func_info in CSF_CATEGORIES.items():
            func_assessments = [a for a in self.assessments if a.function_id == func_id]
            if not func_assessments:
                continue

            avg_current = sum(a.current_tier for a in func_assessments) / len(func_assessments)
            avg_target = sum(a.target_tier for a in func_assessments) / len(func_assessments)

            print(f"\n  {func_info['name']} ({func_id}) - Avg Current: {avg_current:.1f} | Avg Target: {avg_target:.1f}")
            print(f"  {'Category':<50} {'Current':>8} {'Target':>8} {'Gap':>5} {'Priority':>10}")
            print(f"  {'-'*85}")

            for a in func_assessments:
                gap_indicator = f"+{a.gap_size}" if a.gap_size > 0 else "0"
                print(f"  {a.category_name:<50} {a.current_tier:>5}/4  {a.target_tier:>5}/4  {gap_indicator:>5} {a.gap_priority:>10}")

        # Overall summary
        total_avg_current = sum(a.current_tier for a in self.assessments) / len(self.assessments)
        total_avg_target = sum(a.target_tier for a in self.assessments) / len(self.assessments)

        print(f"\n  {'='*85}")
        print(f"  Overall Average Current Tier: {total_avg_current:.2f}")
        print(f"  Overall Average Target Tier:  {total_avg_target:.2f}")
        print(f"  Overall Gap:                  {total_avg_target - total_avg_current:.2f}")

        # Tier distribution
        tier_dist = {1: 0, 2: 0, 3: 0, 4: 0}
        for a in self.assessments:
            tier_dist[a.current_tier] += 1

        print(f"\n  Current Tier Distribution:")
        for tier, count in tier_dist.items():
            bar = "#" * (count * 3)
            print(f"    Tier {tier}: {count:>3} categories {bar}")

        # Save assessment
        report_path = self.output_dir / "maturity_assessment.json"
        with open(report_path, "w") as f:
            json.dump({
                "organization": self.organization,
                "date": datetime.now().isoformat(),
                "overall_current": total_avg_current,
                "overall_target": total_avg_target,
                "assessments": [asdict(a) for a in self.assessments],
            }, f, indent=2)

        print(f"\n  Assessment saved to: {report_path}")
        return self.assessments

    def generate_gap_analysis(self) -> dict:
        """Generate gap analysis between current and target profiles."""
        print("\n" + "=" * 70)
        print("GAP ANALYSIS")
        print("=" * 70)

        gaps = {
            "Critical": [],
            "High": [],
            "Medium": [],
            "On Target": [],
        }

        for a in self.assessments:
            gaps[a.gap_priority].append({
                "category": a.category_id,
                "name": a.category_name,
                "current": a.current_tier,
                "target": a.target_tier,
                "gap": a.gap_size,
                "gaps_detail": a.gaps,
                "recommendations": a.recommendations,
            })

        for priority in ["Critical", "High", "Medium", "On Target"]:
            items = gaps[priority]
            print(f"\n  {priority} ({len(items)} categories):")
            for item in items:
                if priority != "On Target":
                    print(f"    {item['category']}: {item['name']} (Tier {item['current']} -> {item['target']})")
                    for gap in item.get("gaps_detail", []):
                        print(f"      - {gap}")

        gap_path = self.output_dir / "gap_analysis.json"
        with open(gap_path, "w") as f:
            json.dump(gaps, f, indent=2)

        print(f"\n  Gap Analysis saved to: {gap_path}")
        return gaps

    def create_roadmap(self, initiatives: list[dict]) -> list[ImprovementInitiative]:
        """Create improvement roadmap with prioritized initiatives."""
        print("\n" + "=" * 70)
        print("IMPROVEMENT ROADMAP")
        print("=" * 70)

        for init_data in initiatives:
            initiative = ImprovementInitiative(**init_data)
            self.initiatives.append(initiative)

        timeframes = {"Quick Win (0-3 months)": [], "Medium-Term (3-12 months)": [], "Long-Term (12-24 months)": []}
        for init in self.initiatives:
            timeframes.setdefault(init.timeframe, [])
            timeframes[init.timeframe].append(init)

        for tf, items in timeframes.items():
            print(f"\n  {tf}:")
            for item in items:
                print(f"    [{item.initiative_id}] {item.title}")
                print(f"      Category: {item.category_id} | Effort: {item.effort} | Impact: {item.impact}")
                if item.owner:
                    print(f"      Owner: {item.owner}")

        roadmap_path = self.output_dir / "improvement_roadmap.json"
        with open(roadmap_path, "w") as f:
            json.dump([asdict(i) for i in self.initiatives], f, indent=2)

        print(f"\n  Roadmap saved to: {roadmap_path}")
        return self.initiatives

    def generate_executive_summary(self) -> dict:
        """Generate executive-level maturity summary."""
        print("\n" + "=" * 70)
        print("EXECUTIVE SUMMARY")
        print("=" * 70)

        func_scores = {}
        for func_id, func_info in CSF_CATEGORIES.items():
            func_assessments = [a for a in self.assessments if a.function_id == func_id]
            if func_assessments:
                avg = sum(a.current_tier for a in func_assessments) / len(func_assessments)
                target_avg = sum(a.target_tier for a in func_assessments) / len(func_assessments)
                func_scores[func_info["name"]] = {"current": round(avg, 2), "target": round(target_avg, 2)}

        summary = {
            "organization": self.organization,
            "date": datetime.now().isoformat(),
            "function_scores": func_scores,
            "total_categories": len(self.assessments),
            "critical_gaps": sum(1 for a in self.assessments if a.gap_priority == "Critical"),
            "high_gaps": sum(1 for a in self.assessments if a.gap_priority == "High"),
            "improvement_initiatives": len(self.initiatives),
        }

        print(f"\n  Organization: {self.organization}")
        print(f"\n  Function Maturity Scores:")
        for func, scores in func_scores.items():
            bar_current = "|" * int(scores["current"] * 5)
            bar_target = "." * int((scores["target"] - scores["current"]) * 5)
            print(f"    {func:<15} Current: {scores['current']:.1f}/4  Target: {scores['target']:.1f}/4  {bar_current}{bar_target}")

        print(f"\n  Critical Gaps: {summary['critical_gaps']}")
        print(f"  High Gaps: {summary['high_gaps']}")
        print(f"  Planned Initiatives: {summary['improvement_initiatives']}")

        summary_path = self.output_dir / "executive_summary.json"
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        print(f"\n  Executive Summary saved to: {summary_path}")
        return summary


def main():
    """Run NIST CSF 2.0 maturity assessment."""
    assessment = NISTCSFAssessment(organization="Example Corporation")

    sample_scores = [
        {"category_id": "GV.OC", "category_name": "Organizational Context", "function_id": "GV", "current_tier": 2, "target_tier": 3, "gaps": ["Risk appetite not formally documented"], "recommendations": ["Document and approve risk appetite statement"]},
        {"category_id": "GV.RM", "category_name": "Risk Management Strategy", "function_id": "GV", "current_tier": 2, "target_tier": 3, "gaps": ["Strategy not updated annually"], "recommendations": ["Establish annual review cycle"]},
        {"category_id": "GV.RR", "category_name": "Roles and Responsibilities", "function_id": "GV", "current_tier": 3, "target_tier": 3},
        {"category_id": "GV.PO", "category_name": "Policy", "function_id": "GV", "current_tier": 2, "target_tier": 3, "gaps": ["Policies not reviewed in 18+ months"], "recommendations": ["Implement annual policy review cycle"]},
        {"category_id": "GV.OV", "category_name": "Oversight", "function_id": "GV", "current_tier": 1, "target_tier": 3, "gaps": ["No board-level security reporting", "No metrics dashboard"], "recommendations": ["Establish quarterly board reporting", "Deploy security metrics dashboard"]},
        {"category_id": "GV.SC", "category_name": "Supply Chain Risk Management", "function_id": "GV", "current_tier": 1, "target_tier": 3, "gaps": ["No supply chain risk programme", "Vendor assessments ad hoc"], "recommendations": ["Establish vendor risk management programme"]},
        {"category_id": "ID.AM", "category_name": "Asset Management", "function_id": "ID", "current_tier": 2, "target_tier": 3, "gaps": ["Asset inventory incomplete for cloud"], "recommendations": ["Extend CMDB to cloud assets"]},
        {"category_id": "ID.RA", "category_name": "Risk Assessment", "function_id": "ID", "current_tier": 2, "target_tier": 3, "gaps": ["Risk assessments not quantitative"], "recommendations": ["Adopt FAIR methodology for quantification"]},
        {"category_id": "ID.IM", "category_name": "Improvement", "function_id": "ID", "current_tier": 2, "target_tier": 3},
        {"category_id": "PR.AA", "category_name": "Identity and Access Control", "function_id": "PR", "current_tier": 3, "target_tier": 3},
        {"category_id": "PR.AT", "category_name": "Awareness and Training", "function_id": "PR", "current_tier": 2, "target_tier": 3, "gaps": ["No role-based training"], "recommendations": ["Implement role-based security training"]},
        {"category_id": "PR.DS", "category_name": "Data Security", "function_id": "PR", "current_tier": 2, "target_tier": 3, "gaps": ["DLP not fully deployed"], "recommendations": ["Complete DLP deployment"]},
        {"category_id": "PR.PS", "category_name": "Platform Security", "function_id": "PR", "current_tier": 3, "target_tier": 3},
        {"category_id": "PR.IR", "category_name": "Infrastructure Resilience", "function_id": "PR", "current_tier": 2, "target_tier": 3},
        {"category_id": "DE.CM", "category_name": "Continuous Monitoring", "function_id": "DE", "current_tier": 2, "target_tier": 3, "gaps": ["Limited cloud monitoring", "No OT monitoring"], "recommendations": ["Extend SIEM to cloud and OT"]},
        {"category_id": "DE.AE", "category_name": "Adverse Event Analysis", "function_id": "DE", "current_tier": 2, "target_tier": 3, "gaps": ["Manual correlation only"], "recommendations": ["Implement automated correlation"]},
        {"category_id": "RS.MA", "category_name": "Incident Management", "function_id": "RS", "current_tier": 3, "target_tier": 3},
        {"category_id": "RS.AN", "category_name": "Incident Analysis", "function_id": "RS", "current_tier": 2, "target_tier": 3},
        {"category_id": "RS.CO", "category_name": "Response Communication", "function_id": "RS", "current_tier": 2, "target_tier": 3},
        {"category_id": "RS.MI", "category_name": "Incident Mitigation", "function_id": "RS", "current_tier": 2, "target_tier": 3},
        {"category_id": "RC.RP", "category_name": "Recovery Plan Execution", "function_id": "RC", "current_tier": 2, "target_tier": 3, "gaps": ["DR plan not tested in 2+ years"], "recommendations": ["Conduct DR tabletop and technical test"]},
    ]

    assessment.assess_maturity(sample_scores)
    assessment.generate_gap_analysis()

    sample_initiatives = [
        {"initiative_id": "INIT-001", "category_id": "GV.OV", "title": "Establish Board Security Reporting", "description": "Create quarterly security report template and present to board", "current_tier": 1, "target_tier": 3, "timeframe": "Quick Win (0-3 months)", "effort": "Low", "impact": "High", "owner": "CISO"},
        {"initiative_id": "INIT-002", "category_id": "GV.SC", "title": "Vendor Risk Management Programme", "description": "Establish formal vendor assessment and monitoring programme", "current_tier": 1, "target_tier": 3, "timeframe": "Medium-Term (3-12 months)", "effort": "Medium", "impact": "High", "owner": "Security Manager"},
        {"initiative_id": "INIT-003", "category_id": "DE.CM", "title": "Cloud Security Monitoring", "description": "Extend SIEM to cover AWS/Azure/GCP workloads", "current_tier": 2, "target_tier": 3, "timeframe": "Medium-Term (3-12 months)", "effort": "High", "impact": "High", "owner": "SOC Manager"},
        {"initiative_id": "INIT-004", "category_id": "RC.RP", "title": "DR Testing Programme", "description": "Annual DR tabletop and semi-annual technical recovery tests", "current_tier": 2, "target_tier": 3, "timeframe": "Quick Win (0-3 months)", "effort": "Medium", "impact": "High", "owner": "IT Director"},
    ]

    assessment.create_roadmap(sample_initiatives)
    assessment.generate_executive_summary()

    print("\n" + "=" * 70)
    print("NIST CSF 2.0 MATURITY ASSESSMENT COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
