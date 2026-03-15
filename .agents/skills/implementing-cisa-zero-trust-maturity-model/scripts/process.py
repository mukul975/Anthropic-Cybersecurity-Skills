#!/usr/bin/env python3
"""
CISA Zero Trust Maturity Model Assessment and Roadmap Generator.

Evaluates organizational zero trust maturity across the five CISA ZTMM pillars
(Identity, Devices, Networks, Applications, Data) and three cross-cutting
capabilities (Visibility & Analytics, Automation & Orchestration, Governance).
Generates gap analysis, prioritized roadmap, and compliance mapping.
"""

import json
import csv
import datetime
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional
from pathlib import Path


class MaturityStage(IntEnum):
    TRADITIONAL = 0
    INITIAL = 1
    ADVANCED = 2
    OPTIMAL = 3


PILLAR_FUNCTIONS = {
    "Identity": [
        "authentication",
        "identity_stores",
        "risk_assessment",
        "access_management",
        "identity_lifecycle",
        "visibility_analytics",
        "automation_orchestration",
        "governance",
    ],
    "Devices": [
        "policy_enforcement",
        "asset_management",
        "device_compliance",
        "device_threat_protection",
        "visibility_analytics",
        "automation_orchestration",
        "governance",
    ],
    "Networks": [
        "network_segmentation",
        "threat_protection",
        "encryption",
        "network_resilience",
        "visibility_analytics",
        "automation_orchestration",
        "governance",
    ],
    "Applications": [
        "access_authorization",
        "threat_protection",
        "accessibility",
        "application_security",
        "visibility_analytics",
        "automation_orchestration",
        "governance",
    ],
    "Data": [
        "data_inventory",
        "data_categorization",
        "data_availability",
        "data_access",
        "data_encryption",
        "visibility_analytics",
        "automation_orchestration",
        "governance",
    ],
}

OMB_M2209_REQUIREMENTS = {
    "Identity": {
        "requirement": "Agency staff use enterprise-managed identities with phishing-resistant MFA",
        "target_stage": MaturityStage.ADVANCED,
        "key_actions": [
            "Deploy FIDO2/WebAuthn for all users",
            "Integrate identity provider with all applications",
            "Implement authorization based on user attributes",
        ],
    },
    "Devices": {
        "requirement": "Federal government has a complete inventory of authorized devices and can prevent/detect/respond to incidents",
        "target_stage": MaturityStage.ADVANCED,
        "key_actions": [
            "Deploy EDR on all endpoints",
            "Maintain real-time asset inventory",
            "Enforce device compliance before access",
        ],
    },
    "Networks": {
        "requirement": "Agencies encrypt all DNS and HTTP traffic within their environment",
        "target_stage": MaturityStage.ADVANCED,
        "key_actions": [
            "Encrypt all DNS traffic (DoH/DoT)",
            "Enforce HTTPS for all web traffic",
            "Implement network microsegmentation",
        ],
    },
    "Applications": {
        "requirement": "Agencies treat all applications as internet-connected and routinely test them",
        "target_stage": MaturityStage.ADVANCED,
        "key_actions": [
            "Integrate SAST/DAST into CI/CD",
            "Remove application access from VPN dependencies",
            "Implement application-level access policies",
        ],
    },
    "Data": {
        "requirement": "Agencies have thorough data categorization and employ automated tools",
        "target_stage": MaturityStage.ADVANCED,
        "key_actions": [
            "Implement data classification scheme",
            "Deploy automated data tagging",
            "Enable DLP across all data channels",
        ],
    },
}


@dataclass
class FunctionAssessment:
    function_name: str
    current_stage: MaturityStage
    target_stage: MaturityStage
    evidence: str = ""
    gaps: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)


@dataclass
class PillarAssessment:
    pillar_name: str
    functions: list = field(default_factory=list)
    overall_stage: MaturityStage = MaturityStage.TRADITIONAL
    compliance_gap: bool = False

    def calculate_overall(self):
        if not self.functions:
            return
        scores = [f.current_stage.value for f in self.functions]
        avg = sum(scores) / len(scores)
        self.overall_stage = MaturityStage(int(avg))

    def check_compliance(self):
        req = OMB_M2209_REQUIREMENTS.get(self.pillar_name)
        if req:
            self.compliance_gap = self.overall_stage < req["target_stage"]


@dataclass
class RoadmapItem:
    pillar: str
    function_name: str
    current_stage: str
    target_stage: str
    priority: int  # 1=highest, 4=lowest
    effort: str  # low, medium, high
    recommendations: list = field(default_factory=list)
    dependencies: list = field(default_factory=list)


class ZTMMAssessment:
    """Full CISA Zero Trust Maturity Model assessment engine."""

    def __init__(self, organization_name: str):
        self.organization = organization_name
        self.assessment_date = datetime.datetime.now().isoformat()
        self.pillar_assessments: dict[str, PillarAssessment] = {}
        self.roadmap: list[RoadmapItem] = []

    def assess_function(
        self,
        pillar: str,
        function_name: str,
        current_stage: int,
        target_stage: int = 3,
        evidence: str = "",
        gaps: Optional[list] = None,
    ) -> FunctionAssessment:
        current = MaturityStage(current_stage)
        target = MaturityStage(target_stage)
        fa = FunctionAssessment(
            function_name=function_name,
            current_stage=current,
            target_stage=target,
            evidence=evidence,
            gaps=gaps or [],
        )
        if pillar not in self.pillar_assessments:
            self.pillar_assessments[pillar] = PillarAssessment(pillar_name=pillar)
        self.pillar_assessments[pillar].functions.append(fa)
        return fa

    def calculate_maturity(self):
        for pa in self.pillar_assessments.values():
            pa.calculate_overall()
            pa.check_compliance()

    def generate_roadmap(self) -> list[RoadmapItem]:
        self.roadmap = []
        effort_map = {0: "high", 1: "medium", 2: "low", 3: "low"}

        for pillar_name, pa in self.pillar_assessments.items():
            for func in pa.functions:
                if func.current_stage < func.target_stage:
                    gap = func.target_stage.value - func.current_stage.value
                    next_stage = MaturityStage(func.current_stage.value + 1)
                    item = RoadmapItem(
                        pillar=pillar_name,
                        function_name=func.function_name,
                        current_stage=func.current_stage.name,
                        target_stage=next_stage.name,
                        priority=max(1, 4 - gap),
                        effort=effort_map.get(func.current_stage.value, "high"),
                        recommendations=func.recommendations,
                    )
                    self.roadmap.append(item)

        self.roadmap.sort(key=lambda x: (x.priority, x.effort != "low"))
        return self.roadmap

    def get_compliance_status(self) -> dict:
        status = {}
        for pillar_name, pa in self.pillar_assessments.items():
            req = OMB_M2209_REQUIREMENTS.get(pillar_name, {})
            status[pillar_name] = {
                "current_stage": pa.overall_stage.name,
                "required_stage": req.get("target_stage", MaturityStage.ADVANCED).name,
                "compliant": not pa.compliance_gap,
                "requirement": req.get("requirement", "N/A"),
                "key_actions": req.get("key_actions", []),
            }
        return status

    def get_summary(self) -> dict:
        summary = {
            "organization": self.organization,
            "assessment_date": self.assessment_date,
            "pillars": {},
            "overall_maturity": "TRADITIONAL",
        }
        stages = []
        for name, pa in self.pillar_assessments.items():
            summary["pillars"][name] = {
                "stage": pa.overall_stage.name,
                "score": pa.overall_stage.value,
                "functions_assessed": len(pa.functions),
                "compliance_gap": pa.compliance_gap,
            }
            stages.append(pa.overall_stage.value)

        if stages:
            avg = sum(stages) / len(stages)
            summary["overall_maturity"] = MaturityStage(int(avg)).name
            summary["overall_score"] = round(avg, 2)

        return summary

    def export_report(self, output_path: str):
        report = {
            "summary": self.get_summary(),
            "compliance_status": self.get_compliance_status(),
            "roadmap": [
                {
                    "pillar": r.pillar,
                    "function": r.function_name,
                    "current": r.current_stage,
                    "target": r.target_stage,
                    "priority": r.priority,
                    "effort": r.effort,
                }
                for r in self.roadmap
            ],
            "detailed_assessments": {},
        }

        for name, pa in self.pillar_assessments.items():
            report["detailed_assessments"][name] = {
                "overall_stage": pa.overall_stage.name,
                "functions": [
                    {
                        "name": f.function_name,
                        "current": f.current_stage.name,
                        "target": f.target_stage.name,
                        "evidence": f.evidence,
                        "gaps": f.gaps,
                    }
                    for f in pa.functions
                ],
            }

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        return report

    def export_csv(self, output_path: str):
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Pillar", "Function", "Current Stage", "Target Stage",
                "Gap", "Priority", "Effort", "Evidence"
            ])
            for name, pa in self.pillar_assessments.items():
                for func in pa.functions:
                    gap = func.target_stage.value - func.current_stage.value
                    writer.writerow([
                        name, func.function_name,
                        func.current_stage.name, func.target_stage.name,
                        gap, max(1, 4 - gap),
                        "high" if func.current_stage == MaturityStage.TRADITIONAL else "medium",
                        func.evidence,
                    ])


def run_sample_assessment():
    """Run a sample assessment demonstrating the ZTMM assessment process."""
    assessment = ZTMMAssessment("Example Federal Agency")

    # Identity Pillar Assessment
    assessment.assess_function("Identity", "authentication", 1, 3,
                               evidence="MFA deployed for 60% of users, not phishing-resistant",
                               gaps=["No FIDO2/WebAuthn deployment", "Service accounts lack MFA"])
    assessment.assess_function("Identity", "identity_stores", 1, 3,
                               evidence="Centralized AD, partial cloud identity integration")
    assessment.assess_function("Identity", "risk_assessment", 0, 3,
                               evidence="No risk-based authentication in place")
    assessment.assess_function("Identity", "access_management", 1, 3,
                               evidence="Basic RBAC, no attribute-based access control")
    assessment.assess_function("Identity", "identity_lifecycle", 1, 3,
                               evidence="Manual provisioning, no HR integration")

    # Devices Pillar Assessment
    assessment.assess_function("Devices", "policy_enforcement", 1, 3,
                               evidence="MDM deployed, basic compliance checks")
    assessment.assess_function("Devices", "asset_management", 1, 3,
                               evidence="Partial inventory, no IoT coverage")
    assessment.assess_function("Devices", "device_compliance", 0, 3,
                               evidence="No real-time compliance checking")
    assessment.assess_function("Devices", "device_threat_protection", 1, 3,
                               evidence="EDR on 70% of endpoints")

    # Networks Pillar Assessment
    assessment.assess_function("Networks", "network_segmentation", 0, 3,
                               evidence="Flat network, basic VLAN segmentation only")
    assessment.assess_function("Networks", "threat_protection", 1, 3,
                               evidence="Perimeter firewall, no NDR")
    assessment.assess_function("Networks", "encryption", 1, 3,
                               evidence="TLS for external, plaintext internal")
    assessment.assess_function("Networks", "network_resilience", 1, 3,
                               evidence="Basic redundancy, no SD-WAN")

    # Applications Pillar Assessment
    assessment.assess_function("Applications", "access_authorization", 1, 3,
                               evidence="VPN-based access for internal apps")
    assessment.assess_function("Applications", "threat_protection", 1, 3,
                               evidence="WAF for public apps only")
    assessment.assess_function("Applications", "application_security", 0, 3,
                               evidence="Annual pen tests, no CI/CD security integration")

    # Data Pillar Assessment
    assessment.assess_function("Data", "data_inventory", 0, 3,
                               evidence="No comprehensive data inventory")
    assessment.assess_function("Data", "data_categorization", 1, 3,
                               evidence="Basic classification, manual process")
    assessment.assess_function("Data", "data_access", 1, 3,
                               evidence="Role-based access, no fine-grained controls")
    assessment.assess_function("Data", "data_encryption", 1, 3,
                               evidence="Encryption at rest for databases, not all storage")

    # Calculate and report
    assessment.calculate_maturity()
    roadmap = assessment.generate_roadmap()

    print("=" * 70)
    print(f"CISA ZTMM Assessment: {assessment.organization}")
    print(f"Date: {assessment.assessment_date}")
    print("=" * 70)

    summary = assessment.get_summary()
    print(f"\nOverall Maturity: {summary['overall_maturity']} (Score: {summary.get('overall_score', 'N/A')})")
    print("\nPillar Maturity Scores:")
    for pillar, data in summary["pillars"].items():
        compliance = " [COMPLIANCE GAP]" if data["compliance_gap"] else " [COMPLIANT]"
        print(f"  {pillar:20s}: {data['stage']:12s} (Score: {data['score']}){compliance}")

    print("\nOMB M-22-09 Compliance Status:")
    compliance = assessment.get_compliance_status()
    for pillar, status in compliance.items():
        icon = "PASS" if status["compliant"] else "FAIL"
        print(f"  [{icon}] {pillar}: {status['current_stage']} / Required: {status['required_stage']}")

    print(f"\nPrioritized Roadmap ({len(roadmap)} items):")
    for i, item in enumerate(roadmap[:10], 1):
        print(f"  {i}. [{item.pillar}] {item.function_name}: "
              f"{item.current_stage} -> {item.target_stage} "
              f"(Priority: {item.priority}, Effort: {item.effort})")

    # Export reports
    assessment.export_report("ztmm_assessment_report.json")
    assessment.export_csv("ztmm_assessment_report.csv")
    print("\nReports exported: ztmm_assessment_report.json, ztmm_assessment_report.csv")


if __name__ == "__main__":
    run_sample_assessment()
