#!/usr/bin/env python3
"""
Ransomware Tabletop Exercise Generator and Evaluator

Generates customized ransomware tabletop exercise scenarios based on:
- Organization type (healthcare, financial, manufacturing, etc.)
- Threat actor profile (LockBit, ALPHV, Cl0p, Rhysida)
- Infrastructure profile (on-prem, cloud, hybrid)
- Regulatory requirements

Evaluates exercise results and generates after-action reports.
"""

import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


THREAT_ACTORS = {
    "lockbit": {
        "name": "LockBit 3.0",
        "initial_access": ["Phishing with macro-enabled documents", "RDP brute force",
                          "Exploitation of VPN vulnerabilities (Citrix, Fortinet)"],
        "tools": ["Cobalt Strike", "Mimikatz", "PsExec", "Stealbit (data exfiltration)"],
        "ttps": ["Disables Windows Defender via GPO", "Deletes shadow copies with vssadmin",
                "Uses group policy to deploy ransomware across domain",
                "Double extortion with data leak site"],
        "avg_dwell_time": "4-14 days",
        "ransom_range": "$100K - $50M",
        "negotiation_style": "Automated chat portal, deadline-driven",
    },
    "alphv": {
        "name": "ALPHV/BlackCat",
        "initial_access": ["Compromised credentials from IABs", "Exchange server exploitation",
                          "Social engineering of help desk"],
        "tools": ["Cobalt Strike", "Brute Ratel", "Impacket", "ExMatter (exfiltration)"],
        "ttps": ["Written in Rust (cross-platform)", "Targets ESXi hypervisors",
                "Triple extortion (encrypt + leak + DDoS)", "Destroys backups before encryption"],
        "avg_dwell_time": "5-21 days",
        "ransom_range": "$200K - $35M",
        "negotiation_style": "Dedicated Tor negotiation site, threatens DDoS",
    },
    "clop": {
        "name": "Cl0p",
        "initial_access": ["Zero-day exploitation of file transfer platforms (MOVEit, GoAnywhere, Accellion)",
                          "Supply chain compromise"],
        "tools": ["FlawedAmmyy RAT", "SDBot", "TrueBot", "Custom exfiltration tools"],
        "ttps": ["Mass exploitation campaigns", "Data theft without encryption in many cases",
                "Targets managed file transfer (MFT) platforms", "Extended extortion timeline"],
        "avg_dwell_time": "1-7 days (mass exploitation)",
        "ransom_range": "$500K - $20M",
        "negotiation_style": "Email-based, group negotiations for mass attacks",
    },
    "rhysida": {
        "name": "Rhysida",
        "initial_access": ["Phishing", "VPN without MFA exploitation",
                          "Valid credentials purchased from IABs"],
        "tools": ["Cobalt Strike", "PsExec", "PowerShell scripts", "ChaCha20 encryption"],
        "ttps": ["Targets healthcare and education", "Uses living-off-the-land binaries (LOLBins)",
                "Deletes VSS and disables Windows recovery", "Auctions stolen data on leak site"],
        "avg_dwell_time": "3-10 days",
        "ransom_range": "$50K - $15M",
        "negotiation_style": "Tor-based auction site, victim-shaming approach",
    },
}

INDUSTRY_PROFILES = {
    "healthcare": {
        "critical_systems": ["EMR/EHR", "PACS (medical imaging)", "Laboratory Information System",
                           "Pharmacy Management", "Patient Portal", "Medical Devices/IoT"],
        "data_types": ["PHI (Protected Health Information)", "Patient records", "Insurance data",
                      "Clinical trial data", "Employee PII"],
        "regulations": ["HIPAA", "HITECH Act", "State breach notification laws"],
        "notification_timeline": "60 days to individuals, ASAP to HHS OCR if >500 affected",
        "operational_impact": "Patient safety - diversion to other facilities, manual charting",
        "insurance_considerations": "Cyber liability + professional liability intersection",
    },
    "financial": {
        "critical_systems": ["Core banking platform", "Trading systems", "ATM network",
                           "Wire transfer system", "Customer portal", "SWIFT messaging"],
        "data_types": ["PII", "Financial records", "Account numbers", "SSNs",
                      "Transaction histories", "Internal financial data"],
        "regulations": ["GLBA", "SOX", "PCI DSS", "SEC 8-K", "NY DFS 23 NYCRR 500", "GDPR"],
        "notification_timeline": "72 hours (NY DFS), 4 business days (SEC 8-K)",
        "operational_impact": "Transaction processing halt, customer account access disruption",
        "insurance_considerations": "Financial institution bond + cyber liability",
    },
    "manufacturing": {
        "critical_systems": ["SCADA/ICS", "MES (Manufacturing Execution System)", "ERP",
                           "Supply chain management", "Quality management system"],
        "data_types": ["Trade secrets", "Design specifications", "Customer PII",
                      "Supply chain data", "Financial records"],
        "regulations": ["Industry-specific (FDA, NHTSA)", "State breach notification", "GDPR"],
        "notification_timeline": "Varies by state/jurisdiction",
        "operational_impact": "Production line shutdown, supply chain disruption, safety concerns",
        "insurance_considerations": "Business interruption + cyber liability + product liability",
    },
    "education": {
        "critical_systems": ["Student Information System", "Learning Management System",
                           "Email/collaboration", "Research data systems", "Financial aid"],
        "data_types": ["Student PII (FERPA)", "Research data", "Financial aid records",
                      "Employee PII", "Healthcare records (student health)"],
        "regulations": ["FERPA", "HIPAA (student health)", "State breach notification"],
        "notification_timeline": "Varies by state, FERPA has no specific timeline",
        "operational_impact": "Class disruption, research data loss, enrollment processing halt",
        "insurance_considerations": "Education-specific cyber liability policies",
    },
}


@dataclass
class ExerciseInject:
    phase: int
    time_offset_minutes: int
    title: str
    description: str
    decision_required: str
    pressure_element: str


@dataclass
class ExerciseScenario:
    organization: str
    industry: str
    threat_actor: str
    date: str
    duration_hours: float
    participants: list
    scenario_summary: str
    phases: list = field(default_factory=list)
    injects: list = field(default_factory=list)
    evaluation_areas: list = field(default_factory=list)


@dataclass
class ExerciseEvaluation:
    area: str
    score: int  # 1-5
    strengths: list
    gaps: list
    remediation_actions: list


class TabletopGenerator:
    """Generates customized ransomware tabletop exercise scenarios."""

    def __init__(self, org_name: str, industry: str, threat_actor: str):
        self.org_name = org_name
        if industry not in INDUSTRY_PROFILES:
            raise ValueError(f"Unknown industry: {industry}. Choose from: {list(INDUSTRY_PROFILES.keys())}")
        if threat_actor not in THREAT_ACTORS:
            raise ValueError(f"Unknown threat actor: {threat_actor}. Choose from: {list(THREAT_ACTORS.keys())}")
        self.industry = INDUSTRY_PROFILES[industry]
        self.actor = THREAT_ACTORS[threat_actor]
        self.industry_name = industry
        self.scenario = None

    def generate_scenario(self, encrypted_percentage: int = 60,
                         data_exfiltrated: bool = True,
                         backups_intact: bool = True,
                         ransom_amount: str = "$2,000,000") -> ExerciseScenario:
        """Generate a complete exercise scenario."""

        scenario = ExerciseScenario(
            organization=self.org_name,
            industry=self.industry_name,
            threat_actor=self.actor["name"],
            date=datetime.now().strftime("%Y-%m-%d"),
            duration_hours=3.5,
            participants=[
                "CISO / Security Director",
                "CIO / IT Director",
                "General Counsel / Legal",
                "VP Communications / PR",
                "Operations / Business Unit Leader",
                "CFO / Finance",
                "HR Director",
                "External IR firm (optional)",
            ],
            scenario_summary=(
                f"The {self.actor['name']} ransomware group has compromised {self.org_name}'s "
                f"network using {self.actor['initial_access'][0].lower()}. After approximately "
                f"{self.actor['avg_dwell_time']} of dwell time, the attackers have encrypted "
                f"{encrypted_percentage}% of server infrastructure"
                f"{' and exfiltrated sensitive data including ' + self.industry['data_types'][0] if data_exfiltrated else ''}. "
                f"The ransom demand is {ransom_amount} in cryptocurrency with a 72-hour deadline."
            ),
        )

        # Phase 1: Detection
        scenario.phases.append({
            "number": 1,
            "title": "Initial Detection and Triage",
            "duration_minutes": 30,
            "sitrep": (
                f"At 06:15 this morning, the SOC received multiple alerts from the EDR platform "
                f"indicating suspicious process execution on several servers. Investigation reveals "
                f"that {self.actor['tools'][0]} has been deployed on at least 5 systems. "
                f"Users are beginning to report they cannot access {self.industry['critical_systems'][0]}."
            ),
            "discussion_questions": [
                "Who declares the incident? What is the activation criteria?",
                "What is the first action: investigate further or contain immediately?",
                "Who needs to be notified at this stage?",
                "Do we have the forensic capability to investigate in-house?",
            ],
        })

        # Phase 2: Escalation
        scenario.phases.append({
            "number": 2,
            "title": "Full Scope and Ransom Demand",
            "duration_minutes": 30,
            "sitrep": (
                f"It is now 09:00. Assessment confirms {encrypted_percentage}% of servers are encrypted. "
                f"Ransom notes have been found on all affected systems demanding {ransom_amount} "
                f"in Bitcoin. The ransom note includes a Tor link for negotiation and threatens "
                f"to publish stolen data in 72 hours. "
                f"Affected systems include: {', '.join(self.industry['critical_systems'][:3])}."
            ),
            "discussion_questions": [
                "How do we assess the full scope of the breach?",
                "What is our containment strategy? Full shutdown or selective isolation?",
                f"How do we maintain {self.industry['operational_impact'].split(',')[0].lower()} during the outage?",
                "Do we engage law enforcement now or later?",
            ],
        })

        # Phase 3: Decision Points
        backup_status = "Immutable backup copies appear intact. Primary backups on the NAS are encrypted." if backups_intact else "All backup systems have been compromised. The attackers deleted backup catalogs before encrypting."
        scenario.phases.append({
            "number": 3,
            "title": "Critical Decisions",
            "duration_minutes": 45,
            "sitrep": (
                f"It is now 14:00. Forensic analysis confirms: {backup_status} "
                f"{'Recovery from immutable backups is estimated at 5-7 days for full restoration.' if backups_intact else 'Without backups, recovery would require rebuilding from scratch: estimated 3-4 weeks.'} "
                f"The threat actor has posted a sample of stolen {self.industry['data_types'][0]} "
                f"on their leak site as proof of exfiltration. Your cyber insurance carrier has "
                f"engaged a ransomware negotiation firm."
            ),
            "discussion_questions": [
                "Under what conditions would we pay the ransom?",
                f"What are our regulatory notification obligations under {', '.join(self.industry['regulations'][:2])}?",
                "How do we respond to the public data leak?",
                "What is the cost comparison: pay vs. rebuild?",
                "Have we verified the payment recipient against OFAC sanctions?",
            ],
        })

        # Phase 4: Recovery
        scenario.phases.append({
            "number": 4,
            "title": "Recovery and Communication",
            "duration_minutes": 45,
            "sitrep": (
                f"It is Day 3. {'Recovery from immutable backups is underway. AD and DNS are restored. ' if backups_intact else 'The decision has been made to rebuild without paying. '}"
                f"A major customer has contacted the CEO demanding an update within 24 hours "
                f"or they will begin transitioning to a competitor. The media has picked up the "
                f"story and reporters are calling the communications team."
            ),
            "discussion_questions": [
                "What is the system recovery priority order?",
                "What do we tell customers? How much detail?",
                "What is our media statement?",
                "How do we prevent re-infection during recovery?",
                "What evidence must we preserve for law enforcement and insurance?",
            ],
        })

        # Generate injects
        scenario.injects = self._generate_injects(data_exfiltrated, backups_intact)

        # Evaluation areas
        scenario.evaluation_areas = [
            "Detection and Escalation",
            "Containment Decisions",
            "Internal Communication",
            "External Communication (Regulatory, Customer, Media)",
            "Recovery Planning and Execution",
            "Legal and Compliance",
            "Business Continuity",
            "Payment Decision Framework",
        ]

        self.scenario = scenario
        return scenario

    def _generate_injects(self, data_exfiltrated: bool, backups_intact: bool) -> list:
        injects = []

        injects.append(asdict(ExerciseInject(
            phase=1,
            time_offset_minutes=15,
            title="Threat Intelligence Match",
            description=(
                f"Your threat intel provider confirms the C2 infrastructure matches known "
                f"{self.actor['name']} affiliate activity. This group is known for: "
                f"{self.actor['ttps'][0]}"
            ),
            decision_required="Does this change our response urgency or approach?",
            pressure_element="Known aggressive group with history of following through on threats",
        )))

        injects.append(asdict(ExerciseInject(
            phase=2,
            time_offset_minutes=10,
            title="Employee Social Media Leak",
            description=(
                "An employee has posted on social media: 'Our entire network is down, "
                "looks like we got hacked. IT is scrambling.' The post has 500 shares."
            ),
            decision_required="How do we handle unauthorized employee disclosure?",
            pressure_element="Information control is compromised, media may pick up story faster",
        )))

        if data_exfiltrated:
            injects.append(asdict(ExerciseInject(
                phase=3,
                time_offset_minutes=20,
                title="Regulatory Inquiry",
                description=(
                    f"You receive an inquiry from the regulatory authority regarding reports of "
                    f"a data breach involving {self.industry['data_types'][0]}. "
                    f"Notification timeline: {self.industry['notification_timeline']}"
                ),
                decision_required="What information do we provide at this stage?",
                pressure_element="Regulatory clock is ticking, incomplete information available",
            )))

        injects.append(asdict(ExerciseInject(
            phase=4,
            time_offset_minutes=15,
            title="Recovery Complication",
            description=(
                "During restoration of the primary database, the team discovers that the "
                "backup was taken 6 hours before encryption but the attacker had already "
                "planted a persistence mechanism (scheduled task calling beacon). "
                "Restoring this backup will reintroduce the attacker's foothold."
            ),
            decision_required="How do we handle infected but recent backups?",
            pressure_element="Recovery timeline extends, clean backup may be older with more data loss",
        )))

        return injects

    def export_scenario(self, output_dir: str) -> str:
        """Export scenario to JSON file."""
        if not self.scenario:
            self.generate_scenario()

        output_path = Path(output_dir) / f"ttx_scenario_{self.org_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.json"
        with open(output_path, "w") as f:
            json.dump(asdict(self.scenario), f, indent=2)
        return str(output_path)


class ExerciseEvaluator:
    """Evaluates tabletop exercise results and generates AAR."""

    def __init__(self, scenario: ExerciseScenario):
        self.scenario = scenario
        self.evaluations = []

    def add_evaluation(self, area: str, score: int, strengths: list,
                      gaps: list, remediation_actions: list):
        if score < 1 or score > 5:
            raise ValueError("Score must be between 1 and 5")
        self.evaluations.append(ExerciseEvaluation(
            area=area, score=score, strengths=strengths,
            gaps=gaps, remediation_actions=remediation_actions,
        ))

    def calculate_overall_score(self) -> float:
        if not self.evaluations:
            return 0.0
        return round(sum(e.score for e in self.evaluations) / len(self.evaluations), 1)

    def generate_aar(self) -> str:
        """Generate After-Action Report."""
        lines = []
        lines.append("=" * 70)
        lines.append("RANSOMWARE TABLETOP EXERCISE - AFTER ACTION REPORT")
        lines.append("=" * 70)
        lines.append(f"Organization: {self.scenario.organization}")
        lines.append(f"Date: {self.scenario.date}")
        lines.append(f"Threat Actor: {self.scenario.threat_actor}")
        lines.append(f"Industry: {self.scenario.industry}")
        lines.append(f"Duration: {self.scenario.duration_hours} hours")
        lines.append(f"Overall Score: {self.calculate_overall_score()}/5.0")
        lines.append("")
        lines.append("SCENARIO SUMMARY")
        lines.append("-" * 40)
        lines.append(self.scenario.scenario_summary)
        lines.append("")

        lines.append("EVALUATION RESULTS")
        lines.append("-" * 40)
        for eval_item in self.evaluations:
            rating = {1: "Inadequate", 2: "Needs Improvement", 3: "Adequate",
                     4: "Good", 5: "Excellent"}.get(eval_item.score, "N/A")
            lines.append(f"\n  {eval_item.area}: {eval_item.score}/5 ({rating})")
            lines.append("    Strengths:")
            for s in eval_item.strengths:
                lines.append(f"      + {s}")
            lines.append("    Gaps:")
            for g in eval_item.gaps:
                lines.append(f"      - {g}")
            lines.append("    Remediation:")
            for r in eval_item.remediation_actions:
                lines.append(f"      > {r}")

        # Summary statistics
        all_gaps = [g for e in self.evaluations for g in e.gaps]
        all_actions = [a for e in self.evaluations for a in e.remediation_actions]
        lines.append("")
        lines.append("SUMMARY")
        lines.append("-" * 40)
        lines.append(f"Total gaps identified: {len(all_gaps)}")
        lines.append(f"Total remediation actions: {len(all_actions)}")
        lines.append(f"Areas scoring below 3: {sum(1 for e in self.evaluations if e.score < 3)}")
        lines.append("")
        lines.append("=" * 70)

        return "\n".join(lines)


def main():
    """Generate sample tabletop exercise scenario."""
    generator = TabletopGenerator(
        org_name="Acme Healthcare System",
        industry="healthcare",
        threat_actor="rhysida",
    )

    scenario = generator.generate_scenario(
        encrypted_percentage=65,
        data_exfiltrated=True,
        backups_intact=True,
        ransom_amount="$3,500,000",
    )

    # Print scenario overview
    print("=" * 70)
    print("RANSOMWARE TABLETOP EXERCISE SCENARIO")
    print("=" * 70)
    print(f"Organization: {scenario.organization}")
    print(f"Industry: {scenario.industry}")
    print(f"Threat Actor: {scenario.threat_actor}")
    print(f"Duration: {scenario.duration_hours} hours")
    print(f"\nSummary: {scenario.scenario_summary}")
    print(f"\nParticipants: {len(scenario.participants)}")
    for p in scenario.participants:
        print(f"  - {p}")

    print("\nPHASES:")
    for phase in scenario.phases:
        print(f"\n  Phase {phase['number']}: {phase['title']} ({phase['duration_minutes']} min)")
        print(f"  SITREP: {phase['sitrep'][:200]}...")
        print(f"  Questions: {len(phase['discussion_questions'])}")

    print(f"\nINJECTS: {len(scenario.injects)}")
    for inject in scenario.injects:
        print(f"  - Phase {inject['phase']}: {inject['title']}")

    # Export to JSON
    output_path = generator.export_scenario(str(Path(__file__).parent))
    print(f"\nScenario exported to: {output_path}")

    # Demo evaluation
    evaluator = ExerciseEvaluator(scenario)
    evaluator.add_evaluation(
        area="Detection and Escalation",
        score=4,
        strengths=["SOC correctly identified Cobalt Strike indicators",
                   "Incident was declared within 30 minutes"],
        gaps=["No documented criteria for incident declaration threshold"],
        remediation_actions=["Document incident declaration criteria with specific trigger conditions"],
    )
    evaluator.add_evaluation(
        area="Payment Decision Framework",
        score=2,
        strengths=["Legal correctly identified OFAC compliance requirement"],
        gaps=["No pre-established payment decision framework",
              "No pre-engaged negotiation firm",
              "No cryptocurrency procurement mechanism identified"],
        remediation_actions=["Establish ransom payment decision matrix with executive sign-off",
                           "Pre-engage ransomware negotiation firm through cyber insurance",
                           "Identify cryptocurrency procurement path (if payment decision is made)"],
    )

    aar = evaluator.generate_aar()
    print("\n" + aar)


if __name__ == "__main__":
    main()
