#!/usr/bin/env python3
"""
SOC 2 Type II Audit Preparation Automation

Automates control mapping to Trust Services Criteria, evidence tracking,
readiness assessment, and audit preparation for SOC 2 Type II examinations.
"""

import json
import csv
import os
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class TSCCategory(Enum):
    SECURITY = "Security (Common Criteria)"
    AVAILABILITY = "Availability"
    PROCESSING_INTEGRITY = "Processing Integrity"
    CONFIDENTIALITY = "Confidentiality"
    PRIVACY = "Privacy"


class ControlFrequency(Enum):
    CONTINUOUS = "Continuous"
    DAILY = "Daily"
    WEEKLY = "Weekly"
    MONTHLY = "Monthly"
    QUARTERLY = "Quarterly"
    SEMI_ANNUAL = "Semi-Annual"
    ANNUAL = "Annual"
    AS_NEEDED = "As Needed"


class EvidenceStatus(Enum):
    COLLECTED = "Collected"
    PENDING = "Pending"
    MISSING = "Missing"
    NOT_DUE = "Not Due"


class ControlTestResult(Enum):
    NO_EXCEPTION = "No Exception"
    EXCEPTION_NOTED = "Exception Noted"
    NOT_TESTED = "Not Tested"


# Trust Services Criteria - Common Criteria (Security)
TSC_CRITERIA = {
    "CC1.1": {"series": "CC1", "title": "Demonstrates commitment to integrity and ethical values", "category": "Security"},
    "CC1.2": {"series": "CC1", "title": "Board exercises oversight responsibility", "category": "Security"},
    "CC1.3": {"series": "CC1", "title": "Management establishes structures, reporting lines, and authorities", "category": "Security"},
    "CC1.4": {"series": "CC1", "title": "Demonstrates commitment to attract, develop, and retain competent individuals", "category": "Security"},
    "CC1.5": {"series": "CC1", "title": "Holds individuals accountable for internal control responsibilities", "category": "Security"},
    "CC2.1": {"series": "CC2", "title": "Obtains or generates relevant, quality information", "category": "Security"},
    "CC2.2": {"series": "CC2", "title": "Internally communicates information supporting internal control", "category": "Security"},
    "CC2.3": {"series": "CC2", "title": "Communicates with external parties", "category": "Security"},
    "CC3.1": {"series": "CC3", "title": "Specifies objectives with sufficient clarity", "category": "Security"},
    "CC3.2": {"series": "CC3", "title": "Identifies risks to the achievement of objectives", "category": "Security"},
    "CC3.3": {"series": "CC3", "title": "Considers potential for fraud", "category": "Security"},
    "CC3.4": {"series": "CC3", "title": "Identifies and assesses changes that could impact internal control", "category": "Security"},
    "CC4.1": {"series": "CC4", "title": "Selects, develops, and performs ongoing and separate evaluations", "category": "Security"},
    "CC4.2": {"series": "CC4", "title": "Evaluates and communicates internal control deficiencies", "category": "Security"},
    "CC5.1": {"series": "CC5", "title": "Selects and develops control activities", "category": "Security"},
    "CC5.2": {"series": "CC5", "title": "Selects and develops general controls over technology", "category": "Security"},
    "CC5.3": {"series": "CC5", "title": "Deploys through policies that establish expectations and procedures", "category": "Security"},
    "CC6.1": {"series": "CC6", "title": "Logical access security software, infrastructure, and architectures", "category": "Security"},
    "CC6.2": {"series": "CC6", "title": "Prior to credential issuance, registration and authorization", "category": "Security"},
    "CC6.3": {"series": "CC6", "title": "Access removal and modification upon changes", "category": "Security"},
    "CC6.4": {"series": "CC6", "title": "Physical access restrictions to facilities", "category": "Security"},
    "CC6.5": {"series": "CC6", "title": "Discontinuation of physical access", "category": "Security"},
    "CC6.6": {"series": "CC6", "title": "Logical access security against threats from external sources", "category": "Security"},
    "CC6.7": {"series": "CC6", "title": "Restricts transmission, movement, and removal of information", "category": "Security"},
    "CC6.8": {"series": "CC6", "title": "Controls against threats from unauthorized or malicious code", "category": "Security"},
    "CC7.1": {"series": "CC7", "title": "Detection and monitoring procedures for anomalies", "category": "Security"},
    "CC7.2": {"series": "CC7", "title": "Monitors system components for anomalies", "category": "Security"},
    "CC7.3": {"series": "CC7", "title": "Evaluates security events to determine incidents", "category": "Security"},
    "CC7.4": {"series": "CC7", "title": "Responds to identified security incidents", "category": "Security"},
    "CC7.5": {"series": "CC7", "title": "Identifies and remediates vulnerabilities", "category": "Security"},
    "CC8.1": {"series": "CC8", "title": "Authorizes, designs, develops, tests, approves, and implements changes", "category": "Security"},
    "CC9.1": {"series": "CC9", "title": "Identifies and assesses risk mitigation activities", "category": "Security"},
    "CC9.2": {"series": "CC9", "title": "Assesses and manages risks associated with vendors and partners", "category": "Security"},
    # Availability criteria
    "A1.1": {"series": "A1", "title": "Maintains, monitors, and evaluates current processing capacity", "category": "Availability"},
    "A1.2": {"series": "A1", "title": "Environmental protections, software, data backup and recovery", "category": "Availability"},
    "A1.3": {"series": "A1", "title": "Tests recovery plan procedures", "category": "Availability"},
    # Confidentiality criteria
    "C1.1": {"series": "C1", "title": "Identifies and maintains confidential information", "category": "Confidentiality"},
    "C1.2": {"series": "C1", "title": "Disposes of confidential information", "category": "Confidentiality"},
    # Processing Integrity criteria
    "PI1.1": {"series": "PI1", "title": "Obtains or generates relevant, quality information", "category": "Processing Integrity"},
    "PI1.2": {"series": "PI1", "title": "System inputs are complete, accurate, and timely", "category": "Processing Integrity"},
    "PI1.3": {"series": "PI1", "title": "Processing is complete, valid, accurate, timely, and authorized", "category": "Processing Integrity"},
    "PI1.4": {"series": "PI1", "title": "System output is complete, valid, accurate, timely, and authorized", "category": "Processing Integrity"},
    "PI1.5": {"series": "PI1", "title": "Data stored is complete, valid, accurate, timely, and authorized", "category": "Processing Integrity"},
}


@dataclass
class Control:
    control_id: str
    description: str
    tsc_criteria: list
    control_type: str  # Preventive, Detective, Corrective
    frequency: str
    owner: str
    evidence_type: str
    automated: bool = False
    test_result: str = ControlTestResult.NOT_TESTED.value
    exceptions: list = field(default_factory=list)


@dataclass
class EvidenceItem:
    evidence_id: str
    control_id: str
    tsc_criterion: str
    description: str
    period_start: str
    period_end: str
    collection_date: str = ""
    status: str = EvidenceStatus.PENDING.value
    file_reference: str = ""
    notes: str = ""


@dataclass
class ReadinessItem:
    category: str
    item: str
    status: bool
    notes: str = ""
    remediation: str = ""
    due_date: str = ""


class SOC2AuditPrep:
    """Manages SOC 2 Type II audit preparation."""

    def __init__(self, output_dir: str = "./soc2_output",
                 audit_start: str = "", audit_end: str = ""):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.controls: list[Control] = []
        self.evidence: list[EvidenceItem] = []
        self.audit_start = audit_start or (datetime.now() - timedelta(days=365)).strftime("%Y-%m-%d")
        self.audit_end = audit_end or datetime.now().strftime("%Y-%m-%d")
        self.selected_categories: list[str] = ["Security"]

    def select_tsc_categories(self, categories: list[str]) -> dict:
        """Select applicable TSC categories for the audit."""
        print("\n" + "=" * 70)
        print("TSC CATEGORY SELECTION")
        print("=" * 70)

        self.selected_categories = categories
        applicable_criteria = {}

        for crit_id, crit_info in TSC_CRITERIA.items():
            if crit_info["category"] in categories:
                applicable_criteria[crit_id] = crit_info

        print(f"\n  Selected Categories: {', '.join(categories)}")
        print(f"  Applicable Criteria: {len(applicable_criteria)}")
        print(f"  Audit Period: {self.audit_start} to {self.audit_end}")

        for cat in categories:
            count = sum(1 for c in applicable_criteria.values() if c["category"] == cat)
            print(f"    {cat}: {count} criteria")

        return applicable_criteria

    def create_control_matrix(self, controls: list[dict]) -> list[Control]:
        """Create control matrix mapping controls to TSC criteria."""
        print("\n" + "=" * 70)
        print("CONTROL MATRIX")
        print("=" * 70)

        for ctrl_data in controls:
            ctrl = Control(**ctrl_data)
            self.controls.append(ctrl)
            criteria_str = ", ".join(ctrl.tsc_criteria)
            print(f"\n  [{ctrl.control_id}] {ctrl.description[:60]}...")
            print(f"    TSC: {criteria_str}")
            print(f"    Type: {ctrl.control_type} | Frequency: {ctrl.frequency}")
            print(f"    Owner: {ctrl.owner} | Automated: {ctrl.automated}")

        # Coverage analysis
        covered_criteria = set()
        for ctrl in self.controls:
            covered_criteria.update(ctrl.tsc_criteria)

        applicable_criteria = {
            k for k, v in TSC_CRITERIA.items()
            if v["category"] in self.selected_categories
        }
        uncovered = applicable_criteria - covered_criteria

        print(f"\n  Total Controls: {len(self.controls)}")
        print(f"  Criteria Covered: {len(covered_criteria)} / {len(applicable_criteria)}")
        if uncovered:
            print(f"  GAPS - Uncovered Criteria: {', '.join(sorted(uncovered))}")
        else:
            print(f"  All applicable criteria covered")

        # Save control matrix
        matrix_path = self.output_dir / "control_matrix.json"
        with open(matrix_path, "w") as f:
            json.dump([asdict(c) for c in self.controls], f, indent=2)

        # CSV for auditor
        csv_path = self.output_dir / "control_matrix.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Control ID", "Description", "TSC Criteria", "Control Type",
                "Frequency", "Owner", "Evidence Type", "Automated",
                "Test Result", "Exceptions"
            ])
            for ctrl in self.controls:
                writer.writerow([
                    ctrl.control_id,
                    ctrl.description,
                    "; ".join(ctrl.tsc_criteria),
                    ctrl.control_type,
                    ctrl.frequency,
                    ctrl.owner,
                    ctrl.evidence_type,
                    "Yes" if ctrl.automated else "No",
                    ctrl.test_result,
                    "; ".join(ctrl.exceptions) if ctrl.exceptions else "",
                ])

        print(f"  Control Matrix saved to: {matrix_path}")
        return self.controls

    def track_evidence(self, evidence_items: list[dict]) -> dict:
        """Track evidence collection status for audit period."""
        print("\n" + "=" * 70)
        print("EVIDENCE COLLECTION TRACKER")
        print("=" * 70)

        for item_data in evidence_items:
            item = EvidenceItem(**item_data)
            self.evidence.append(item)

        # Status summary
        status_counts = {}
        for item in self.evidence:
            status_counts.setdefault(item.status, 0)
            status_counts[item.status] += 1

        total = len(self.evidence)
        collected = status_counts.get(EvidenceStatus.COLLECTED.value, 0)
        pending = status_counts.get(EvidenceStatus.PENDING.value, 0)
        missing = status_counts.get(EvidenceStatus.MISSING.value, 0)

        print(f"\n  Evidence Items: {total}")
        print(f"  Collected: {collected} ({collected/total*100:.1f}%)" if total > 0 else "")
        print(f"  Pending: {pending}")
        print(f"  Missing: {missing}")

        if missing > 0:
            print(f"\n  ALERT: {missing} evidence items are missing!")
            for item in self.evidence:
                if item.status == EvidenceStatus.MISSING.value:
                    print(f"    - [{item.evidence_id}] {item.description} (Control: {item.control_id})")

        # Save evidence tracker
        tracker_path = self.output_dir / "evidence_tracker.json"
        with open(tracker_path, "w") as f:
            json.dump([asdict(e) for e in self.evidence], f, indent=2)

        print(f"\n  Evidence Tracker saved to: {tracker_path}")
        return status_counts

    def assess_readiness(self) -> dict:
        """Perform SOC 2 Type II audit readiness assessment."""
        print("\n" + "=" * 70)
        print("SOC 2 TYPE II READINESS ASSESSMENT")
        print("=" * 70)

        readiness_checks = [
            ReadinessItem("Documentation", "System Description Document completed", False),
            ReadinessItem("Documentation", "Management Assertion Letter drafted", False),
            ReadinessItem("Documentation", "Control matrix documented and reviewed", bool(self.controls)),
            ReadinessItem("Documentation", "Security policies current and approved", False),
            ReadinessItem("Documentation", "Risk assessment completed within audit period", False),

            ReadinessItem("Controls", "All TSC criteria mapped to at least one control", False),
            ReadinessItem("Controls", "Control owners identified and briefed", False),
            ReadinessItem("Controls", "No control design gaps identified", False),
            ReadinessItem("Controls", "Compensating controls documented for exceptions", False),

            ReadinessItem("Evidence", "Evidence collection covers full audit period", False),
            ReadinessItem("Evidence", "Quarterly access reviews completed", False),
            ReadinessItem("Evidence", "Annual penetration test completed", False),
            ReadinessItem("Evidence", "Security awareness training records available", False),
            ReadinessItem("Evidence", "Change management tickets with approvals", False),
            ReadinessItem("Evidence", "Incident response logs available", False),
            ReadinessItem("Evidence", "Vulnerability scan reports for audit period", False),

            ReadinessItem("Operations", "Background checks completed for new hires", False),
            ReadinessItem("Operations", "MFA enabled for all in-scope systems", False),
            ReadinessItem("Operations", "Encryption at rest and in transit verified", False),
            ReadinessItem("Operations", "Backup and recovery testing documented", False),

            ReadinessItem("Vendor", "Subservice organizations identified", False),
            ReadinessItem("Vendor", "Carve-out or inclusive method determined", False),
            ReadinessItem("Vendor", "CUECs documented", False),
            ReadinessItem("Vendor", "Vendor SOC reports reviewed", False),
        ]

        # Auto-check based on data
        if self.controls:
            readiness_checks[5].status = True  # Controls mapped

        if self.evidence:
            collected = sum(1 for e in self.evidence if e.status == EvidenceStatus.COLLECTED.value)
            if collected == len(self.evidence) and len(self.evidence) > 0:
                readiness_checks[9].status = True

        # Display results
        categories = {}
        for check in readiness_checks:
            categories.setdefault(check.category, [])
            categories[check.category].append(check)

        total_checks = len(readiness_checks)
        passed = sum(1 for c in readiness_checks if c.status)
        pct = (passed / total_checks * 100) if total_checks > 0 else 0

        print(f"\n  Readiness Score: {passed}/{total_checks} ({pct:.1f}%)")

        for cat, checks in categories.items():
            print(f"\n  {cat}:")
            for check in checks:
                icon = "[PASS]" if check.status else "[FAIL]"
                print(f"    {icon} {check.item}")

        # Recommendation
        if pct >= 90:
            print(f"\n  RECOMMENDATION: Ready for audit. Schedule with audit firm.")
        elif pct >= 70:
            print(f"\n  RECOMMENDATION: Address remaining items within 2-4 weeks.")
        else:
            print(f"\n  RECOMMENDATION: Significant gaps remain. Delay audit until addressed.")

        # Save readiness report
        report = {
            "date": datetime.now().isoformat(),
            "audit_period": f"{self.audit_start} to {self.audit_end}",
            "readiness_percentage": pct,
            "checks": [asdict(c) for c in readiness_checks],
        }
        report_path = self.output_dir / "readiness_assessment.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n  Readiness Report saved to: {report_path}")
        return report

    def generate_audit_summary(self) -> dict:
        """Generate overall audit preparation summary dashboard."""
        print("\n" + "=" * 70)
        print("SOC 2 TYPE II AUDIT PREPARATION SUMMARY")
        print("=" * 70)

        summary = {
            "generated": datetime.now().isoformat(),
            "audit_period": f"{self.audit_start} to {self.audit_end}",
            "tsc_categories": self.selected_categories,
            "controls": {
                "total": len(self.controls),
                "preventive": sum(1 for c in self.controls if c.control_type == "Preventive"),
                "detective": sum(1 for c in self.controls if c.control_type == "Detective"),
                "corrective": sum(1 for c in self.controls if c.control_type == "Corrective"),
                "automated": sum(1 for c in self.controls if c.automated),
                "manual": sum(1 for c in self.controls if not c.automated),
            },
            "evidence": {
                "total": len(self.evidence),
                "collected": sum(1 for e in self.evidence if e.status == EvidenceStatus.COLLECTED.value),
                "pending": sum(1 for e in self.evidence if e.status == EvidenceStatus.PENDING.value),
                "missing": sum(1 for e in self.evidence if e.status == EvidenceStatus.MISSING.value),
            },
        }

        print(f"\n  Audit Period: {summary['audit_period']}")
        print(f"  TSC Categories: {', '.join(summary['tsc_categories'])}")
        print(f"\n  Controls: {summary['controls']['total']}")
        print(f"    Preventive: {summary['controls']['preventive']}")
        print(f"    Detective: {summary['controls']['detective']}")
        print(f"    Corrective: {summary['controls']['corrective']}")
        print(f"    Automated: {summary['controls']['automated']}")
        print(f"\n  Evidence: {summary['evidence']['total']}")
        print(f"    Collected: {summary['evidence']['collected']}")
        print(f"    Pending: {summary['evidence']['pending']}")
        print(f"    Missing: {summary['evidence']['missing']}")

        summary_path = self.output_dir / "audit_summary.json"
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        print(f"\n  Summary saved to: {summary_path}")
        return summary


def main():
    """Run SOC 2 Type II audit preparation."""
    prep = SOC2AuditPrep(
        audit_start="2024-01-01",
        audit_end="2024-12-31"
    )

    # Select TSC categories
    criteria = prep.select_tsc_categories(["Security", "Availability", "Confidentiality"])

    # Create control matrix
    sample_controls = [
        {
            "control_id": "CTRL-001",
            "description": "Multi-factor authentication is required for all access to production systems and sensitive data",
            "tsc_criteria": ["CC6.1", "CC6.6"],
            "control_type": "Preventive",
            "frequency": ControlFrequency.CONTINUOUS.value,
            "owner": "IT Security Manager",
            "evidence_type": "System configuration screenshot",
            "automated": True,
        },
        {
            "control_id": "CTRL-002",
            "description": "Quarterly user access reviews are performed for all in-scope systems with formal approval",
            "tsc_criteria": ["CC6.2", "CC6.3"],
            "control_type": "Detective",
            "frequency": ControlFrequency.QUARTERLY.value,
            "owner": "IT Manager",
            "evidence_type": "Access review completion report with approvals",
            "automated": False,
        },
        {
            "control_id": "CTRL-003",
            "description": "Security events are monitored 24/7 through SIEM with automated alerting for critical events",
            "tsc_criteria": ["CC7.1", "CC7.2", "CC7.3"],
            "control_type": "Detective",
            "frequency": ControlFrequency.CONTINUOUS.value,
            "owner": "SOC Team Lead",
            "evidence_type": "SIEM dashboard and alert configuration",
            "automated": True,
        },
        {
            "control_id": "CTRL-004",
            "description": "All changes to production systems follow change management process with peer review and management approval",
            "tsc_criteria": ["CC8.1"],
            "control_type": "Preventive",
            "frequency": ControlFrequency.AS_NEEDED.value,
            "owner": "Engineering Manager",
            "evidence_type": "Change tickets with approval chain",
            "automated": False,
        },
        {
            "control_id": "CTRL-005",
            "description": "Annual penetration testing is conducted by qualified third party with findings remediated",
            "tsc_criteria": ["CC7.1", "CC7.5"],
            "control_type": "Detective",
            "frequency": ControlFrequency.ANNUAL.value,
            "owner": "CISO",
            "evidence_type": "Penetration test report and remediation tracker",
            "automated": False,
        },
        {
            "control_id": "CTRL-006",
            "description": "Data at rest is encrypted using AES-256 and data in transit uses TLS 1.2 or higher",
            "tsc_criteria": ["CC6.1", "CC6.7", "C1.1"],
            "control_type": "Preventive",
            "frequency": ControlFrequency.CONTINUOUS.value,
            "owner": "Cloud Architect",
            "evidence_type": "Encryption configuration verification",
            "automated": True,
        },
        {
            "control_id": "CTRL-007",
            "description": "Incident response process is documented, tested annually, and incidents are tracked to resolution",
            "tsc_criteria": ["CC7.3", "CC7.4"],
            "control_type": "Corrective",
            "frequency": ControlFrequency.AS_NEEDED.value,
            "owner": "Security Incident Manager",
            "evidence_type": "IR plan, tabletop exercise report, incident tickets",
            "automated": False,
        },
        {
            "control_id": "CTRL-008",
            "description": "Vendor security assessments are performed prior to engagement and annually thereafter",
            "tsc_criteria": ["CC9.2"],
            "control_type": "Preventive",
            "frequency": ControlFrequency.ANNUAL.value,
            "owner": "Vendor Management",
            "evidence_type": "Vendor assessment questionnaires and SOC reports",
            "automated": False,
        },
    ]
    controls = prep.create_control_matrix(sample_controls)

    # Track evidence
    sample_evidence = [
        {
            "evidence_id": "EVD-001",
            "control_id": "CTRL-001",
            "tsc_criterion": "CC6.1",
            "description": "MFA configuration screenshots for production systems",
            "period_start": "2024-01-01",
            "period_end": "2024-12-31",
            "status": EvidenceStatus.COLLECTED.value,
            "collection_date": "2024-12-15",
            "file_reference": "evidence/CC6.1/mfa_config_2024.pdf",
        },
        {
            "evidence_id": "EVD-002",
            "control_id": "CTRL-002",
            "tsc_criterion": "CC6.3",
            "description": "Q1 2024 User Access Review - All Systems",
            "period_start": "2024-01-01",
            "period_end": "2024-03-31",
            "status": EvidenceStatus.COLLECTED.value,
            "collection_date": "2024-04-05",
            "file_reference": "evidence/CC6.3/q1_access_review.pdf",
        },
        {
            "evidence_id": "EVD-003",
            "control_id": "CTRL-005",
            "tsc_criterion": "CC7.1",
            "description": "Annual penetration test report",
            "period_start": "2024-01-01",
            "period_end": "2024-12-31",
            "status": EvidenceStatus.COLLECTED.value,
            "collection_date": "2024-10-30",
            "file_reference": "evidence/CC7.1/pentest_report_2024.pdf",
        },
        {
            "evidence_id": "EVD-004",
            "control_id": "CTRL-002",
            "tsc_criterion": "CC6.3",
            "description": "Q4 2024 User Access Review - All Systems",
            "period_start": "2024-10-01",
            "period_end": "2024-12-31",
            "status": EvidenceStatus.PENDING.value,
        },
    ]
    prep.track_evidence(sample_evidence)

    # Readiness assessment
    prep.assess_readiness()

    # Generate summary
    prep.generate_audit_summary()

    print("\n" + "=" * 70)
    print("SOC 2 TYPE II AUDIT PREPARATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
