#!/usr/bin/env python3
"""
ISO 27001 ISMS Compliance Check Automation

Automates gap analysis, risk assessment tracking, Statement of Applicability
management, and audit readiness checks for ISO/IEC 27001:2022 implementation.
"""

import json
import csv
import os
import sys
from datetime import datetime, timedelta
from typing import Optional
from pathlib import Path
from dataclasses import dataclass, field, asdict
from enum import Enum


class ControlCategory(Enum):
    ORGANIZATIONAL = "A.5"
    PEOPLE = "A.6"
    PHYSICAL = "A.7"
    TECHNOLOGICAL = "A.8"


class ControlStatus(Enum):
    NOT_IMPLEMENTED = "Not Implemented"
    PARTIALLY_IMPLEMENTED = "Partially Implemented"
    FULLY_IMPLEMENTED = "Fully Implemented"
    NOT_APPLICABLE = "Not Applicable"


class RiskLevel(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NEGLIGIBLE = "Negligible"


class RiskTreatment(Enum):
    MITIGATE = "Mitigate"
    TRANSFER = "Transfer"
    AVOID = "Avoid"
    ACCEPT = "Accept"


# Full Annex A control catalog for ISO 27001:2022
ANNEX_A_CONTROLS = {
    "A.5.1": {"title": "Policies for information security", "category": "Organizational"},
    "A.5.2": {"title": "Information security roles and responsibilities", "category": "Organizational"},
    "A.5.3": {"title": "Segregation of duties", "category": "Organizational"},
    "A.5.4": {"title": "Management responsibilities", "category": "Organizational"},
    "A.5.5": {"title": "Contact with authorities", "category": "Organizational"},
    "A.5.6": {"title": "Contact with special interest groups", "category": "Organizational"},
    "A.5.7": {"title": "Threat intelligence", "category": "Organizational", "new": True},
    "A.5.8": {"title": "Information security in project management", "category": "Organizational"},
    "A.5.9": {"title": "Inventory of information and other associated assets", "category": "Organizational"},
    "A.5.10": {"title": "Acceptable use of information and other associated assets", "category": "Organizational"},
    "A.5.11": {"title": "Return of assets", "category": "Organizational"},
    "A.5.12": {"title": "Classification of information", "category": "Organizational"},
    "A.5.13": {"title": "Labelling of information", "category": "Organizational"},
    "A.5.14": {"title": "Information transfer", "category": "Organizational"},
    "A.5.15": {"title": "Access control", "category": "Organizational"},
    "A.5.16": {"title": "Identity management", "category": "Organizational"},
    "A.5.17": {"title": "Authentication information", "category": "Organizational"},
    "A.5.18": {"title": "Access rights", "category": "Organizational"},
    "A.5.19": {"title": "Information security in supplier relationships", "category": "Organizational"},
    "A.5.20": {"title": "Addressing information security within supplier agreements", "category": "Organizational"},
    "A.5.21": {"title": "Managing information security in the ICT supply chain", "category": "Organizational"},
    "A.5.22": {"title": "Monitoring, review and change management of supplier services", "category": "Organizational"},
    "A.5.23": {"title": "Information security for use of cloud services", "category": "Organizational", "new": True},
    "A.5.24": {"title": "Information security incident management planning and preparation", "category": "Organizational"},
    "A.5.25": {"title": "Assessment and decision on information security events", "category": "Organizational"},
    "A.5.26": {"title": "Response to information security incidents", "category": "Organizational"},
    "A.5.27": {"title": "Learning from information security incidents", "category": "Organizational"},
    "A.5.28": {"title": "Collection of evidence", "category": "Organizational"},
    "A.5.29": {"title": "Information security during disruption", "category": "Organizational"},
    "A.5.30": {"title": "ICT readiness for business continuity", "category": "Organizational", "new": True},
    "A.5.31": {"title": "Legal, statutory, regulatory and contractual requirements", "category": "Organizational"},
    "A.5.32": {"title": "Intellectual property rights", "category": "Organizational"},
    "A.5.33": {"title": "Protection of records", "category": "Organizational"},
    "A.5.34": {"title": "Privacy and protection of PII", "category": "Organizational"},
    "A.5.35": {"title": "Independent review of information security", "category": "Organizational"},
    "A.5.36": {"title": "Compliance with policies, rules and standards", "category": "Organizational"},
    "A.5.37": {"title": "Documented operating procedures", "category": "Organizational"},
    "A.6.1": {"title": "Screening", "category": "People"},
    "A.6.2": {"title": "Terms and conditions of employment", "category": "People"},
    "A.6.3": {"title": "Information security awareness, education and training", "category": "People"},
    "A.6.4": {"title": "Disciplinary process", "category": "People"},
    "A.6.5": {"title": "Responsibilities after termination or change of employment", "category": "People"},
    "A.6.6": {"title": "Confidentiality or non-disclosure agreements", "category": "People"},
    "A.6.7": {"title": "Remote working", "category": "People"},
    "A.6.8": {"title": "Information security event reporting", "category": "People"},
    "A.7.1": {"title": "Physical security perimeters", "category": "Physical"},
    "A.7.2": {"title": "Physical entry", "category": "Physical"},
    "A.7.3": {"title": "Securing offices, rooms and facilities", "category": "Physical"},
    "A.7.4": {"title": "Physical security monitoring", "category": "Physical", "new": True},
    "A.7.5": {"title": "Protecting against physical and environmental threats", "category": "Physical"},
    "A.7.6": {"title": "Working in secure areas", "category": "Physical"},
    "A.7.7": {"title": "Clear desk and clear screen", "category": "Physical"},
    "A.7.8": {"title": "Equipment siting and protection", "category": "Physical"},
    "A.7.9": {"title": "Security of assets off-premises", "category": "Physical"},
    "A.7.10": {"title": "Storage media", "category": "Physical"},
    "A.7.11": {"title": "Supporting utilities", "category": "Physical"},
    "A.7.12": {"title": "Cabling security", "category": "Physical"},
    "A.7.13": {"title": "Equipment maintenance", "category": "Physical"},
    "A.7.14": {"title": "Secure disposal or re-use of equipment", "category": "Physical"},
    "A.8.1": {"title": "User endpoint devices", "category": "Technological"},
    "A.8.2": {"title": "Privileged access rights", "category": "Technological"},
    "A.8.3": {"title": "Information access restriction", "category": "Technological"},
    "A.8.4": {"title": "Access to source code", "category": "Technological"},
    "A.8.5": {"title": "Secure authentication", "category": "Technological"},
    "A.8.6": {"title": "Capacity management", "category": "Technological"},
    "A.8.7": {"title": "Protection against malware", "category": "Technological"},
    "A.8.8": {"title": "Management of technical vulnerabilities", "category": "Technological"},
    "A.8.9": {"title": "Configuration management", "category": "Technological", "new": True},
    "A.8.10": {"title": "Information deletion", "category": "Technological", "new": True},
    "A.8.11": {"title": "Data masking", "category": "Technological", "new": True},
    "A.8.12": {"title": "Data leakage prevention", "category": "Technological", "new": True},
    "A.8.13": {"title": "Information backup", "category": "Technological"},
    "A.8.14": {"title": "Redundancy of information processing facilities", "category": "Technological"},
    "A.8.15": {"title": "Logging", "category": "Technological"},
    "A.8.16": {"title": "Monitoring activities", "category": "Technological", "new": True},
    "A.8.17": {"title": "Clock synchronization", "category": "Technological"},
    "A.8.18": {"title": "Use of privileged utility programs", "category": "Technological"},
    "A.8.19": {"title": "Installation of software on operational systems", "category": "Technological"},
    "A.8.20": {"title": "Networks security", "category": "Technological"},
    "A.8.21": {"title": "Security of network services", "category": "Technological"},
    "A.8.22": {"title": "Segregation of networks", "category": "Technological"},
    "A.8.23": {"title": "Web filtering", "category": "Technological", "new": True},
    "A.8.24": {"title": "Use of cryptography", "category": "Technological"},
    "A.8.25": {"title": "Secure development life cycle", "category": "Technological"},
    "A.8.26": {"title": "Application security requirements", "category": "Technological"},
    "A.8.27": {"title": "Secure system architecture and engineering principles", "category": "Technological"},
    "A.8.28": {"title": "Secure coding", "category": "Technological", "new": True},
    "A.8.29": {"title": "Security testing in development and acceptance", "category": "Technological"},
    "A.8.30": {"title": "Outsourced development", "category": "Technological"},
    "A.8.31": {"title": "Separation of development, test and production environments", "category": "Technological"},
    "A.8.32": {"title": "Change management", "category": "Technological"},
    "A.8.33": {"title": "Test information", "category": "Technological"},
    "A.8.34": {"title": "Protection of information systems during audit testing", "category": "Technological"},
}


@dataclass
class RiskEntry:
    risk_id: str
    asset: str
    threat: str
    vulnerability: str
    likelihood: int  # 1-5
    impact: int      # 1-5
    existing_controls: list = field(default_factory=list)
    risk_level: str = ""
    treatment: str = ""
    treatment_controls: list = field(default_factory=list)
    owner: str = ""
    status: str = "Open"
    due_date: str = ""

    def __post_init__(self):
        score = self.likelihood * self.impact
        if score >= 20:
            self.risk_level = RiskLevel.CRITICAL.value
        elif score >= 15:
            self.risk_level = RiskLevel.HIGH.value
        elif score >= 8:
            self.risk_level = RiskLevel.MEDIUM.value
        elif score >= 4:
            self.risk_level = RiskLevel.LOW.value
        else:
            self.risk_level = RiskLevel.NEGLIGIBLE.value


@dataclass
class SoAEntry:
    control_id: str
    control_title: str
    applicable: bool
    justification: str
    implementation_status: str
    control_owner: str = ""
    linked_risks: list = field(default_factory=list)
    evidence_reference: str = ""


@dataclass
class AuditFinding:
    finding_id: str
    clause_or_control: str
    finding_type: str  # Major NCR, Minor NCR, Observation, OFI
    description: str
    evidence: str
    root_cause: str = ""
    corrective_action: str = ""
    responsible_person: str = ""
    due_date: str = ""
    status: str = "Open"
    closure_date: str = ""


class ISO27001ComplianceManager:
    """Manages ISO 27001 ISMS compliance checks and tracking."""

    def __init__(self, output_dir: str = "./iso27001_output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.risk_register: list[RiskEntry] = []
        self.soa_entries: list[SoAEntry] = []
        self.audit_findings: list[AuditFinding] = []

    def perform_gap_analysis(self) -> dict:
        """Perform gap analysis against all 93 Annex A controls."""
        print("\n" + "=" * 70)
        print("ISO 27001:2022 GAP ANALYSIS")
        print("=" * 70)

        results = {
            "date": datetime.now().isoformat(),
            "total_controls": len(ANNEX_A_CONTROLS),
            "categories": {},
            "controls": {},
            "summary": {}
        }

        status_counts = {s.value: 0 for s in ControlStatus}

        for control_id, control_info in ANNEX_A_CONTROLS.items():
            category = control_info["category"]
            if category not in results["categories"]:
                results["categories"][category] = {
                    "total": 0,
                    "implemented": 0,
                    "partial": 0,
                    "not_implemented": 0,
                    "not_applicable": 0,
                }

            # Default assessment - mark all as not implemented for gap analysis
            status = ControlStatus.NOT_IMPLEMENTED.value
            results["controls"][control_id] = {
                "title": control_info["title"],
                "category": category,
                "is_new_2022": control_info.get("new", False),
                "status": status,
                "gap_notes": "",
                "priority": "High" if control_info.get("new", False) else "Medium",
            }

            results["categories"][category]["total"] += 1
            results["categories"][category]["not_implemented"] += 1
            status_counts[status] += 1

        results["summary"] = {
            "compliance_percentage": 0.0,
            "controls_needing_implementation": status_counts[ControlStatus.NOT_IMPLEMENTED.value],
            "new_2022_controls": sum(
                1 for c in ANNEX_A_CONTROLS.values() if c.get("new", False)
            ),
            "status_breakdown": status_counts,
        }

        # Save gap analysis report
        report_path = self.output_dir / "gap_analysis_report.json"
        with open(report_path, "w") as f:
            json.dump(results, f, indent=2)

        print(f"\nTotal Controls Assessed: {results['total_controls']}")
        print(f"\nCategory Breakdown:")
        for cat, data in results["categories"].items():
            print(f"  {cat}: {data['total']} controls")
        print(f"\nNew 2022 Controls: {results['summary']['new_2022_controls']}")
        print(f"Gap Analysis Report saved to: {report_path}")

        return results

    def create_risk_register(self, risks: list[dict]) -> list[RiskEntry]:
        """Create and populate risk register with assessed risks."""
        print("\n" + "=" * 70)
        print("RISK REGISTER CREATION")
        print("=" * 70)

        for risk_data in risks:
            entry = RiskEntry(**risk_data)
            self.risk_register.append(entry)
            print(f"\n  [{entry.risk_id}] {entry.asset}")
            print(f"    Threat: {entry.threat}")
            print(f"    Vulnerability: {entry.vulnerability}")
            print(f"    Score: {entry.likelihood} x {entry.impact} = {entry.likelihood * entry.impact}")
            print(f"    Risk Level: {entry.risk_level}")
            print(f"    Treatment: {entry.treatment}")

        # Save risk register
        register_path = self.output_dir / "risk_register.json"
        with open(register_path, "w") as f:
            json.dump([asdict(r) for r in self.risk_register], f, indent=2)

        # Generate risk summary
        risk_summary = {}
        for entry in self.risk_register:
            risk_summary.setdefault(entry.risk_level, 0)
            risk_summary[entry.risk_level] += 1

        print(f"\n  Risk Summary:")
        for level, count in sorted(risk_summary.items()):
            print(f"    {level}: {count}")
        print(f"\n  Risk Register saved to: {register_path}")

        return self.risk_register

    def generate_soa(self, control_assessments: Optional[dict] = None) -> list[SoAEntry]:
        """Generate Statement of Applicability for all 93 controls."""
        print("\n" + "=" * 70)
        print("STATEMENT OF APPLICABILITY (SoA)")
        print("=" * 70)

        if control_assessments is None:
            control_assessments = {}

        for control_id, control_info in ANNEX_A_CONTROLS.items():
            assessment = control_assessments.get(control_id, {})
            entry = SoAEntry(
                control_id=control_id,
                control_title=control_info["title"],
                applicable=assessment.get("applicable", True),
                justification=assessment.get("justification", "Required by risk assessment"),
                implementation_status=assessment.get("status", ControlStatus.NOT_IMPLEMENTED.value),
                control_owner=assessment.get("owner", ""),
                linked_risks=assessment.get("linked_risks", []),
                evidence_reference=assessment.get("evidence", ""),
            )
            self.soa_entries.append(entry)

        # Calculate SoA statistics
        applicable_count = sum(1 for e in self.soa_entries if e.applicable)
        implemented_count = sum(
            1 for e in self.soa_entries
            if e.applicable and e.implementation_status == ControlStatus.FULLY_IMPLEMENTED.value
        )
        partial_count = sum(
            1 for e in self.soa_entries
            if e.applicable and e.implementation_status == ControlStatus.PARTIALLY_IMPLEMENTED.value
        )
        not_applicable_count = sum(1 for e in self.soa_entries if not e.applicable)

        compliance_pct = (
            (implemented_count / applicable_count * 100) if applicable_count > 0 else 0
        )

        print(f"\n  Total Controls: {len(self.soa_entries)}")
        print(f"  Applicable: {applicable_count}")
        print(f"  Not Applicable: {not_applicable_count}")
        print(f"  Fully Implemented: {implemented_count}")
        print(f"  Partially Implemented: {partial_count}")
        print(f"  Compliance Rate: {compliance_pct:.1f}%")

        # Save SoA
        soa_path = self.output_dir / "statement_of_applicability.json"
        with open(soa_path, "w") as f:
            json.dump([asdict(e) for e in self.soa_entries], f, indent=2)

        # Generate CSV version for auditors
        csv_path = self.output_dir / "soa_report.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Control ID", "Title", "Category", "Applicable",
                "Justification", "Implementation Status", "Owner",
                "Linked Risks", "Evidence Reference", "New in 2022"
            ])
            for entry in self.soa_entries:
                control_info = ANNEX_A_CONTROLS.get(entry.control_id, {})
                writer.writerow([
                    entry.control_id,
                    entry.control_title,
                    control_info.get("category", ""),
                    "Yes" if entry.applicable else "No",
                    entry.justification,
                    entry.implementation_status,
                    entry.control_owner,
                    "; ".join(entry.linked_risks),
                    entry.evidence_reference,
                    "Yes" if control_info.get("new", False) else "No",
                ])

        print(f"  SoA saved to: {soa_path}")
        print(f"  SoA CSV saved to: {csv_path}")

        return self.soa_entries

    def check_audit_readiness(self) -> dict:
        """Check readiness for Stage 1 and Stage 2 certification audits."""
        print("\n" + "=" * 70)
        print("CERTIFICATION AUDIT READINESS CHECK")
        print("=" * 70)

        checks = {
            "mandatory_documents": {
                "Information Security Policy (A.5.1)": False,
                "ISMS Scope Document (Clause 4.3)": False,
                "Risk Assessment Methodology (Clause 6.1.2)": False,
                "Risk Assessment Report (Clause 8.2)": False,
                "Risk Treatment Plan (Clause 6.1.3)": False,
                "Statement of Applicability (Clause 6.1.3)": False,
                "Information Security Objectives (Clause 6.2)": False,
                "Competence Evidence (Clause 7.2)": False,
                "Operational Planning Documents (Clause 8.1)": False,
                "Internal Audit Programme and Reports (Clause 9.2)": False,
                "Management Review Minutes (Clause 9.3)": False,
                "Corrective Action Records (Clause 10.1)": False,
            },
            "process_checks": {
                "Risk assessment completed within last 12 months": False,
                "Internal audit covers all clauses and applicable controls": False,
                "Management review conducted": False,
                "All major nonconformities closed": False,
                "Security awareness training delivered": False,
                "Incident response process tested": False,
                "Business continuity plans tested": False,
                "Supplier security reviews conducted": False,
            },
            "control_implementation": {
                "All applicable Annex A controls implemented": False,
                "Evidence of control operation available": False,
                "Control effectiveness measured": False,
                "New 2022 controls addressed": False,
            },
        }

        # Auto-check based on existing data
        if self.soa_entries:
            checks["mandatory_documents"]["Statement of Applicability (Clause 6.1.3)"] = True

        if self.risk_register:
            checks["mandatory_documents"]["Risk Assessment Report (Clause 8.2)"] = True
            checks["process_checks"]["Risk assessment completed within last 12 months"] = True

        total_checks = sum(len(v) for v in checks.values())
        passed_checks = sum(
            sum(1 for passed in v.values() if passed) for v in checks.values()
        )
        readiness_pct = (passed_checks / total_checks * 100) if total_checks > 0 else 0

        print(f"\n  Readiness Score: {passed_checks}/{total_checks} ({readiness_pct:.1f}%)")

        for section, items in checks.items():
            print(f"\n  {section.replace('_', ' ').title()}:")
            for item, status in items.items():
                icon = "[PASS]" if status else "[FAIL]"
                print(f"    {icon} {item}")

        if readiness_pct < 80:
            print(f"\n  WARNING: Readiness below 80%. Address gaps before scheduling Stage 1 audit.")
        elif readiness_pct < 100:
            print(f"\n  NOTICE: Some items pending. Complete before Stage 2 audit.")
        else:
            print(f"\n  READY: All checks passed. Proceed with certification audit.")

        # Save readiness report
        report = {
            "date": datetime.now().isoformat(),
            "readiness_percentage": readiness_pct,
            "passed": passed_checks,
            "total": total_checks,
            "checks": checks,
        }
        report_path = self.output_dir / "audit_readiness_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n  Readiness Report saved to: {report_path}")
        return report

    def track_audit_findings(self, findings: list[dict]) -> list[AuditFinding]:
        """Track internal or external audit findings and corrective actions."""
        print("\n" + "=" * 70)
        print("AUDIT FINDINGS TRACKER")
        print("=" * 70)

        for finding_data in findings:
            finding = AuditFinding(**finding_data)
            self.audit_findings.append(finding)
            print(f"\n  [{finding.finding_id}] {finding.finding_type}")
            print(f"    Clause/Control: {finding.clause_or_control}")
            print(f"    Description: {finding.description}")
            print(f"    Status: {finding.status}")

        # Summary
        type_counts = {}
        for f in self.audit_findings:
            type_counts.setdefault(f.finding_type, 0)
            type_counts[f.finding_type] += 1

        print(f"\n  Finding Summary:")
        for ftype, count in type_counts.items():
            print(f"    {ftype}: {count}")

        open_count = sum(1 for f in self.audit_findings if f.status == "Open")
        print(f"    Open Findings: {open_count}")

        # Save findings
        findings_path = self.output_dir / "audit_findings.json"
        with open(findings_path, "w") as f:
            json.dump([asdict(af) for af in self.audit_findings], f, indent=2)

        print(f"\n  Findings saved to: {findings_path}")
        return self.audit_findings

    def generate_compliance_dashboard(self) -> dict:
        """Generate overall ISMS compliance dashboard metrics."""
        print("\n" + "=" * 70)
        print("ISMS COMPLIANCE DASHBOARD")
        print("=" * 70)

        dashboard = {
            "generated": datetime.now().isoformat(),
            "risk_register": {
                "total_risks": len(self.risk_register),
                "by_level": {},
                "by_treatment": {},
                "open_risks": sum(1 for r in self.risk_register if r.status == "Open"),
            },
            "soa": {
                "total_controls": len(ANNEX_A_CONTROLS),
                "applicable": sum(1 for e in self.soa_entries if e.applicable),
                "fully_implemented": sum(
                    1 for e in self.soa_entries
                    if e.applicable and e.implementation_status == ControlStatus.FULLY_IMPLEMENTED.value
                ),
                "partially_implemented": sum(
                    1 for e in self.soa_entries
                    if e.applicable and e.implementation_status == ControlStatus.PARTIALLY_IMPLEMENTED.value
                ),
                "not_implemented": sum(
                    1 for e in self.soa_entries
                    if e.applicable and e.implementation_status == ControlStatus.NOT_IMPLEMENTED.value
                ),
            },
            "audit_findings": {
                "total": len(self.audit_findings),
                "open": sum(1 for f in self.audit_findings if f.status == "Open"),
                "major_ncrs": sum(1 for f in self.audit_findings if f.finding_type == "Major NCR"),
                "minor_ncrs": sum(1 for f in self.audit_findings if f.finding_type == "Minor NCR"),
            },
        }

        # Risk breakdown
        for r in self.risk_register:
            dashboard["risk_register"]["by_level"].setdefault(r.risk_level, 0)
            dashboard["risk_register"]["by_level"][r.risk_level] += 1
            if r.treatment:
                dashboard["risk_register"]["by_treatment"].setdefault(r.treatment, 0)
                dashboard["risk_register"]["by_treatment"][r.treatment] += 1

        # Compliance rate
        applicable = dashboard["soa"]["applicable"]
        implemented = dashboard["soa"]["fully_implemented"]
        dashboard["soa"]["compliance_rate"] = (
            f"{(implemented / applicable * 100):.1f}%" if applicable > 0 else "N/A"
        )

        print(f"\n  Risk Register:")
        print(f"    Total Risks: {dashboard['risk_register']['total_risks']}")
        print(f"    Open Risks: {dashboard['risk_register']['open_risks']}")
        for level, count in dashboard["risk_register"]["by_level"].items():
            print(f"    {level}: {count}")

        print(f"\n  Statement of Applicability:")
        print(f"    Total Controls: {dashboard['soa']['total_controls']}")
        print(f"    Applicable: {dashboard['soa']['applicable']}")
        print(f"    Fully Implemented: {dashboard['soa']['fully_implemented']}")
        print(f"    Compliance Rate: {dashboard['soa']['compliance_rate']}")

        print(f"\n  Audit Findings:")
        print(f"    Total: {dashboard['audit_findings']['total']}")
        print(f"    Open: {dashboard['audit_findings']['open']}")
        print(f"    Major NCRs: {dashboard['audit_findings']['major_ncrs']}")

        # Save dashboard
        dashboard_path = self.output_dir / "compliance_dashboard.json"
        with open(dashboard_path, "w") as f:
            json.dump(dashboard, f, indent=2)

        print(f"\n  Dashboard saved to: {dashboard_path}")
        return dashboard


def main():
    """Run ISO 27001 compliance assessment."""
    manager = ISO27001ComplianceManager()

    # Phase 1: Gap Analysis
    gap_results = manager.perform_gap_analysis()

    # Phase 2: Risk Register with sample risks
    sample_risks = [
        {
            "risk_id": "RISK-001",
            "asset": "Customer Database",
            "threat": "SQL Injection Attack",
            "vulnerability": "Unparameterized database queries",
            "likelihood": 4,
            "impact": 5,
            "existing_controls": ["WAF", "Input validation"],
            "treatment": RiskTreatment.MITIGATE.value,
            "treatment_controls": ["A.8.26", "A.8.28", "A.8.29"],
            "owner": "CTO",
            "due_date": (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"),
        },
        {
            "risk_id": "RISK-002",
            "asset": "Employee Laptops",
            "threat": "Ransomware Infection",
            "vulnerability": "Outdated endpoint protection",
            "likelihood": 4,
            "impact": 4,
            "existing_controls": ["Antivirus"],
            "treatment": RiskTreatment.MITIGATE.value,
            "treatment_controls": ["A.8.1", "A.8.7", "A.8.8"],
            "owner": "IT Manager",
            "due_date": (datetime.now() + timedelta(days=14)).strftime("%Y-%m-%d"),
        },
        {
            "risk_id": "RISK-003",
            "asset": "Cloud Infrastructure (AWS)",
            "threat": "Unauthorized Access via Misconfigured IAM",
            "vulnerability": "Overly permissive IAM policies",
            "likelihood": 3,
            "impact": 5,
            "existing_controls": ["MFA for root account"],
            "treatment": RiskTreatment.MITIGATE.value,
            "treatment_controls": ["A.5.15", "A.5.23", "A.8.2", "A.8.3"],
            "owner": "Cloud Architect",
            "due_date": (datetime.now() + timedelta(days=21)).strftime("%Y-%m-%d"),
        },
        {
            "risk_id": "RISK-004",
            "asset": "Physical Server Room",
            "threat": "Unauthorized Physical Access",
            "vulnerability": "No CCTV monitoring, single-factor entry",
            "likelihood": 2,
            "impact": 4,
            "existing_controls": ["Key card access"],
            "treatment": RiskTreatment.MITIGATE.value,
            "treatment_controls": ["A.7.1", "A.7.2", "A.7.4"],
            "owner": "Facilities Manager",
            "due_date": (datetime.now() + timedelta(days=45)).strftime("%Y-%m-%d"),
        },
        {
            "risk_id": "RISK-005",
            "asset": "Business Operations",
            "threat": "Key Person Dependency",
            "vulnerability": "Single administrator with no backup",
            "likelihood": 3,
            "impact": 3,
            "existing_controls": [],
            "treatment": RiskTreatment.MITIGATE.value,
            "treatment_controls": ["A.5.2", "A.5.3", "A.6.2"],
            "owner": "HR Director",
            "due_date": (datetime.now() + timedelta(days=60)).strftime("%Y-%m-%d"),
        },
    ]

    risk_register = manager.create_risk_register(sample_risks)

    # Phase 3: Statement of Applicability
    soa = manager.generate_soa()

    # Phase 4: Audit Readiness Check
    readiness = manager.check_audit_readiness()

    # Phase 5: Sample Audit Findings
    sample_findings = [
        {
            "finding_id": "FIND-001",
            "clause_or_control": "A.5.7",
            "finding_type": "Minor NCR",
            "description": "Threat intelligence process not formally documented",
            "evidence": "No threat intelligence procedure or subscription found",
            "root_cause": "New 2022 control not yet addressed",
            "corrective_action": "Establish threat intelligence feeds and document process",
            "responsible_person": "Security Analyst",
            "due_date": (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"),
        },
        {
            "finding_id": "FIND-002",
            "clause_or_control": "Clause 9.2",
            "finding_type": "Minor NCR",
            "description": "Internal audit programme does not cover all Annex A controls",
            "evidence": "Audit plan only covers 60 of 93 applicable controls",
            "root_cause": "Audit programme not updated for 2022 edition",
            "corrective_action": "Revise audit programme to cover all applicable controls",
            "responsible_person": "Internal Auditor",
            "due_date": (datetime.now() + timedelta(days=14)).strftime("%Y-%m-%d"),
        },
    ]

    findings = manager.track_audit_findings(sample_findings)

    # Phase 6: Compliance Dashboard
    dashboard = manager.generate_compliance_dashboard()

    print("\n" + "=" * 70)
    print("ISO 27001 COMPLIANCE ASSESSMENT COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
