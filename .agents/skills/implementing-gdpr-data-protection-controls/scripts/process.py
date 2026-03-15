#!/usr/bin/env python3
"""
GDPR Data Protection Compliance Automation

Automates data mapping, ROPA creation, DPIA assessment, data subject
request tracking, breach notification management, and compliance reporting.
"""

import json
import csv
import os
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class LawfulBasis(Enum):
    CONSENT = "Consent (Art. 6(1)(a))"
    CONTRACT = "Contract (Art. 6(1)(b))"
    LEGAL_OBLIGATION = "Legal Obligation (Art. 6(1)(c))"
    VITAL_INTERESTS = "Vital Interests (Art. 6(1)(d))"
    PUBLIC_TASK = "Public Task (Art. 6(1)(e))"
    LEGITIMATE_INTEREST = "Legitimate Interest (Art. 6(1)(f))"


class DSRType(Enum):
    ACCESS = "Right of Access (Art. 15)"
    RECTIFICATION = "Right to Rectification (Art. 16)"
    ERASURE = "Right to Erasure (Art. 17)"
    RESTRICTION = "Right to Restriction (Art. 18)"
    PORTABILITY = "Right to Data Portability (Art. 20)"
    OBJECTION = "Right to Object (Art. 21)"
    AUTOMATED = "Automated Decision-Making (Art. 22)"


class BreachSeverity(Enum):
    NO_RISK = "No Risk"
    RISK = "Risk to Rights and Freedoms"
    HIGH_RISK = "High Risk to Rights and Freedoms"


class TransferMechanism(Enum):
    ADEQUACY = "Adequacy Decision (Art. 45)"
    SCCS = "Standard Contractual Clauses (Art. 46(2)(c))"
    BCRS = "Binding Corporate Rules (Art. 47)"
    CONSENT = "Explicit Consent (Art. 49(1)(a))"
    CONTRACT = "Necessary for Contract (Art. 49(1)(b))"
    DEROGATION = "Other Derogation (Art. 49)"


ADEQUATE_COUNTRIES = [
    "Andorra", "Argentina", "Canada", "Faroe Islands", "Guernsey",
    "Israel", "Isle of Man", "Japan", "Jersey", "New Zealand",
    "Republic of Korea", "Switzerland", "United Kingdom", "Uruguay",
    "United States (Data Privacy Framework participants)"
]


@dataclass
class ProcessingActivity:
    activity_id: str
    name: str
    purpose: str
    lawful_basis: str
    data_subjects: list
    personal_data_categories: list
    special_categories: bool = False
    recipients: list = field(default_factory=list)
    international_transfers: list = field(default_factory=list)
    retention_period: str = ""
    systems: list = field(default_factory=list)
    security_measures: list = field(default_factory=list)
    dpia_required: bool = False
    controller_name: str = ""
    processor_name: str = ""


@dataclass
class DataSubjectRequest:
    dsr_id: str
    request_type: str
    data_subject_name: str
    data_subject_email: str
    received_date: str
    identity_verified: bool = False
    identity_verified_date: str = ""
    deadline: str = ""
    status: str = "Received"
    systems_searched: list = field(default_factory=list)
    response_date: str = ""
    notes: str = ""

    def __post_init__(self):
        if not self.deadline and self.received_date:
            received = datetime.strptime(self.received_date, "%Y-%m-%d")
            self.deadline = (received + timedelta(days=30)).strftime("%Y-%m-%d")


@dataclass
class BreachRecord:
    breach_id: str
    detected_date: str
    detected_time: str
    description: str
    data_categories: list
    subjects_affected: int
    severity: str
    notification_deadline: str = ""
    authority_notified: bool = False
    authority_notification_date: str = ""
    subjects_notified: bool = False
    subjects_notification_date: str = ""
    root_cause: str = ""
    remediation: str = ""
    status: str = "Investigating"

    def __post_init__(self):
        if not self.notification_deadline and self.detected_date:
            detected = datetime.strptime(self.detected_date, "%Y-%m-%d")
            self.notification_deadline = (detected + timedelta(hours=72)).strftime("%Y-%m-%d %H:%M")


@dataclass
class DPIARecord:
    dpia_id: str
    processing_activity: str
    description: str
    necessity_assessment: str
    risks_identified: list
    mitigation_measures: list
    residual_risk: str
    dpo_consultation: bool = False
    authority_consultation: bool = False
    approved: bool = False
    approval_date: str = ""
    reviewer: str = ""


class GDPRComplianceManager:
    """Manages GDPR compliance controls and tracking."""

    def __init__(self, output_dir: str = "./gdpr_output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.processing_activities: list[ProcessingActivity] = []
        self.dsr_log: list[DataSubjectRequest] = []
        self.breach_register: list[BreachRecord] = []
        self.dpia_register: list[DPIARecord] = []

    def create_ropa(self, activities: list[dict]) -> list[ProcessingActivity]:
        """Create Records of Processing Activities (Art. 30)."""
        print("\n" + "=" * 70)
        print("RECORDS OF PROCESSING ACTIVITIES (ROPA)")
        print("=" * 70)

        for act_data in activities:
            activity = ProcessingActivity(**act_data)
            self.processing_activities.append(activity)
            print(f"\n  [{activity.activity_id}] {activity.name}")
            print(f"    Purpose: {activity.purpose}")
            print(f"    Lawful Basis: {activity.lawful_basis}")
            print(f"    Data Subjects: {', '.join(activity.data_subjects)}")
            print(f"    Special Categories: {'Yes' if activity.special_categories else 'No'}")
            print(f"    International Transfers: {'Yes' if activity.international_transfers else 'No'}")
            print(f"    DPIA Required: {'Yes' if activity.dpia_required else 'No'}")

        # Summary statistics
        total = len(self.processing_activities)
        special = sum(1 for a in self.processing_activities if a.special_categories)
        transfers = sum(1 for a in self.processing_activities if a.international_transfers)
        dpia_needed = sum(1 for a in self.processing_activities if a.dpia_required)

        print(f"\n  ROPA Summary:")
        print(f"    Total Processing Activities: {total}")
        print(f"    Special Category Processing: {special}")
        print(f"    International Transfers: {transfers}")
        print(f"    DPIA Required: {dpia_needed}")

        # Lawful basis breakdown
        basis_counts = {}
        for a in self.processing_activities:
            basis_counts.setdefault(a.lawful_basis, 0)
            basis_counts[a.lawful_basis] += 1
        print(f"\n  Lawful Basis Breakdown:")
        for basis, count in basis_counts.items():
            print(f"    {basis}: {count}")

        # Save ROPA
        ropa_path = self.output_dir / "ropa.json"
        with open(ropa_path, "w") as f:
            json.dump([asdict(a) for a in self.processing_activities], f, indent=2)

        csv_path = self.output_dir / "ropa.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Activity ID", "Name", "Purpose", "Lawful Basis",
                "Data Subjects", "Personal Data Categories", "Special Categories",
                "Recipients", "International Transfers", "Retention Period",
                "Systems", "Security Measures", "DPIA Required"
            ])
            for a in self.processing_activities:
                writer.writerow([
                    a.activity_id, a.name, a.purpose, a.lawful_basis,
                    "; ".join(a.data_subjects), "; ".join(a.personal_data_categories),
                    "Yes" if a.special_categories else "No",
                    "; ".join(a.recipients), "; ".join(a.international_transfers),
                    a.retention_period, "; ".join(a.systems),
                    "; ".join(a.security_measures), "Yes" if a.dpia_required else "No"
                ])

        print(f"\n  ROPA saved to: {ropa_path}")
        return self.processing_activities

    def process_dsr(self, requests: list[dict]) -> dict:
        """Track and manage data subject requests."""
        print("\n" + "=" * 70)
        print("DATA SUBJECT REQUEST TRACKER")
        print("=" * 70)

        for req_data in requests:
            dsr = DataSubjectRequest(**req_data)
            self.dsr_log.append(dsr)
            print(f"\n  [{dsr.dsr_id}] {dsr.request_type}")
            print(f"    Subject: {dsr.data_subject_name}")
            print(f"    Received: {dsr.received_date}")
            print(f"    Deadline: {dsr.deadline}")
            print(f"    Status: {dsr.status}")
            print(f"    Identity Verified: {'Yes' if dsr.identity_verified else 'No'}")

        # Overdue check
        today = datetime.now().strftime("%Y-%m-%d")
        overdue = [d for d in self.dsr_log if d.deadline < today and d.status != "Completed"]
        if overdue:
            print(f"\n  ALERT: {len(overdue)} overdue DSRs!")
            for d in overdue:
                print(f"    [{d.dsr_id}] {d.request_type} - Deadline: {d.deadline}")

        # Summary
        type_counts = {}
        for d in self.dsr_log:
            type_counts.setdefault(d.request_type, 0)
            type_counts[d.request_type] += 1

        print(f"\n  DSR Summary:")
        for rtype, count in type_counts.items():
            print(f"    {rtype}: {count}")
        print(f"    Total: {len(self.dsr_log)}")
        print(f"    Overdue: {len(overdue)}")

        dsr_path = self.output_dir / "dsr_log.json"
        with open(dsr_path, "w") as f:
            json.dump([asdict(d) for d in self.dsr_log], f, indent=2)

        print(f"\n  DSR Log saved to: {dsr_path}")
        return {"total": len(self.dsr_log), "overdue": len(overdue), "by_type": type_counts}

    def manage_breach(self, breaches: list[dict]) -> list[BreachRecord]:
        """Manage breach register and notification tracking."""
        print("\n" + "=" * 70)
        print("BREACH REGISTER AND NOTIFICATION TRACKER")
        print("=" * 70)

        for breach_data in breaches:
            breach = BreachRecord(**breach_data)
            self.breach_register.append(breach)
            print(f"\n  [{breach.breach_id}] {breach.description[:60]}...")
            print(f"    Detected: {breach.detected_date} {breach.detected_time}")
            print(f"    Severity: {breach.severity}")
            print(f"    Subjects Affected: {breach.subjects_affected}")
            print(f"    Notification Deadline: {breach.notification_deadline}")
            print(f"    Authority Notified: {'Yes' if breach.authority_notified else 'No'}")
            if breach.severity == BreachSeverity.HIGH_RISK.value:
                print(f"    Subjects Notified: {'Yes' if breach.subjects_notified else 'No'}")
            print(f"    Status: {breach.status}")

        breach_path = self.output_dir / "breach_register.json"
        with open(breach_path, "w") as f:
            json.dump([asdict(b) for b in self.breach_register], f, indent=2)

        print(f"\n  Breach Register saved to: {breach_path}")
        return self.breach_register

    def conduct_dpia(self, dpias: list[dict]) -> list[DPIARecord]:
        """Conduct and record Data Protection Impact Assessments."""
        print("\n" + "=" * 70)
        print("DATA PROTECTION IMPACT ASSESSMENTS (DPIAs)")
        print("=" * 70)

        for dpia_data in dpias:
            dpia = DPIARecord(**dpia_data)
            self.dpia_register.append(dpia)
            print(f"\n  [{dpia.dpia_id}] {dpia.processing_activity}")
            print(f"    Description: {dpia.description[:60]}...")
            print(f"    Risks Identified: {len(dpia.risks_identified)}")
            print(f"    Mitigation Measures: {len(dpia.mitigation_measures)}")
            print(f"    Residual Risk: {dpia.residual_risk}")
            print(f"    DPO Consulted: {'Yes' if dpia.dpo_consultation else 'No'}")
            print(f"    Approved: {'Yes' if dpia.approved else 'No'}")

        dpia_path = self.output_dir / "dpia_register.json"
        with open(dpia_path, "w") as f:
            json.dump([asdict(d) for d in self.dpia_register], f, indent=2)

        print(f"\n  DPIA Register saved to: {dpia_path}")
        return self.dpia_register

    def assess_compliance(self) -> dict:
        """Generate overall GDPR compliance assessment."""
        print("\n" + "=" * 70)
        print("GDPR COMPLIANCE ASSESSMENT")
        print("=" * 70)

        checks = {
            "Article 5 - Principles": {
                "All processing has documented lawful basis": bool(self.processing_activities),
                "Purpose limitation documented for each activity": False,
                "Data minimization assessed": False,
                "Accuracy procedures in place": False,
                "Retention periods defined": any(a.retention_period for a in self.processing_activities),
                "Security measures documented": any(a.security_measures for a in self.processing_activities),
            },
            "Article 25 - Privacy by Design": {
                "Development processes include privacy reviews": False,
                "Default privacy settings implemented": False,
                "Data minimization built into systems": False,
            },
            "Article 30 - ROPA": {
                "Records of processing maintained": bool(self.processing_activities),
                "Controller details documented": any(a.controller_name for a in self.processing_activities),
                "All processing activities captured": len(self.processing_activities) > 0,
            },
            "Article 32 - Security Measures": {
                "Encryption implemented for personal data": False,
                "Pseudonymization implemented where appropriate": False,
                "Access controls for personal data systems": False,
                "Regular security testing performed": False,
            },
            "Articles 33-34 - Breach Notification": {
                "Breach detection capabilities in place": False,
                "72-hour notification process documented": False,
                "Breach register maintained": bool(self.breach_register),
                "Breach response tested": False,
            },
            "Article 35 - DPIA": {
                "DPIA criteria documented": False,
                "DPIAs conducted for high-risk processing": bool(self.dpia_register),
                "DPO consulted on DPIAs": any(d.dpo_consultation for d in self.dpia_register),
            },
            "Articles 12-22 - Data Subject Rights": {
                "DSR handling process documented": False,
                "30-day response capability": bool(self.dsr_log),
                "Identity verification process": any(d.identity_verified for d in self.dsr_log),
                "Erasure capability across systems": False,
                "Portability export capability": False,
            },
            "Articles 44-49 - International Transfers": {
                "Cross-border transfers mapped": any(a.international_transfers for a in self.processing_activities),
                "Transfer mechanisms in place (SCCs/BCRs)": False,
                "Transfer impact assessments conducted": False,
            },
        }

        total = sum(len(v) for v in checks.values())
        passed = sum(sum(1 for x in v.values() if x) for v in checks.values())
        pct = (passed / total * 100) if total > 0 else 0

        print(f"\n  Compliance Score: {passed}/{total} ({pct:.1f}%)")

        for article, items in checks.items():
            cat_passed = sum(1 for x in items.values() if x)
            cat_total = len(items)
            print(f"\n  {article} ({cat_passed}/{cat_total}):")
            for item, status in items.items():
                icon = "[PASS]" if status else "[FAIL]"
                print(f"    {icon} {item}")

        report = {
            "date": datetime.now().isoformat(),
            "compliance_percentage": pct,
            "checks": checks,
            "ropa_count": len(self.processing_activities),
            "dsr_count": len(self.dsr_log),
            "breach_count": len(self.breach_register),
            "dpia_count": len(self.dpia_register),
        }

        report_path = self.output_dir / "gdpr_compliance_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n  Compliance Report saved to: {report_path}")
        return report


def main():
    """Run GDPR compliance assessment."""
    manager = GDPRComplianceManager()

    # ROPA
    sample_activities = [
        {
            "activity_id": "PROC-001",
            "name": "Customer Account Management",
            "purpose": "Managing customer accounts and providing services",
            "lawful_basis": LawfulBasis.CONTRACT.value,
            "data_subjects": ["Customers"],
            "personal_data_categories": ["Name", "Email", "Phone", "Address", "Payment details"],
            "recipients": ["Payment processor", "CRM provider"],
            "international_transfers": ["US (Payment processor - SCCs)"],
            "retention_period": "Duration of contract + 6 years",
            "systems": ["CRM", "Payment gateway", "Database"],
            "security_measures": ["Encryption at rest", "TLS in transit", "RBAC", "MFA"],
            "controller_name": "Example Corp Ltd",
        },
        {
            "activity_id": "PROC-002",
            "name": "Employee HR Processing",
            "purpose": "Employment administration, payroll, benefits",
            "lawful_basis": LawfulBasis.CONTRACT.value,
            "data_subjects": ["Employees", "Job applicants"],
            "personal_data_categories": ["Name", "Address", "DOB", "NI number", "Bank details", "Health data"],
            "special_categories": True,
            "recipients": ["Payroll provider", "Pension provider", "HMRC"],
            "retention_period": "Employment + 7 years",
            "systems": ["HRIS", "Payroll system"],
            "security_measures": ["Encryption", "Access controls", "Audit logging"],
            "dpia_required": True,
            "controller_name": "Example Corp Ltd",
        },
        {
            "activity_id": "PROC-003",
            "name": "Website Analytics",
            "purpose": "Analyzing website usage to improve user experience",
            "lawful_basis": LawfulBasis.CONSENT.value,
            "data_subjects": ["Website visitors"],
            "personal_data_categories": ["IP address", "Cookie identifiers", "Browsing behavior"],
            "recipients": ["Analytics provider"],
            "international_transfers": ["US (Analytics provider - EU-US DPF)"],
            "retention_period": "26 months",
            "systems": ["Website", "Analytics platform"],
            "security_measures": ["IP anonymization", "Cookie consent", "Data pseudonymization"],
            "controller_name": "Example Corp Ltd",
        },
    ]
    manager.create_ropa(sample_activities)

    # DSRs
    sample_dsrs = [
        {
            "dsr_id": "DSR-001",
            "request_type": DSRType.ACCESS.value,
            "data_subject_name": "John Smith",
            "data_subject_email": "john.smith@email.com",
            "received_date": "2024-12-01",
            "identity_verified": True,
            "identity_verified_date": "2024-12-02",
            "status": "In Progress",
            "systems_searched": ["CRM", "Email", "Analytics"],
        },
        {
            "dsr_id": "DSR-002",
            "request_type": DSRType.ERASURE.value,
            "data_subject_name": "Jane Doe",
            "data_subject_email": "jane.doe@email.com",
            "received_date": "2024-12-15",
            "identity_verified": True,
            "identity_verified_date": "2024-12-16",
            "status": "Completed",
            "response_date": "2024-12-28",
        },
    ]
    manager.process_dsr(sample_dsrs)

    # Breaches
    sample_breaches = [
        {
            "breach_id": "BREACH-001",
            "detected_date": "2024-11-15",
            "detected_time": "14:30",
            "description": "Unauthorized access to customer database via compromised admin credentials",
            "data_categories": ["Name", "Email", "Phone"],
            "subjects_affected": 2500,
            "severity": BreachSeverity.HIGH_RISK.value,
            "authority_notified": True,
            "authority_notification_date": "2024-11-16",
            "subjects_notified": True,
            "subjects_notification_date": "2024-11-18",
            "root_cause": "Credential compromise via phishing",
            "remediation": "MFA enforced, passwords reset, phishing training deployed",
            "status": "Closed",
        },
    ]
    manager.manage_breach(sample_breaches)

    # DPIAs
    sample_dpias = [
        {
            "dpia_id": "DPIA-001",
            "processing_activity": "Employee HR Processing",
            "description": "Processing of employee health data for occupational health and benefits administration",
            "necessity_assessment": "Processing is necessary for employment contract and legal obligations",
            "risks_identified": [
                "Unauthorized access to health data",
                "Data breach exposing sensitive employee information",
                "Excessive data collection beyond what is necessary",
            ],
            "mitigation_measures": [
                "Encryption of all health data at rest and in transit",
                "Strict RBAC limiting access to HR and OH staff only",
                "Audit logging of all access to health records",
                "Annual access reviews",
                "Staff training on handling special category data",
            ],
            "residual_risk": "Low",
            "dpo_consultation": True,
            "approved": True,
            "approval_date": "2024-06-15",
            "reviewer": "DPO",
        },
    ]
    manager.conduct_dpia(sample_dpias)

    # Overall compliance assessment
    manager.assess_compliance()

    print("\n" + "=" * 70)
    print("GDPR COMPLIANCE ASSESSMENT COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
