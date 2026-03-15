#!/usr/bin/env python3
"""
Access Review and Certification Engine

Automates access review campaigns by collecting entitlement data,
assigning reviewers, tracking certification decisions, generating
compliance reports, and identifying SOD violations.
"""

import json
import datetime
import csv
import io
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class UserEntitlement:
    """A user-to-entitlement mapping for review."""
    user_id: str
    user_name: str
    department: str
    manager: str
    application: str
    entitlement: str
    risk_level: str  # critical, high, medium, low
    last_used: Optional[str] = None
    granted_date: Optional[str] = None
    review_status: str = "pending"  # pending, approved, revoked, escalated
    reviewer: str = ""
    decision_date: Optional[str] = None
    justification: str = ""


@dataclass
class SODRule:
    """Separation of Duties conflict rule."""
    rule_id: str
    description: str
    entitlement_a: str
    application_a: str
    entitlement_b: str
    application_b: str
    severity: str  # critical, high, medium


@dataclass
class CampaignConfig:
    """Access review campaign configuration."""
    campaign_id: str
    name: str
    start_date: str
    end_date: str
    review_model: str  # manager, app_owner, hybrid
    scope_applications: List[str] = field(default_factory=list)
    escalation_days: int = 21
    auto_revoke_unreviewed: bool = False


class AccessReviewEngine:
    """Manages access review and certification campaigns."""

    def __init__(self, config: CampaignConfig):
        self.config = config
        self.entitlements: List[UserEntitlement] = []
        self.sod_rules: List[SODRule] = []
        self.sod_violations: List[Dict] = []

    def load_entitlements(self, entitlements: List[Dict]):
        """Load user-entitlement data for review."""
        for e in entitlements:
            ue = UserEntitlement(**e)
            if not self.config.scope_applications or \
               ue.application in self.config.scope_applications:
                self.entitlements.append(ue)

    def load_sod_rules(self, rules: List[Dict]):
        """Load SOD conflict rules."""
        for r in rules:
            self.sod_rules.append(SODRule(**r))

    def assign_reviewers(self):
        """Assign reviewers based on campaign review model."""
        for ent in self.entitlements:
            if ent.review_status != "pending":
                continue
            if self.config.review_model == "manager":
                ent.reviewer = ent.manager
            elif self.config.review_model == "app_owner":
                ent.reviewer = f"owner_{ent.application}"
            elif self.config.review_model == "hybrid":
                if ent.risk_level in ("critical", "high"):
                    ent.reviewer = f"owner_{ent.application}"
                else:
                    ent.reviewer = ent.manager

    def detect_sod_violations(self) -> List[Dict]:
        """Detect separation of duties violations."""
        self.sod_violations = []
        user_entitlements = defaultdict(list)

        for ent in self.entitlements:
            user_entitlements[ent.user_id].append(ent)

        for user_id, ents in user_entitlements.items():
            for rule in self.sod_rules:
                has_a = any(
                    e.application == rule.application_a and e.entitlement == rule.entitlement_a
                    for e in ents
                )
                has_b = any(
                    e.application == rule.application_b and e.entitlement == rule.entitlement_b
                    for e in ents
                )
                if has_a and has_b:
                    user_name = next(e.user_name for e in ents)
                    self.sod_violations.append({
                        "user_id": user_id,
                        "user_name": user_name,
                        "rule_id": rule.rule_id,
                        "description": rule.description,
                        "severity": rule.severity,
                        "entitlement_a": f"{rule.application_a}:{rule.entitlement_a}",
                        "entitlement_b": f"{rule.application_b}:{rule.entitlement_b}"
                    })

        return self.sod_violations

    def identify_stale_access(self, days_threshold: int = 90) -> List[UserEntitlement]:
        """Identify entitlements not used within threshold."""
        stale = []
        now = datetime.datetime.now()

        for ent in self.entitlements:
            if ent.last_used:
                try:
                    last = datetime.datetime.fromisoformat(ent.last_used)
                    if (now - last).days > days_threshold:
                        stale.append(ent)
                except ValueError:
                    pass
            else:
                stale.append(ent)

        return stale

    def identify_orphaned_access(self, active_users: Set[str]) -> List[UserEntitlement]:
        """Identify entitlements belonging to inactive/terminated users."""
        return [e for e in self.entitlements if e.user_id not in active_users]

    def process_decision(self, user_id: str, application: str, entitlement: str,
                         decision: str, justification: str = ""):
        """Process a reviewer's certification decision."""
        for ent in self.entitlements:
            if (ent.user_id == user_id and ent.application == application and
                    ent.entitlement == entitlement):
                ent.review_status = decision
                ent.decision_date = datetime.datetime.now().isoformat()
                ent.justification = justification
                break

    def get_campaign_metrics(self) -> Dict:
        """Calculate campaign progress metrics."""
        total = len(self.entitlements)
        if total == 0:
            return {"total": 0, "completion_rate": 0}

        by_status = defaultdict(int)
        by_risk = defaultdict(lambda: defaultdict(int))
        by_reviewer = defaultdict(lambda: {"total": 0, "completed": 0})

        for ent in self.entitlements:
            by_status[ent.review_status] += 1
            by_risk[ent.risk_level][ent.review_status] += 1
            by_reviewer[ent.reviewer]["total"] += 1
            if ent.review_status in ("approved", "revoked"):
                by_reviewer[ent.reviewer]["completed"] += 1

        completed = by_status.get("approved", 0) + by_status.get("revoked", 0)
        revocation_rate = by_status.get("revoked", 0) / max(completed, 1) * 100

        return {
            "total": total,
            "pending": by_status.get("pending", 0),
            "approved": by_status.get("approved", 0),
            "revoked": by_status.get("revoked", 0),
            "escalated": by_status.get("escalated", 0),
            "completion_rate": round(completed / total * 100, 1),
            "revocation_rate": round(revocation_rate, 1),
            "by_risk": dict(by_risk),
            "sod_violations": len(self.sod_violations),
            "reviewer_progress": {k: v for k, v in by_reviewer.items()}
        }

    def generate_compliance_report(self) -> str:
        """Generate compliance-ready access review report."""
        metrics = self.get_campaign_metrics()
        stale = self.identify_stale_access()

        lines = [
            "=" * 70,
            "ACCESS REVIEW AND CERTIFICATION REPORT",
            "=" * 70,
            f"Campaign: {self.config.name} ({self.config.campaign_id})",
            f"Period: {self.config.start_date} to {self.config.end_date}",
            f"Review Model: {self.config.review_model}",
            f"Report Generated: {datetime.datetime.now().isoformat()}",
            "-" * 70,
            "",
            "CAMPAIGN METRICS",
            f"  Total Entitlements Reviewed: {metrics['total']}",
            f"  Completion Rate: {metrics['completion_rate']}%",
            f"  Approved: {metrics['approved']}",
            f"  Revoked: {metrics['revoked']}",
            f"  Pending: {metrics['pending']}",
            f"  Escalated: {metrics['escalated']}",
            f"  Revocation Rate: {metrics['revocation_rate']}%",
            f"  Stale Access Items: {len(stale)}",
            f"  SOD Violations: {metrics['sod_violations']}",
            ""
        ]

        if self.sod_violations:
            lines.append("SOD VIOLATIONS:")
            lines.append("-" * 40)
            for v in self.sod_violations:
                lines.append(f"  [{v['severity'].upper()}] {v['user_name']} ({v['user_id']})")
                lines.append(f"    Rule: {v['description']}")
                lines.append(f"    Conflict: {v['entitlement_a']} <-> {v['entitlement_b']}")
            lines.append("")

        # Reviewer progress
        lines.append("REVIEWER PROGRESS:")
        lines.append("-" * 40)
        for reviewer, progress in metrics["reviewer_progress"].items():
            pct = round(progress["completed"] / max(progress["total"], 1) * 100, 1)
            lines.append(f"  {reviewer}: {progress['completed']}/{progress['total']} ({pct}%)")
        lines.append("")

        # Revoked access details
        revoked = [e for e in self.entitlements if e.review_status == "revoked"]
        if revoked:
            lines.append("REVOKED ACCESS:")
            lines.append("-" * 40)
            for e in revoked:
                lines.append(f"  {e.user_name} - {e.application}:{e.entitlement} [{e.risk_level}]")
            lines.append("")

        lines.append("=" * 70)
        overall = "COMPLIANT" if metrics["completion_rate"] >= 95 else "NON-COMPLIANT"
        lines.append(f"COMPLIANCE STATUS: {overall}")
        lines.append("=" * 70)

        return "\n".join(lines)


def main():
    """Run access review with sample data."""
    config = CampaignConfig(
        campaign_id="AR-2026-Q1",
        name="Q1 2026 Quarterly Access Review",
        start_date="2026-01-01",
        end_date="2026-03-31",
        review_model="hybrid",
        scope_applications=["SAP", "Salesforce", "AWS", "GitHub"]
    )

    engine = AccessReviewEngine(config)

    sample_entitlements = [
        {"user_id": "U001", "user_name": "Alice Johnson", "department": "Finance",
         "manager": "Bob Smith", "application": "SAP", "entitlement": "AP_Create",
         "risk_level": "high", "last_used": "2026-02-20", "granted_date": "2024-06-15"},
        {"user_id": "U001", "user_name": "Alice Johnson", "department": "Finance",
         "manager": "Bob Smith", "application": "SAP", "entitlement": "AP_Approve",
         "risk_level": "critical", "last_used": "2026-02-18", "granted_date": "2025-01-10"},
        {"user_id": "U002", "user_name": "Charlie Brown", "department": "Engineering",
         "manager": "Diana Prince", "application": "AWS", "entitlement": "AdminAccess",
         "risk_level": "critical", "last_used": "2025-10-01", "granted_date": "2024-03-20"},
        {"user_id": "U003", "user_name": "Eve Wilson", "department": "Sales",
         "manager": "Frank Castle", "application": "Salesforce", "entitlement": "Standard_User",
         "risk_level": "low", "last_used": "2026-02-22", "granted_date": "2025-08-01"},
        {"user_id": "U004", "user_name": "Grace Lee", "department": "Engineering",
         "manager": "Diana Prince", "application": "GitHub", "entitlement": "Org_Admin",
         "risk_level": "high", "last_used": "2026-02-21", "granted_date": "2025-05-15"},
    ]

    sod_rules = [
        {"rule_id": "SOD-001", "description": "AP Create and AP Approve conflict",
         "entitlement_a": "AP_Create", "application_a": "SAP",
         "entitlement_b": "AP_Approve", "application_b": "SAP",
         "severity": "critical"}
    ]

    engine.load_entitlements(sample_entitlements)
    engine.load_sod_rules(sod_rules)
    engine.assign_reviewers()
    engine.detect_sod_violations()

    # Simulate some decisions
    engine.process_decision("U001", "SAP", "AP_Create", "approved", "Required for daily AP processing")
    engine.process_decision("U002", "AWS", "AdminAccess", "revoked", "Stale access - user no longer needs admin")
    engine.process_decision("U003", "Salesforce", "Standard_User", "approved", "Active sales team member")

    report = engine.generate_compliance_report()
    print(report)


if __name__ == "__main__":
    main()
