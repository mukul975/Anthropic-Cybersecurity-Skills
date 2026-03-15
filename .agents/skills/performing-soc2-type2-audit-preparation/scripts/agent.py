#!/usr/bin/env python3
"""Agent for SOC 2 Type II audit preparation.

Tracks Trust Services Criteria (TSC) control mapping, evidence
collection status, control testing results, and generates
readiness reports with gap analysis.
"""

import json
import sys
from datetime import datetime, timedelta
from collections import defaultdict


COMMON_CRITERIA = {
    "CC1": "Control Environment",
    "CC2": "Communication and Information",
    "CC3": "Risk Assessment",
    "CC4": "Monitoring Activities",
    "CC5": "Control Activities",
    "CC6": "Logical and Physical Access",
    "CC7": "System Operations",
    "CC8": "Change Management",
    "CC9": "Risk Mitigation",
}

TRUST_CATEGORIES = {
    "Security": {"required": True, "series": "CC"},
    "Availability": {"required": False, "series": "A"},
    "Processing Integrity": {"required": False, "series": "PI"},
    "Confidentiality": {"required": False, "series": "C"},
    "Privacy": {"required": False, "series": "P"},
}


class SOC2AuditAgent:
    """Manages SOC 2 Type II audit preparation lifecycle."""

    def __init__(self, org_name, audit_start, audit_end, categories=None):
        self.org_name = org_name
        self.audit_start = audit_start
        self.audit_end = audit_end
        self.categories = categories or ["Security"]
        self.controls = []
        self.evidence = []
        self.gaps = []

    def add_control(self, control_id, criteria, description, owner,
                    frequency, evidence_type, status="implemented"):
        """Register a control mapped to a TSC criterion."""
        self.controls.append({
            "control_id": control_id, "criteria": criteria,
            "description": description, "owner": owner,
            "frequency": frequency, "evidence_type": evidence_type,
            "status": status, "test_results": [],
        })

    def build_default_control_set(self):
        """Load a baseline set of controls for the Common Criteria."""
        defaults = [
            ("CTL-CC6.1-01", "CC6.1", "MFA enforced for all remote access",
             "IAM Team", "continuous", "SSO config screenshot"),
            ("CTL-CC6.1-02", "CC6.1", "Role-based access control implemented",
             "IAM Team", "continuous", "RBAC policy document"),
            ("CTL-CC6.3-01", "CC6.3", "Access removed within 24h of termination",
             "HR/IT", "per-event", "Offboarding ticket"),
            ("CTL-CC7.1-01", "CC7.1", "SIEM alerting for security events",
             "SOC", "continuous", "SIEM alert report"),
            ("CTL-CC7.2-01", "CC7.2", "Incident response plan tested annually",
             "Security", "annual", "IR tabletop exercise report"),
            ("CTL-CC8.1-01", "CC8.1", "Change management with approval workflow",
             "Engineering", "per-event", "Change ticket with approvals"),
            ("CTL-CC6.6-01", "CC6.6", "Quarterly access reviews completed",
             "IAM Team", "quarterly", "Access review completion report"),
            ("CTL-CC3.1-01", "CC3.1", "Annual risk assessment performed",
             "Security", "annual", "Risk assessment document"),
            ("CTL-CC7.1-02", "CC7.1", "Vulnerability scanning performed weekly",
             "Security", "weekly", "Vulnerability scan report"),
            ("CTL-CC5.3-01", "CC5.3", "Annual penetration test performed",
             "Security", "annual", "Pentest report"),
        ]
        for args in defaults:
            self.add_control(*args)
        return self.controls

    def record_evidence(self, control_id, evidence_date, description, file_ref):
        """Record evidence collected for a control."""
        self.evidence.append({
            "control_id": control_id, "date": evidence_date,
            "description": description, "file_ref": file_ref,
        })

    def assess_evidence_coverage(self):
        """Check evidence coverage for each control over the audit period."""
        coverage = []
        for ctrl in self.controls:
            ctrl_evidence = [e for e in self.evidence
                            if e["control_id"] == ctrl["control_id"]]
            freq = ctrl["frequency"]
            if freq == "quarterly":
                expected = 4
            elif freq == "monthly":
                expected = 12
            elif freq == "weekly":
                expected = 52
            elif freq == "annual":
                expected = 1
            elif freq == "continuous":
                expected = 1
            else:
                expected = 1

            collected = len(ctrl_evidence)
            gap = expected - collected if collected < expected else 0
            status = "complete" if gap == 0 else "incomplete"
            entry = {"control_id": ctrl["control_id"],
                     "criteria": ctrl["criteria"],
                     "frequency": freq,
                     "expected_evidence": expected,
                     "collected_evidence": collected,
                     "gap": gap, "status": status}
            coverage.append(entry)
            if gap > 0:
                self.gaps.append(entry)
        return coverage

    def generate_readiness_report(self):
        """Generate SOC 2 Type II readiness assessment report."""
        coverage = self.assess_evidence_coverage()
        criteria_status = defaultdict(lambda: {"total": 0, "complete": 0})
        for c in coverage:
            crit = c["criteria"]
            criteria_status[crit]["total"] += 1
            if c["status"] == "complete":
                criteria_status[crit]["complete"] += 1

        overall_complete = sum(1 for c in coverage if c["status"] == "complete")
        overall_total = len(coverage)

        report = {
            "organization": self.org_name,
            "audit_period": f"{self.audit_start} to {self.audit_end}",
            "categories": self.categories,
            "report_date": datetime.utcnow().isoformat(),
            "total_controls": overall_total,
            "controls_with_complete_evidence": overall_complete,
            "readiness_pct": round(overall_complete / max(overall_total, 1) * 100, 1),
            "criteria_summary": dict(criteria_status),
            "gaps": self.gaps,
            "recommendation": (
                "Ready for audit" if not self.gaps
                else f"{len(self.gaps)} controls need additional evidence"
            ),
        }
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    org = sys.argv[1] if len(sys.argv) > 1 else "Acme Corp"
    agent = SOC2AuditAgent(org, "2025-01-01", "2025-12-31",
                           categories=["Security", "Availability"])
    agent.build_default_control_set()
    agent.record_evidence("CTL-CC6.1-01", "2025-03-01",
                          "Okta MFA config screenshot", "evidence/mfa_config.png")
    agent.record_evidence("CTL-CC7.1-01", "2025-03-15",
                          "Splunk alert summary Q1", "evidence/siem_q1.pdf")
    agent.generate_readiness_report()


if __name__ == "__main__":
    main()
