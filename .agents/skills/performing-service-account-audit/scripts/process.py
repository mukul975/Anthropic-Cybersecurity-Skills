#!/usr/bin/env python3
"""
Service Account Audit Engine

Discovers, classifies, and audits service accounts across enterprise
infrastructure. Identifies orphaned, over-privileged, and non-compliant
service accounts with remediation recommendations.
"""

import json
import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class ServiceAccount:
    """Represents a service account across any platform."""
    account_id: str
    username: str
    platform: str  # ad, aws, azure, gcp, database, application
    account_type: str  # service, gmsa, iam_user, iam_role, service_principal, managed_identity
    owner: str = ""
    application: str = ""
    privilege_level: str = "standard"  # standard, elevated, admin, domain_admin
    password_last_set: Optional[str] = None
    last_logon: Optional[str] = None
    password_never_expires: bool = False
    interactive_logon_allowed: bool = False
    member_of_privileged_group: bool = False
    has_spn: bool = False
    status: str = "active"


@dataclass
class AuditFinding:
    severity: str
    category: str
    title: str
    details: str
    affected_accounts: List[str] = field(default_factory=list)
    remediation: str = ""


class ServiceAccountAuditor:
    """Audits service accounts for security compliance."""

    def __init__(self, password_max_age_days: int = 90, stale_threshold_days: int = 90):
        self.accounts: List[ServiceAccount] = []
        self.findings: List[AuditFinding] = []
        self.password_max_age = password_max_age_days
        self.stale_threshold = stale_threshold_days

    def load_accounts(self, accounts: List[Dict]):
        for a in accounts:
            self.accounts.append(ServiceAccount(**a))

    def audit_all(self) -> List[AuditFinding]:
        self.findings = []
        self._check_orphaned_accounts()
        self._check_password_age()
        self._check_stale_accounts()
        self._check_privilege_levels()
        self._check_interactive_logon()
        self._check_password_never_expires()
        self._check_kerberoastable()
        self._check_gmsa_candidates()
        return self.findings

    def _check_orphaned_accounts(self):
        orphaned = [a for a in self.accounts if not a.owner and a.status == "active"]
        if orphaned:
            self.findings.append(AuditFinding(
                severity="high",
                category="Orphaned Accounts",
                title=f"{len(orphaned)} service accounts have no assigned owner",
                details="Accounts without owners cannot be reviewed or maintained.",
                affected_accounts=[f"{a.username}@{a.platform}" for a in orphaned],
                remediation="Assign owner using CMDB/application inventory. Disable if no owner found."
            ))

    def _check_password_age(self):
        now = datetime.datetime.now()
        stale_pwd = []
        for a in self.accounts:
            if a.status != "active" or a.account_type in ("gmsa", "managed_identity"):
                continue
            if a.password_last_set:
                try:
                    pwd_date = datetime.datetime.fromisoformat(a.password_last_set)
                    age = (now - pwd_date).days
                    if age > self.password_max_age:
                        stale_pwd.append(f"{a.username}@{a.platform}: {age} days old")
                except ValueError:
                    pass
            else:
                stale_pwd.append(f"{a.username}@{a.platform}: unknown age")

        if stale_pwd:
            self.findings.append(AuditFinding(
                severity="critical",
                category="Password Age",
                title=f"{len(stale_pwd)} service accounts exceed {self.password_max_age}-day password policy",
                details="Stale passwords increase risk of credential compromise.",
                affected_accounts=stale_pwd,
                remediation="Rotate credentials immediately. Implement automated rotation."
            ))

    def _check_stale_accounts(self):
        now = datetime.datetime.now()
        stale = []
        for a in self.accounts:
            if a.status != "active":
                continue
            if a.last_logon:
                try:
                    last = datetime.datetime.fromisoformat(a.last_logon)
                    if (now - last).days > self.stale_threshold:
                        stale.append(a)
                except ValueError:
                    pass
            elif not a.last_logon:
                stale.append(a)

        if stale:
            self.findings.append(AuditFinding(
                severity="medium",
                category="Stale Accounts",
                title=f"{len(stale)} service accounts inactive for {self.stale_threshold}+ days",
                details="Unused accounts are attack surface without business value.",
                affected_accounts=[f"{a.username}@{a.platform}" for a in stale],
                remediation="Validate with application owners. Disable if no longer needed."
            ))

    def _check_privilege_levels(self):
        over_priv = [a for a in self.accounts
                     if a.member_of_privileged_group and a.status == "active"]
        if over_priv:
            self.findings.append(AuditFinding(
                severity="critical",
                category="Over-Privileged",
                title=f"{len(over_priv)} service accounts in privileged groups",
                details="Service accounts with admin privileges are high-value targets.",
                affected_accounts=[f"{a.username}@{a.platform} ({a.privilege_level})" for a in over_priv],
                remediation="Reduce to minimum required permissions. Vault credentials in PAM."
            ))

    def _check_interactive_logon(self):
        interactive = [a for a in self.accounts
                       if a.interactive_logon_allowed and a.status == "active"]
        if interactive:
            self.findings.append(AuditFinding(
                severity="high",
                category="Interactive Logon",
                title=f"{len(interactive)} service accounts allow interactive logon",
                details="Service accounts should not permit interactive/remote logon.",
                affected_accounts=[f"{a.username}@{a.platform}" for a in interactive],
                remediation="Deny interactive logon via GPO/policy. Service accounts should only run as services."
            ))

    def _check_password_never_expires(self):
        never_exp = [a for a in self.accounts
                     if a.password_never_expires and a.account_type != "gmsa" and a.status == "active"]
        if never_exp:
            self.findings.append(AuditFinding(
                severity="high",
                category="Password Policy",
                title=f"{len(never_exp)} service accounts with PasswordNeverExpires",
                details="Non-expiring passwords circumvent rotation policies.",
                affected_accounts=[f"{a.username}@{a.platform}" for a in never_exp],
                remediation="Migrate to gMSA or implement automated PAM rotation."
            ))

    def _check_kerberoastable(self):
        kerberoastable = [a for a in self.accounts
                          if a.has_spn and a.account_type == "service" and a.status == "active"]
        if kerberoastable:
            self.findings.append(AuditFinding(
                severity="high",
                category="Kerberoasting",
                title=f"{len(kerberoastable)} accounts vulnerable to Kerberoasting",
                details="Accounts with SPNs can have their password hashes extracted offline.",
                affected_accounts=[f"{a.username}@{a.platform}" for a in kerberoastable],
                remediation="Use long (25+ char) passwords. Migrate to gMSA. Monitor for Kerberoast attacks."
            ))

    def _check_gmsa_candidates(self):
        candidates = [a for a in self.accounts
                      if a.platform == "ad" and a.account_type == "service" and a.status == "active"]
        if candidates:
            self.findings.append(AuditFinding(
                severity="low",
                category="gMSA Migration",
                title=f"{len(candidates)} AD service accounts eligible for gMSA migration",
                details="Group Managed Service Accounts provide automatic password rotation.",
                affected_accounts=[f"{a.username}" for a in candidates],
                remediation="Evaluate each account for gMSA compatibility. Plan migration."
            ))

    def generate_report(self) -> str:
        if not self.findings:
            self.audit_all()

        lines = [
            "=" * 70,
            "SERVICE ACCOUNT AUDIT REPORT",
            "=" * 70,
            f"Report Date: {datetime.datetime.now().isoformat()}",
            f"Total Accounts Audited: {len(self.accounts)}",
            f"Findings: {len(self.findings)}",
            "-" * 70, ""
        ]

        by_platform = defaultdict(int)
        for a in self.accounts:
            by_platform[a.platform] += 1
        lines.append("PLATFORM DISTRIBUTION:")
        for p, c in sorted(by_platform.items()):
            lines.append(f"  {p}: {c}")
        lines.append("")

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for f in sorted(self.findings, key=lambda x: sev_order.get(x.severity, 5)):
            lines.append(f"[{f.severity.upper()}] {f.title}")
            lines.append(f"  Category: {f.category}")
            lines.append(f"  {f.details}")
            if f.remediation:
                lines.append(f"  Fix: {f.remediation}")
            if f.affected_accounts:
                for a in f.affected_accounts[:5]:
                    lines.append(f"    - {a}")
                if len(f.affected_accounts) > 5:
                    lines.append(f"    ... and {len(f.affected_accounts) - 5} more")
            lines.append("")

        lines.append("=" * 70)
        critical = sum(1 for f in self.findings if f.severity == "critical")
        lines.append(f"OVERALL: {'FAIL' if critical else 'PASS WITH FINDINGS'}")
        lines.append("=" * 70)
        return "\n".join(lines)


def main():
    auditor = ServiceAccountAuditor()
    auditor.load_accounts([
        {"account_id": "1", "username": "svc_backup", "platform": "ad", "account_type": "service",
         "owner": "ops-team", "application": "Veeam Backup", "privilege_level": "admin",
         "password_last_set": "2025-06-15", "last_logon": "2026-02-22",
         "password_never_expires": True, "member_of_privileged_group": True, "has_spn": True},
        {"account_id": "2", "username": "svc_monitoring", "platform": "ad", "account_type": "service",
         "owner": "", "application": "", "privilege_level": "standard",
         "password_last_set": "2024-08-01", "last_logon": "2025-03-01",
         "password_never_expires": True, "has_spn": True},
        {"account_id": "3", "username": "app-api-key", "platform": "aws", "account_type": "iam_user",
         "owner": "dev-team", "application": "Web API", "privilege_level": "elevated",
         "password_last_set": "2026-01-15", "last_logon": "2026-02-23"},
        {"account_id": "4", "username": "svc_sql_agent", "platform": "ad", "account_type": "service",
         "owner": "dba-team", "application": "SQL Server", "privilege_level": "admin",
         "password_last_set": "2026-02-20", "last_logon": "2026-02-23",
         "interactive_logon_allowed": True, "member_of_privileged_group": True},
    ])
    print(auditor.generate_report())


if __name__ == "__main__":
    main()
