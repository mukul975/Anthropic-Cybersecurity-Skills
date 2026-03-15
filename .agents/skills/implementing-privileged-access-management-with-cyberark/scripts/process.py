#!/usr/bin/env python3
"""
CyberArk PAM Health Monitor and Audit Script

Monitors CyberArk vault health, checks credential rotation status,
audits safe permissions, and generates compliance reports for
privileged access management.
"""

import json
import datetime
import hashlib
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class PrivilegedAccount:
    """Represents a privileged account in the vault."""
    account_id: str
    username: str
    address: str  # target system
    platform_id: str
    safe_name: str
    account_type: str  # domain_admin, local_admin, service_account, dba, network
    last_rotation: Optional[str] = None
    last_verification: Optional[str] = None
    last_access: Optional[str] = None
    rotation_interval_days: int = 30
    status: str = "active"  # active, locked, failed_rotation, disabled


@dataclass
class SafeConfig:
    """Represents a CyberArk safe configuration."""
    safe_name: str
    description: str
    members: List[Dict] = field(default_factory=list)  # {"user": "...", "role": "..."}
    retention_days: int = 365
    dual_control: bool = False
    require_reason: bool = True
    account_count: int = 0


@dataclass
class PAMAuditFinding:
    """PAM audit finding."""
    finding_id: str
    severity: str
    category: str
    title: str
    details: str
    affected_accounts: List[str] = field(default_factory=list)
    remediation: str = ""
    nist_control: str = ""


class CyberArkPAMAuditor:
    """Audits CyberArk PAM configuration and compliance."""

    ROTATION_POLICIES = {
        "domain_admin": 1,       # days
        "local_admin": 3,
        "service_account": 30,
        "dba": 1,
        "network": 7,
        "cloud_iam": 90,
        "root": 3,
    }

    def __init__(self):
        self.accounts: List[PrivilegedAccount] = []
        self.safes: List[SafeConfig] = []
        self.findings: List[PAMAuditFinding] = []
        self.finding_counter = 0

    def load_accounts(self, accounts: List[Dict]):
        """Load privileged accounts for audit."""
        for acct in accounts:
            self.accounts.append(PrivilegedAccount(**acct))

    def load_safes(self, safes: List[Dict]):
        """Load safe configurations for audit."""
        for safe in safes:
            self.safes.append(SafeConfig(**safe))

    def _next_finding_id(self) -> str:
        self.finding_counter += 1
        return f"PAM-{self.finding_counter:04d}"

    def audit_all(self) -> List[PAMAuditFinding]:
        """Run all PAM audit checks."""
        self.findings = []
        self.finding_counter = 0
        self._audit_rotation_compliance()
        self._audit_verification_status()
        self._audit_stale_accounts()
        self._audit_safe_permissions()
        self._audit_dual_control()
        self._audit_service_account_dependencies()
        self._audit_account_coverage()
        return self.findings

    def _audit_rotation_compliance(self):
        """Check if credentials are being rotated per policy."""
        now = datetime.datetime.now()
        overdue_accounts = []

        for acct in self.accounts:
            if acct.status == "disabled":
                continue
            max_days = self.ROTATION_POLICIES.get(acct.account_type, 30)
            if acct.last_rotation:
                try:
                    last_rot = datetime.datetime.fromisoformat(acct.last_rotation)
                    days_since = (now - last_rot).days
                    if days_since > max_days:
                        overdue_accounts.append(
                            f"{acct.username}@{acct.address} ({acct.account_type}): "
                            f"{days_since} days since rotation, policy: {max_days} days"
                        )
                except ValueError:
                    pass
            else:
                overdue_accounts.append(
                    f"{acct.username}@{acct.address}: Never rotated"
                )

        if overdue_accounts:
            self.findings.append(PAMAuditFinding(
                finding_id=self._next_finding_id(),
                severity="critical",
                category="Credential Rotation",
                title=f"{len(overdue_accounts)} accounts overdue for rotation",
                details="The following accounts exceed their rotation policy:\n" +
                        "\n".join(f"  - {a}" for a in overdue_accounts),
                affected_accounts=[a.split("@")[0] for a in overdue_accounts],
                remediation="Investigate CPM rotation failures. Check reconciliation accounts. Run manual rotation.",
                nist_control="IA-5(1)"
            ))
        else:
            self.findings.append(PAMAuditFinding(
                finding_id=self._next_finding_id(),
                severity="info",
                category="Credential Rotation",
                title="All accounts within rotation policy",
                details="All active accounts have been rotated within their policy window."
            ))

    def _audit_verification_status(self):
        """Check credential verification status."""
        unverified = []
        now = datetime.datetime.now()

        for acct in self.accounts:
            if acct.status == "disabled":
                continue
            if not acct.last_verification:
                unverified.append(f"{acct.username}@{acct.address}: Never verified")
            else:
                try:
                    last_ver = datetime.datetime.fromisoformat(acct.last_verification)
                    days_since = (now - last_ver).days
                    if days_since > 7:
                        unverified.append(
                            f"{acct.username}@{acct.address}: {days_since} days since verification"
                        )
                except ValueError:
                    pass

        if unverified:
            self.findings.append(PAMAuditFinding(
                finding_id=self._next_finding_id(),
                severity="high",
                category="Credential Verification",
                title=f"{len(unverified)} accounts have stale verification",
                details="Vault credentials may not match target systems:\n" +
                        "\n".join(f"  - {u}" for u in unverified),
                remediation="Run CPM verification task. Check target system connectivity.",
                nist_control="IA-5(2)"
            ))

    def _audit_stale_accounts(self):
        """Identify accounts that haven't been accessed."""
        stale = []
        now = datetime.datetime.now()

        for acct in self.accounts:
            if acct.status == "disabled":
                continue
            if not acct.last_access:
                stale.append(f"{acct.username}@{acct.address}: Never accessed from vault")
            else:
                try:
                    last_acc = datetime.datetime.fromisoformat(acct.last_access)
                    days_since = (now - last_acc).days
                    if days_since > 90:
                        stale.append(
                            f"{acct.username}@{acct.address}: {days_since} days since last access"
                        )
                except ValueError:
                    pass

        if stale:
            self.findings.append(PAMAuditFinding(
                finding_id=self._next_finding_id(),
                severity="medium",
                category="Stale Accounts",
                title=f"{len(stale)} accounts unused for 90+ days",
                details="These accounts may be candidates for decommissioning:\n" +
                        "\n".join(f"  - {s}" for s in stale),
                remediation="Review with account owners. Disable or remove if no longer needed.",
                nist_control="AC-2(3)"
            ))

    def _audit_safe_permissions(self):
        """Check safe member permissions for least privilege."""
        for safe in self.safes:
            admin_count = sum(1 for m in safe.members if m.get("role") == "admin")
            if admin_count > 3:
                self.findings.append(PAMAuditFinding(
                    finding_id=self._next_finding_id(),
                    severity="high",
                    category="Safe Permissions",
                    title=f"Safe '{safe.safe_name}' has {admin_count} admins",
                    details=f"Excessive admin access to safe '{safe.safe_name}'. "
                            "Admin role allows full control including member management.",
                    remediation="Review safe admins. Reduce to minimum required (typically 2).",
                    nist_control="AC-6"
                ))

            for member in safe.members:
                if member.get("role") == "full_access":
                    self.findings.append(PAMAuditFinding(
                        finding_id=self._next_finding_id(),
                        severity="medium",
                        category="Safe Permissions",
                        title=f"Full access granted in safe '{safe.safe_name}'",
                        details=f"User '{member.get('user')}' has full access to safe '{safe.safe_name}'.",
                        remediation="Assign minimum required permissions (retrieve, list) instead of full access.",
                        nist_control="AC-6(1)"
                    ))

    def _audit_dual_control(self):
        """Check dual control enforcement for sensitive safes."""
        for safe in self.safes:
            if not safe.dual_control:
                high_priv_types = any(
                    acct.account_type in ("domain_admin", "root", "dba")
                    for acct in self.accounts if acct.safe_name == safe.safe_name
                )
                if high_priv_types:
                    self.findings.append(PAMAuditFinding(
                        finding_id=self._next_finding_id(),
                        severity="high",
                        category="Dual Control",
                        title=f"Dual control not enabled for high-privilege safe '{safe.safe_name}'",
                        details=f"Safe '{safe.safe_name}' contains high-privilege accounts but "
                                "does not require dual control for credential checkout.",
                        remediation="Enable dual control requiring approval before credential release.",
                        nist_control="AC-5"
                    ))

    def _audit_service_account_dependencies(self):
        """Check for service accounts that may have rotation dependencies."""
        service_accounts = [a for a in self.accounts if a.account_type == "service_account"]
        if service_accounts:
            rapid_rotation = [
                a for a in service_accounts
                if a.rotation_interval_days < 7
            ]
            if rapid_rotation:
                self.findings.append(PAMAuditFinding(
                    finding_id=self._next_finding_id(),
                    severity="medium",
                    category="Service Account Rotation",
                    title=f"{len(rapid_rotation)} service accounts with aggressive rotation",
                    details="Service accounts with < 7-day rotation may cause application disruptions "
                            "if dependencies are not properly managed.",
                    remediation="Verify application dependency management before aggressive rotation. "
                                "Use account groups for coordinated rotation.",
                    nist_control="IA-5(1)"
                ))

    def _audit_account_coverage(self):
        """Check for potential gaps in privileged account coverage."""
        account_types = set(a.account_type for a in self.accounts)
        expected_types = {"domain_admin", "local_admin", "service_account", "dba", "network", "root"}
        missing = expected_types - account_types

        if missing:
            self.findings.append(PAMAuditFinding(
                finding_id=self._next_finding_id(),
                severity="medium",
                category="Coverage Gap",
                title=f"No {', '.join(missing)} accounts in vault",
                details=f"Account types not found in vault: {', '.join(missing)}. "
                        "These may be unmanaged privileged accounts.",
                remediation="Run privileged account discovery scan. Onboard missing account types.",
                nist_control="AC-2"
            ))

    def generate_report(self) -> str:
        """Generate comprehensive PAM audit report."""
        if not self.findings:
            self.audit_all()

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(self.findings, key=lambda f: severity_order.get(f.severity, 5))

        lines = [
            "=" * 70,
            "CYBERARK PAM AUDIT REPORT",
            "=" * 70,
            f"Report Date: {datetime.datetime.now().isoformat()}",
            f"Total Accounts Audited: {len(self.accounts)}",
            f"Total Safes Audited: {len(self.safes)}",
            f"Total Findings: {len(self.findings)}",
            "-" * 70,
            ""
        ]

        by_severity = {}
        for f in sorted_findings:
            by_severity.setdefault(f.severity, []).append(f)

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = len(by_severity.get(sev, []))
            lines.append(f"  {sev.upper()}: {count}")
        lines.append("")

        for f in sorted_findings:
            icon = {"critical": "[!!!]", "high": "[!!]", "medium": "[!]", "low": "[~]", "info": "[i]"}.get(f.severity, "")
            lines.append(f"{icon} {f.finding_id} [{f.severity.upper()}] {f.title}")
            lines.append(f"    Category: {f.category}")
            lines.append(f"    {f.details}")
            if f.remediation:
                lines.append(f"    Remediation: {f.remediation}")
            if f.nist_control:
                lines.append(f"    NIST Control: {f.nist_control}")
            lines.append("")

        lines.append("=" * 70)
        critical_count = len(by_severity.get("critical", []))
        overall = "FAIL" if critical_count > 0 else "PASS WITH FINDINGS" if len(self.findings) > len(by_severity.get("info", [])) else "PASS"
        lines.append(f"OVERALL: {overall}")
        lines.append("=" * 70)

        return "\n".join(lines)


def main():
    """Run PAM audit with sample data."""
    auditor = CyberArkPAMAuditor()

    sample_accounts = [
        {"account_id": "1", "username": "domain_admin01", "address": "dc01.corp.local",
         "platform_id": "WinDomain", "safe_name": "DomainAdmins", "account_type": "domain_admin",
         "last_rotation": "2026-02-20", "last_verification": "2026-02-22", "last_access": "2026-02-21"},
        {"account_id": "2", "username": "root", "address": "webserver01.corp.local",
         "platform_id": "UnixSSH", "safe_name": "LinuxRoot", "account_type": "root",
         "last_rotation": "2026-01-15", "last_verification": "2026-01-16"},
        {"account_id": "3", "username": "sa", "address": "sqlserver01.corp.local",
         "platform_id": "MSSQL", "safe_name": "DatabaseAdmins", "account_type": "dba",
         "last_rotation": "2026-02-22", "last_verification": "2026-02-22", "last_access": "2026-02-23"},
        {"account_id": "4", "username": "svc_backup", "address": "backup01.corp.local",
         "platform_id": "WinService", "safe_name": "ServiceAccounts", "account_type": "service_account",
         "last_rotation": "2026-02-01", "rotation_interval_days": 5},
        {"account_id": "5", "username": "admin", "address": "switch01.corp.local",
         "platform_id": "CiscoIOS", "safe_name": "NetworkDevices", "account_type": "network",
         "last_rotation": "2026-02-10", "last_verification": "2026-02-10"},
    ]

    sample_safes = [
        {"safe_name": "DomainAdmins", "description": "Domain admin accounts", "dual_control": True,
         "members": [{"user": "admin1", "role": "admin"}, {"user": "admin2", "role": "admin"}], "account_count": 5},
        {"safe_name": "LinuxRoot", "description": "Linux root accounts", "dual_control": False,
         "members": [{"user": "admin1", "role": "admin"}, {"user": "admin2", "role": "admin"},
                     {"user": "admin3", "role": "admin"}, {"user": "admin4", "role": "admin"}], "account_count": 20},
        {"safe_name": "ServiceAccounts", "description": "Service accounts", "dual_control": False,
         "members": [{"user": "svc_team", "role": "full_access"}], "account_count": 50},
    ]

    auditor.load_accounts(sample_accounts)
    auditor.load_safes(sample_safes)
    report = auditor.generate_report()
    print(report)


if __name__ == "__main__":
    main()
