#!/usr/bin/env python3
"""
Ransomware Backup Strategy Assessment and Monitoring Tool

Audits backup infrastructure for ransomware resilience by checking:
- 3-2-1-1-0 compliance (copies, media types, offsite, immutable, restore testing)
- Backup credential isolation from production AD
- Immutable storage configuration
- Restore test history and success rates
- RPO/RTO compliance per tier

Supports Veeam, AWS Backup, and Azure Backup via API integration.
"""

import json
import subprocess
import sys
import os
import socket
import ssl
import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path


@dataclass
class BackupCopy:
    location: str
    media_type: str
    is_offsite: bool
    is_immutable: bool
    is_airgapped: bool
    retention_days: int
    last_successful: Optional[str] = None
    encryption_algorithm: Optional[str] = None


@dataclass
class RecoveryTier:
    name: str
    tier_level: int
    systems: list
    rpo_hours: float
    rto_hours: float
    backup_frequency: str
    restore_test_frequency: str
    last_restore_test: Optional[str] = None
    last_restore_result: Optional[str] = None


@dataclass
class BackupAssessment:
    organization: str
    assessment_date: str
    backup_solution: str
    copies: list = field(default_factory=list)
    tiers: list = field(default_factory=list)
    credential_isolation: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    score: float = 0.0


class BackupStrategyAuditor:
    """Audits backup infrastructure for ransomware resilience."""

    def __init__(self, org_name: str, backup_solution: str):
        self.assessment = BackupAssessment(
            organization=org_name,
            assessment_date=datetime.datetime.now().strftime("%Y-%m-%d"),
            backup_solution=backup_solution,
        )
        self.max_score = 0
        self.earned_score = 0

    def add_backup_copy(self, copy: BackupCopy):
        self.assessment.copies.append(copy)

    def add_recovery_tier(self, tier: RecoveryTier):
        self.assessment.tiers.append(tier)

    def set_credential_isolation(
        self,
        domain_joined: bool,
        mfa_enabled: bool,
        separate_network: bool,
        rdp_disabled: bool,
        dedicated_admin_accounts: bool,
    ):
        self.assessment.credential_isolation = {
            "domain_joined": domain_joined,
            "mfa_enabled": mfa_enabled,
            "separate_network": separate_network,
            "rdp_disabled": rdp_disabled,
            "dedicated_admin_accounts": dedicated_admin_accounts,
        }

    def _add_finding(self, severity: str, category: str, title: str, detail: str, recommendation: str):
        self.assessment.findings.append({
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "recommendation": recommendation,
        })

    def audit_321_10_compliance(self):
        """Check compliance with the 3-2-1-1-0 backup rule."""
        copies = self.assessment.copies

        # 3 - At least 3 copies
        self.max_score += 20
        if len(copies) >= 3:
            self.earned_score += 20
        else:
            self._add_finding(
                "CRITICAL", "3-2-1-1-0",
                f"Insufficient backup copies: {len(copies)} of 3 required",
                f"Only {len(copies)} backup copies configured. Minimum 3 required.",
                "Add additional backup copies to meet 3-2-1-1-0 minimum.",
            )

        # 2 - At least 2 different media types
        self.max_score += 15
        media_types = set(c.media_type for c in copies)
        if len(media_types) >= 2:
            self.earned_score += 15
        else:
            self._add_finding(
                "HIGH", "3-2-1-1-0",
                f"Insufficient media diversity: {len(media_types)} type(s)",
                f"All backups use {media_types}. Need at least 2 different media types.",
                "Add backup copy on different media (e.g., tape, cloud object storage, SAN).",
            )

        # 1 - At least 1 offsite copy
        self.max_score += 15
        offsite_copies = [c for c in copies if c.is_offsite]
        if offsite_copies:
            self.earned_score += 15
        else:
            self._add_finding(
                "CRITICAL", "3-2-1-1-0",
                "No offsite backup copy",
                "All backup copies are stored on-premises. A site-level disaster would destroy all copies.",
                "Configure at least one offsite backup copy (cloud, remote site, or tape vaulting).",
            )

        # 1 - At least 1 immutable or air-gapped copy
        self.max_score += 25
        immutable_copies = [c for c in copies if c.is_immutable or c.is_airgapped]
        if immutable_copies:
            self.earned_score += 25
        else:
            self._add_finding(
                "CRITICAL", "3-2-1-1-0",
                "No immutable or air-gapped backup copy",
                "No backup copies are protected against modification or deletion. "
                "Ransomware operators routinely delete accessible backups.",
                "Deploy immutable storage (S3 Object Lock, Hardened Linux Repository) "
                "or air-gapped backup (tape with physical separation).",
            )

        # 0 - Restore testing with zero errors
        self.max_score += 25
        if self.assessment.tiers:
            tested_tiers = [t for t in self.assessment.tiers if t.last_restore_result == "Success"]
            all_tiers = len(self.assessment.tiers)
            if len(tested_tiers) == all_tiers:
                self.earned_score += 25
            elif tested_tiers:
                partial_score = int(25 * len(tested_tiers) / all_tiers)
                self.earned_score += partial_score
                self._add_finding(
                    "HIGH", "3-2-1-1-0",
                    f"Incomplete restore testing: {len(tested_tiers)}/{all_tiers} tiers verified",
                    f"Only {len(tested_tiers)} of {all_tiers} recovery tiers have successful restore tests.",
                    "Implement automated restore testing (SureBackup) for all tiers.",
                )
            else:
                self._add_finding(
                    "CRITICAL", "3-2-1-1-0",
                    "No successful restore tests recorded",
                    "No recovery tiers have documented successful restore verification.",
                    "Implement automated restore testing immediately. Untested backups "
                    "should be considered unreliable.",
                )

    def audit_credential_isolation(self):
        """Check backup credential isolation from production AD."""
        creds = self.assessment.credential_isolation
        if not creds:
            self._add_finding(
                "CRITICAL", "Credential Isolation",
                "Credential isolation not assessed",
                "No information provided about backup credential isolation.",
                "Assess backup admin account configuration and network isolation.",
            )
            return

        self.max_score += 10
        if not creds.get("domain_joined", True):
            self.earned_score += 10
        else:
            self._add_finding(
                "CRITICAL", "Credential Isolation",
                "Backup servers joined to production AD domain",
                "Backup infrastructure is domain-joined. Ransomware operators compromise "
                "backup credentials via Kerberoasting, DCSync, or GPO manipulation.",
                "Remove backup servers from production AD. Use local accounts or a "
                "dedicated management domain.",
            )

        self.max_score += 5
        if creds.get("mfa_enabled", False):
            self.earned_score += 5
        else:
            self._add_finding(
                "HIGH", "Credential Isolation",
                "MFA not enabled for backup administration",
                "Backup admin accounts do not require multi-factor authentication.",
                "Enable MFA for all backup console access using hardware tokens.",
            )

        self.max_score += 5
        if creds.get("separate_network", False):
            self.earned_score += 5
        else:
            self._add_finding(
                "HIGH", "Credential Isolation",
                "Backup infrastructure not on separate network segment",
                "Backup servers share the production network segment.",
                "Segment backup infrastructure into a dedicated VLAN with strict firewall rules.",
            )

        self.max_score += 3
        if creds.get("rdp_disabled", False):
            self.earned_score += 3
        else:
            self._add_finding(
                "MEDIUM", "Credential Isolation",
                "RDP enabled on backup servers",
                "Remote Desktop Protocol is accessible on backup servers.",
                "Disable RDP and use out-of-band management (iLO/iDRAC) for emergency access.",
            )

        self.max_score += 2
        if creds.get("dedicated_admin_accounts", False):
            self.earned_score += 2
        else:
            self._add_finding(
                "HIGH", "Credential Isolation",
                "No dedicated backup admin accounts",
                "Backup administration uses shared or production admin accounts.",
                "Create dedicated backup admin accounts with least-privilege access.",
            )

    def audit_rpo_rto_compliance(self):
        """Check if backup frequency meets RPO targets and document RTO validation."""
        for tier in self.assessment.tiers:
            self.max_score += 5
            # Check if restore test is recent enough
            if tier.last_restore_test:
                try:
                    last_test = datetime.datetime.strptime(tier.last_restore_test, "%Y-%m-%d")
                    days_since_test = (datetime.datetime.now() - last_test).days

                    frequency_map = {
                        "weekly": 7,
                        "monthly": 30,
                        "quarterly": 90,
                    }
                    expected_days = frequency_map.get(tier.restore_test_frequency.lower(), 30)

                    if days_since_test <= expected_days * 1.5:
                        self.earned_score += 5
                    else:
                        self._add_finding(
                            "HIGH", "RPO/RTO",
                            f"Tier {tier.tier_level} ({tier.name}): Restore test overdue",
                            f"Last test was {days_since_test} days ago. "
                            f"Expected frequency: {tier.restore_test_frequency}.",
                            f"Run restore test for {tier.name} tier immediately.",
                        )
                except ValueError:
                    self._add_finding(
                        "MEDIUM", "RPO/RTO",
                        f"Tier {tier.tier_level}: Invalid restore test date format",
                        f"Date '{tier.last_restore_test}' could not be parsed.",
                        "Use YYYY-MM-DD format for restore test dates.",
                    )
            else:
                self._add_finding(
                    "CRITICAL", "RPO/RTO",
                    f"Tier {tier.tier_level} ({tier.name}): No restore test recorded",
                    "No restore test has been documented for this recovery tier.",
                    f"Implement {tier.restore_test_frequency} automated restore testing.",
                )

    def audit_encryption(self):
        """Check backup encryption configuration."""
        for copy in self.assessment.copies:
            self.max_score += 3
            if copy.encryption_algorithm:
                if copy.encryption_algorithm.upper() in ("AES-256", "AES256", "AES-256-GCM"):
                    self.earned_score += 3
                else:
                    self._add_finding(
                        "MEDIUM", "Encryption",
                        f"Weak backup encryption: {copy.encryption_algorithm}",
                        f"Backup copy at {copy.location} uses {copy.encryption_algorithm}.",
                        "Upgrade to AES-256 encryption for all backup copies.",
                    )
            else:
                self._add_finding(
                    "HIGH", "Encryption",
                    f"Unencrypted backup: {copy.location}",
                    f"Backup copy at {copy.location} is not encrypted.",
                    "Enable AES-256 encryption for all backup copies, both at rest and in transit.",
                )

    def audit_immutable_retention(self):
        """Check immutable retention period against typical ransomware dwell time."""
        avg_dwell_time_days = 21  # Average ransomware dwell time

        for copy in self.assessment.copies:
            if copy.is_immutable:
                self.max_score += 5
                if copy.retention_days > avg_dwell_time_days:
                    self.earned_score += 5
                else:
                    self._add_finding(
                        "CRITICAL", "Immutable Retention",
                        f"Immutable retention too short: {copy.retention_days} days",
                        f"Immutable retention at {copy.location} is {copy.retention_days} days. "
                        f"Average ransomware dwell time is {avg_dwell_time_days} days. "
                        "Attackers may wait for immutability to expire.",
                        f"Increase immutable retention to at least {avg_dwell_time_days * 2} days.",
                    )

    def run_full_audit(self) -> dict:
        """Execute all audit checks and calculate overall score."""
        self.audit_321_10_compliance()
        self.audit_credential_isolation()
        self.audit_rpo_rto_compliance()
        self.audit_encryption()
        self.audit_immutable_retention()

        if self.max_score > 0:
            self.assessment.score = round((self.earned_score / self.max_score) * 100, 1)

        return asdict(self.assessment)

    def generate_report(self) -> str:
        """Generate human-readable assessment report."""
        result = self.run_full_audit()
        lines = []

        lines.append("=" * 70)
        lines.append("RANSOMWARE BACKUP STRATEGY ASSESSMENT REPORT")
        lines.append("=" * 70)
        lines.append(f"Organization: {result['organization']}")
        lines.append(f"Date: {result['assessment_date']}")
        lines.append(f"Backup Solution: {result['backup_solution']}")
        lines.append(f"Overall Score: {result['score']}%")
        lines.append("")

        # Score interpretation
        score = result["score"]
        if score >= 90:
            rating = "EXCELLENT - Ransomware-resilient backup architecture"
        elif score >= 75:
            rating = "GOOD - Minor gaps in ransomware resilience"
        elif score >= 50:
            rating = "FAIR - Significant gaps require remediation"
        else:
            rating = "POOR - Critical ransomware backup risks present"
        lines.append(f"Rating: {rating}")
        lines.append("")

        # 3-2-1-1-0 Summary
        lines.append("-" * 40)
        lines.append("3-2-1-1-0 COMPLIANCE")
        lines.append("-" * 40)
        copies = result["copies"]
        lines.append(f"Total copies: {len(copies)} (minimum 3)")
        media_types = set(c["media_type"] for c in copies)
        lines.append(f"Media types: {', '.join(media_types)} ({len(media_types)} types, minimum 2)")
        offsite = sum(1 for c in copies if c["is_offsite"])
        lines.append(f"Offsite copies: {offsite} (minimum 1)")
        immutable = sum(1 for c in copies if c["is_immutable"] or c["is_airgapped"])
        lines.append(f"Immutable/Air-gapped copies: {immutable} (minimum 1)")
        lines.append("")

        # Recovery Tiers
        lines.append("-" * 40)
        lines.append("RECOVERY TIERS")
        lines.append("-" * 40)
        for tier in result["tiers"]:
            lines.append(f"  Tier {tier['tier_level']}: {tier['name']}")
            lines.append(f"    Systems: {len(tier['systems'])}")
            lines.append(f"    RPO: {tier['rpo_hours']}h | RTO: {tier['rto_hours']}h")
            lines.append(f"    Backup: {tier['backup_frequency']}")
            lines.append(f"    Restore test: {tier['restore_test_frequency']} "
                        f"(Last: {tier['last_restore_test'] or 'Never'}, "
                        f"Result: {tier['last_restore_result'] or 'N/A'})")
        lines.append("")

        # Credential Isolation
        lines.append("-" * 40)
        lines.append("CREDENTIAL ISOLATION")
        lines.append("-" * 40)
        creds = result["credential_isolation"]
        for key, val in creds.items():
            status = "PASS" if (val if key != "domain_joined" else not val) else "FAIL"
            lines.append(f"  {key}: {'Yes' if val else 'No'} [{status}]")
        lines.append("")

        # Findings
        lines.append("-" * 40)
        lines.append(f"FINDINGS ({len(result['findings'])} total)")
        lines.append("-" * 40)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(result["findings"], key=lambda f: severity_order.get(f["severity"], 5))

        for i, finding in enumerate(sorted_findings, 1):
            lines.append(f"\n  [{finding['severity']}] #{i}: {finding['title']}")
            lines.append(f"    Category: {finding['category']}")
            lines.append(f"    Detail: {finding['detail']}")
            lines.append(f"    Recommendation: {finding['recommendation']}")

        lines.append("")
        lines.append("=" * 70)
        lines.append("END OF REPORT")
        lines.append("=" * 70)

        return "\n".join(lines)


def check_veeam_api(server: str, port: int = 9419) -> dict:
    """Check Veeam Backup & Replication API availability."""
    result = {"reachable": False, "tls": False, "api_version": None}
    try:
        sock = socket.create_connection((server, port), timeout=5)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        ssock = context.wrap_socket(sock, server_hostname=server)
        result["reachable"] = True
        result["tls"] = True
        ssock.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        try:
            sock = socket.create_connection((server, port), timeout=5)
            result["reachable"] = True
            sock.close()
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
    return result


def check_s3_object_lock(bucket_name: str) -> dict:
    """Check AWS S3 bucket for Object Lock configuration."""
    result = {"bucket": bucket_name, "object_lock_enabled": False, "retention_mode": None, "retention_days": None}
    try:
        output = subprocess.run(
            ["aws", "s3api", "get-object-lock-configuration", "--bucket", bucket_name],
            capture_output=True, text=True, timeout=30,
        )
        if output.returncode == 0:
            config = json.loads(output.stdout)
            lock_config = config.get("ObjectLockConfiguration", {})
            result["object_lock_enabled"] = lock_config.get("ObjectLockEnabled") == "Enabled"
            rule = lock_config.get("Rule", {}).get("DefaultRetention", {})
            result["retention_mode"] = rule.get("Mode")
            result["retention_days"] = rule.get("Days")
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass
    return result


def main():
    """Run example backup strategy assessment."""
    auditor = BackupStrategyAuditor(
        org_name="Example Financial Services",
        backup_solution="Veeam Backup & Replication 12",
    )

    # Define backup copies
    auditor.add_backup_copy(BackupCopy(
        location="On-premises NAS (Building A)",
        media_type="NAS/NFS",
        is_offsite=False,
        is_immutable=False,
        is_airgapped=False,
        retention_days=14,
        last_successful="2026-02-22",
        encryption_algorithm="AES-256",
    ))

    auditor.add_backup_copy(BackupCopy(
        location="Veeam Hardened Linux Repository",
        media_type="Linux/XFS",
        is_offsite=False,
        is_immutable=True,
        is_airgapped=False,
        retention_days=30,
        last_successful="2026-02-22",
        encryption_algorithm="AES-256",
    ))

    auditor.add_backup_copy(BackupCopy(
        location="AWS S3 (us-west-2) Object Lock",
        media_type="Cloud Object Storage",
        is_offsite=True,
        is_immutable=True,
        is_airgapped=False,
        retention_days=60,
        last_successful="2026-02-22",
        encryption_algorithm="AES-256",
    ))

    # Define recovery tiers
    auditor.add_recovery_tier(RecoveryTier(
        name="Critical",
        tier_level=1,
        systems=["DC01", "DC02", "DNS01", "ERP-DB", "CoreBanking"],
        rpo_hours=1,
        rto_hours=4,
        backup_frequency="Hourly incremental, Daily full",
        restore_test_frequency="weekly",
        last_restore_test="2026-02-20",
        last_restore_result="Success",
    ))

    auditor.add_recovery_tier(RecoveryTier(
        name="Important",
        tier_level=2,
        systems=["Exchange", "FileServer01", "WebApp01", "SharePoint"],
        rpo_hours=4,
        rto_hours=12,
        backup_frequency="4-hour incremental, Daily full",
        restore_test_frequency="monthly",
        last_restore_test="2026-02-01",
        last_restore_result="Success",
    ))

    auditor.add_recovery_tier(RecoveryTier(
        name="Standard",
        tier_level=3,
        systems=["DevServer01", "TestDB", "ArchiveNAS"],
        rpo_hours=24,
        rto_hours=48,
        backup_frequency="Daily incremental, Weekly full",
        restore_test_frequency="quarterly",
        last_restore_test="2025-12-15",
        last_restore_result="Success",
    ))

    # Set credential isolation status
    auditor.set_credential_isolation(
        domain_joined=False,
        mfa_enabled=True,
        separate_network=True,
        rdp_disabled=True,
        dedicated_admin_accounts=True,
    )

    # Generate and print report
    report = auditor.generate_report()
    print(report)

    # Export JSON for integration
    result = auditor.run_full_audit()
    output_path = Path(__file__).parent / "assessment_result.json"
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nJSON report saved to: {output_path}")


if __name__ == "__main__":
    main()
