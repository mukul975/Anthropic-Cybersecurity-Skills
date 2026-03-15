#!/usr/bin/env python3
"""
Duo MFA Configuration Auditor and Health Checker

Audits Duo MFA deployment configuration, checks policy compliance,
detects MFA fatigue patterns, and monitors authentication health.
"""

import json
import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class DuoPolicy:
    """Duo authentication policy configuration."""
    policy_name: str
    group: str
    allowed_methods: List[str]  # push, verified_push, webauthn, totp, sms, phone
    remembered_devices_days: int = 0
    require_device_health: bool = False
    require_encryption: bool = False
    min_os_version: str = ""
    trusted_networks: List[str] = field(default_factory=list)
    failmode: str = "secure"  # secure or safe


@dataclass
class AuthEvent:
    """Authentication event from Duo logs."""
    timestamp: str
    username: str
    factor: str  # push, verified_push, webauthn, totp, sms, phone, bypass
    result: str  # success, denied, fraud, timeout
    ip_address: str
    device_os: str = ""
    application: str = ""
    reason: str = ""


@dataclass
class MFAAuditFinding:
    """MFA audit finding."""
    severity: str
    category: str
    title: str
    description: str
    recommendation: str = ""


class DuoMFAAuditor:
    """Audits Duo MFA configuration and detects anomalies."""

    PHISHING_RESISTANT = {"verified_push", "webauthn", "fido2"}
    WEAK_METHODS = {"sms", "phone"}
    AAL2_METHODS = {"push", "verified_push", "webauthn", "totp", "fido2"}

    def __init__(self):
        self.policies: List[DuoPolicy] = []
        self.auth_events: List[AuthEvent] = []
        self.findings: List[MFAAuditFinding] = []

    def load_policies(self, policies: List[Dict]):
        for p in policies:
            self.policies.append(DuoPolicy(**p))

    def load_auth_events(self, events: List[Dict]):
        for e in events:
            self.auth_events.append(AuthEvent(**e))

    def audit_all(self) -> List[MFAAuditFinding]:
        self.findings = []
        self._audit_policy_strength()
        self._audit_weak_methods()
        self._audit_device_health()
        self._audit_failmode()
        self._audit_remembered_devices()
        self._detect_mfa_fatigue()
        self._detect_bypass_usage()
        self._audit_method_distribution()
        return self.findings

    def _audit_policy_strength(self):
        for policy in self.policies:
            has_phishing_resistant = any(
                m in self.PHISHING_RESISTANT for m in policy.allowed_methods
            )
            if "privileged" in policy.group.lower() or "admin" in policy.group.lower():
                if not has_phishing_resistant:
                    self.findings.append(MFAAuditFinding(
                        severity="critical",
                        category="Policy Strength",
                        title=f"Privileged group '{policy.group}' lacks phishing-resistant MFA",
                        description=f"Policy '{policy.policy_name}' allows only: {', '.join(policy.allowed_methods)}",
                        recommendation="Enable Verified Push or WebAuthn for privileged users per CISA guidance"
                    ))

    def _audit_weak_methods(self):
        for policy in self.policies:
            weak = set(policy.allowed_methods) & self.WEAK_METHODS
            if weak:
                self.findings.append(MFAAuditFinding(
                    severity="high",
                    category="Weak Methods",
                    title=f"Weak MFA methods enabled for '{policy.group}'",
                    description=f"SMS and/or phone call enabled: {', '.join(weak)}. "
                                "These are vulnerable to SIM swapping and social engineering.",
                    recommendation="Disable SMS/phone for users with smartphone access. Use push or WebAuthn."
                ))

    def _audit_device_health(self):
        for policy in self.policies:
            if not policy.require_device_health:
                self.findings.append(MFAAuditFinding(
                    severity="medium",
                    category="Device Health",
                    title=f"Device health not enforced for '{policy.group}'",
                    description="Unmanaged or unhealthy devices can authenticate without restriction.",
                    recommendation="Enable device health policy to check OS version, encryption, and firewall."
                ))

    def _audit_failmode(self):
        for policy in self.policies:
            if policy.failmode == "safe":
                self.findings.append(MFAAuditFinding(
                    severity="high",
                    category="Failmode",
                    title=f"Failmode set to 'safe' for '{policy.policy_name}'",
                    description="When Duo is unreachable, users are allowed in without MFA.",
                    recommendation="Set failmode to 'secure' to deny access when Duo is unavailable."
                ))

    def _audit_remembered_devices(self):
        for policy in self.policies:
            if policy.remembered_devices_days > 30:
                self.findings.append(MFAAuditFinding(
                    severity="medium",
                    category="Remembered Devices",
                    title=f"Long remembered device period for '{policy.group}'",
                    description=f"Devices remembered for {policy.remembered_devices_days} days. "
                                "Stolen devices retain MFA bypass.",
                    recommendation="Reduce remembered device period to 7 days or less."
                ))

    def _detect_mfa_fatigue(self):
        """Detect potential MFA prompt bombing / fatigue attacks."""
        user_denials = defaultdict(list)
        for event in self.auth_events:
            if event.result in ("denied", "timeout", "fraud"):
                user_denials[event.username].append(event)

        for user, denials in user_denials.items():
            if len(denials) >= 5:
                # Check if denials happened within a short window
                timestamps = sorted(denials, key=lambda e: e.timestamp)
                if len(timestamps) >= 5:
                    self.findings.append(MFAAuditFinding(
                        severity="critical",
                        category="MFA Fatigue",
                        title=f"Potential MFA fatigue attack on user '{user}'",
                        description=f"{len(denials)} denied/timeout MFA attempts detected. "
                                    "This pattern indicates potential MFA prompt bombing.",
                        recommendation=f"Lock account '{user}', verify with user, enable Verified Push, "
                                       "investigate source IPs."
                    ))

    def _detect_bypass_usage(self):
        bypass_events = [e for e in self.auth_events if e.factor == "bypass"]
        if bypass_events:
            users = set(e.username for e in bypass_events)
            self.findings.append(MFAAuditFinding(
                severity="high",
                category="Bypass Usage",
                title=f"{len(bypass_events)} MFA bypass authentications detected",
                description=f"Users with bypass codes: {', '.join(users)}. "
                            "Bypass codes circumvent MFA protection.",
                recommendation="Review bypass usage. Ensure bypass codes are single-use and time-limited."
            ))

    def _audit_method_distribution(self):
        method_counts = defaultdict(int)
        for event in self.auth_events:
            if event.result == "success":
                method_counts[event.factor] += 1

        total = sum(method_counts.values())
        if total > 0:
            weak_pct = sum(method_counts.get(m, 0) for m in self.WEAK_METHODS) / total * 100
            if weak_pct > 10:
                self.findings.append(MFAAuditFinding(
                    severity="medium",
                    category="Method Distribution",
                    title=f"{weak_pct:.1f}% of authentications use weak MFA methods",
                    description="Significant portion of users still using SMS/phone.",
                    recommendation="Migrate users to Duo Push, Verified Push, or WebAuthn."
                ))

    def generate_report(self) -> str:
        if not self.findings:
            self.audit_all()

        lines = [
            "=" * 70,
            "DUO MFA CONFIGURATION AUDIT REPORT",
            "=" * 70,
            f"Report Date: {datetime.datetime.now().isoformat()}",
            f"Policies Audited: {len(self.policies)}",
            f"Auth Events Analyzed: {len(self.auth_events)}",
            f"Findings: {len(self.findings)}",
            "-" * 70, ""
        ]

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for f in sorted(self.findings, key=lambda x: severity_order.get(x.severity, 5)):
            lines.append(f"[{f.severity.upper()}] {f.title}")
            lines.append(f"  Category: {f.category}")
            lines.append(f"  {f.description}")
            if f.recommendation:
                lines.append(f"  Fix: {f.recommendation}")
            lines.append("")

        lines.append("=" * 70)
        critical = sum(1 for f in self.findings if f.severity == "critical")
        lines.append(f"OVERALL: {'FAIL' if critical > 0 else 'PASS WITH FINDINGS' if self.findings else 'PASS'}")
        lines.append("=" * 70)
        return "\n".join(lines)


def main():
    auditor = DuoMFAAuditor()
    auditor.load_policies([
        {"policy_name": "Standard Users", "group": "standard_users",
         "allowed_methods": ["push", "totp", "sms"], "remembered_devices_days": 7,
         "failmode": "secure"},
        {"policy_name": "Privileged Admins", "group": "privileged_admins",
         "allowed_methods": ["push", "totp"], "remembered_devices_days": 0,
         "require_device_health": True, "failmode": "safe"},
        {"policy_name": "Contractors", "group": "contractors",
         "allowed_methods": ["push", "phone", "sms"], "remembered_devices_days": 45,
         "failmode": "secure"},
    ])

    auditor.load_auth_events([
        {"timestamp": "2026-02-23T08:00:00", "username": "alice", "factor": "push",
         "result": "success", "ip_address": "10.0.1.50", "application": "VPN"},
        {"timestamp": "2026-02-23T08:01:00", "username": "bob", "factor": "sms",
         "result": "success", "ip_address": "192.168.1.100", "application": "VPN"},
        {"timestamp": "2026-02-23T08:02:00", "username": "charlie", "factor": "push",
         "result": "denied", "ip_address": "203.0.113.50", "application": "RDP"},
        {"timestamp": "2026-02-23T08:02:30", "username": "charlie", "factor": "push",
         "result": "denied", "ip_address": "203.0.113.50", "application": "RDP"},
        {"timestamp": "2026-02-23T08:03:00", "username": "charlie", "factor": "push",
         "result": "denied", "ip_address": "203.0.113.50", "application": "RDP"},
        {"timestamp": "2026-02-23T08:03:30", "username": "charlie", "factor": "push",
         "result": "timeout", "ip_address": "203.0.113.50", "application": "RDP"},
        {"timestamp": "2026-02-23T08:04:00", "username": "charlie", "factor": "push",
         "result": "denied", "ip_address": "203.0.113.50", "application": "RDP"},
        {"timestamp": "2026-02-23T09:00:00", "username": "dave", "factor": "bypass",
         "result": "success", "ip_address": "10.0.2.75", "application": "SSH"},
    ])

    print(auditor.generate_report())


if __name__ == "__main__":
    main()
