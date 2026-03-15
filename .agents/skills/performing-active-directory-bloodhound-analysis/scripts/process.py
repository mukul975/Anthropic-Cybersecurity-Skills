#!/usr/bin/env python3
"""
BloodHound Data Analyzer

Parses BloodHound JSON collection data to identify high-risk attack paths,
Kerberoastable accounts, ACL misconfigurations, and delegation abuse
opportunities without requiring the BloodHound GUI.
"""

import json
import os
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ADUser:
    name: str
    enabled: bool = True
    has_spn: bool = False
    dont_req_preauth: bool = False
    admin_count: bool = False
    password_last_set: str = ""
    last_logon: str = ""
    description: str = ""
    sid: str = ""


@dataclass
class ADComputer:
    name: str
    os: str = ""
    enabled: bool = True
    unconstrained_delegation: bool = False
    allowed_to_delegate: list = field(default_factory=list)
    local_admins: list = field(default_factory=list)
    has_sessions: list = field(default_factory=list)


@dataclass
class ADGroup:
    name: str
    members: list = field(default_factory=list)
    high_value: bool = False
    sid: str = ""


@dataclass
class Finding:
    severity: str  # critical, high, medium, low
    category: str
    title: str
    description: str
    affected_objects: list = field(default_factory=list)
    attack_path: str = ""
    remediation: str = ""
    mitre_technique: str = ""


class BloodHoundAnalyzer:
    """Analyze BloodHound collection data for attack paths."""

    def __init__(self):
        self.users: dict[str, ADUser] = {}
        self.computers: dict[str, ADComputer] = {}
        self.groups: dict[str, ADGroup] = {}
        self.acl_edges: list[dict] = []
        self.findings: list[Finding] = []
        self.domain_admins: set = set()

    def load_bloodhound_data(self, data_dir: str) -> None:
        """Load BloodHound JSON files from collection directory."""
        for filename in os.listdir(data_dir):
            filepath = os.path.join(data_dir, filename)
            if not filename.endswith(".json"):
                continue

            with open(filepath) as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    print(f"[-] Failed to parse {filename}")
                    continue

            if "users" in filename.lower() or (isinstance(data, dict) and data.get("meta", {}).get("type") == "users"):
                self._parse_users(data)
            elif "computers" in filename.lower() or (isinstance(data, dict) and data.get("meta", {}).get("type") == "computers"):
                self._parse_computers(data)
            elif "groups" in filename.lower() or (isinstance(data, dict) and data.get("meta", {}).get("type") == "groups"):
                self._parse_groups(data)

        print(f"[+] Loaded: {len(self.users)} users, {len(self.computers)} computers, {len(self.groups)} groups")

    def _parse_users(self, data: dict) -> None:
        """Parse user data from BloodHound JSON."""
        items = data.get("data", data) if isinstance(data, dict) else data
        if isinstance(items, dict):
            items = items.get("data", [])

        for user_data in items:
            props = user_data.get("Properties", user_data.get("properties", {}))
            name = props.get("name", user_data.get("name", "unknown"))
            user = ADUser(
                name=name,
                enabled=props.get("enabled", True),
                has_spn=props.get("hasspn", False),
                dont_req_preauth=props.get("dontreqpreauth", False),
                admin_count=props.get("admincount", False),
                password_last_set=str(props.get("pwdlastset", "")),
                last_logon=str(props.get("lastlogon", "")),
                description=props.get("description", ""),
                sid=props.get("objectid", props.get("objectsid", "")),
            )
            self.users[name.upper()] = user

    def _parse_computers(self, data: dict) -> None:
        """Parse computer data from BloodHound JSON."""
        items = data.get("data", data) if isinstance(data, dict) else data
        if isinstance(items, dict):
            items = items.get("data", [])

        for comp_data in items:
            props = comp_data.get("Properties", comp_data.get("properties", {}))
            name = props.get("name", comp_data.get("name", "unknown"))
            computer = ADComputer(
                name=name,
                os=props.get("operatingsystem", ""),
                enabled=props.get("enabled", True),
                unconstrained_delegation=props.get("unconstraineddelegation", False),
                allowed_to_delegate=props.get("allowedtodelegate", []) or [],
            )
            self.computers[name.upper()] = computer

    def _parse_groups(self, data: dict) -> None:
        """Parse group data from BloodHound JSON."""
        items = data.get("data", data) if isinstance(data, dict) else data
        if isinstance(items, dict):
            items = items.get("data", [])

        for group_data in items:
            props = group_data.get("Properties", group_data.get("properties", {}))
            name = props.get("name", group_data.get("name", "unknown"))

            members_raw = group_data.get("Members", group_data.get("members", []))
            members = [m.get("MemberId", m.get("ObjectIdentifier", "")) for m in members_raw] if members_raw else []

            group = ADGroup(
                name=name,
                members=members,
                high_value=props.get("highvalue", False),
                sid=props.get("objectid", ""),
            )
            self.groups[name.upper()] = group

            if "DOMAIN ADMINS" in name.upper():
                self.domain_admins = set(members)

    def find_kerberoastable_accounts(self) -> list[Finding]:
        """Identify Kerberoastable service accounts."""
        kerberoastable = [u for u in self.users.values() if u.has_spn and u.enabled]
        findings = []

        if kerberoastable:
            privileged_kerberoastable = [
                u for u in kerberoastable if u.admin_count
            ]

            findings.append(Finding(
                severity="critical" if privileged_kerberoastable else "high",
                category="Kerberoasting",
                title=f"Found {len(kerberoastable)} Kerberoastable Accounts",
                description=(
                    f"{len(kerberoastable)} enabled user accounts have Service Principal Names (SPNs) "
                    f"set, making them vulnerable to Kerberoasting (T1558.003). "
                    f"{len(privileged_kerberoastable)} of these are privileged accounts."
                ),
                affected_objects=[u.name for u in kerberoastable],
                attack_path="GetUserSPNs.py -> Request TGS -> Crack offline with hashcat -m 13100",
                remediation=(
                    "1. Use Group Managed Service Accounts (gMSA) where possible\n"
                    "2. Set 25+ character passwords on service accounts\n"
                    "3. Enable AES encryption only (disable RC4)\n"
                    "4. Monitor Event ID 4769 for anomalous TGS requests"
                ),
                mitre_technique="T1558.003",
            ))

        return findings

    def find_asrep_roastable_accounts(self) -> list[Finding]:
        """Identify AS-REP Roastable accounts."""
        asrep = [u for u in self.users.values() if u.dont_req_preauth and u.enabled]
        findings = []

        if asrep:
            findings.append(Finding(
                severity="high",
                category="AS-REP Roasting",
                title=f"Found {len(asrep)} AS-REP Roastable Accounts",
                description=(
                    f"{len(asrep)} accounts have 'Do not require Kerberos pre-authentication' "
                    f"enabled, allowing offline password cracking (T1558.004)."
                ),
                affected_objects=[u.name for u in asrep],
                attack_path="GetNPUsers.py -> Request AS-REP -> Crack with hashcat -m 18200",
                remediation=(
                    "1. Enable Kerberos pre-authentication for all accounts\n"
                    "2. Use strong passwords (25+ characters) on affected accounts\n"
                    "3. Monitor Event ID 4768 with pre-auth type 0"
                ),
                mitre_technique="T1558.004",
            ))

        return findings

    def find_unconstrained_delegation(self) -> list[Finding]:
        """Identify computers with unconstrained delegation."""
        unconstrained = [
            c for c in self.computers.values()
            if c.unconstrained_delegation and c.enabled
            and "DOMAIN CONTROLLER" not in c.name.upper()
        ]
        findings = []

        if unconstrained:
            findings.append(Finding(
                severity="critical",
                category="Delegation Abuse",
                title=f"Found {len(unconstrained)} Non-DC Computers with Unconstrained Delegation",
                description=(
                    f"{len(unconstrained)} computers (excluding DCs) have unconstrained delegation "
                    f"enabled. An attacker with admin access to these systems can capture TGTs "
                    f"from any user that authenticates to them, including Domain Admins."
                ),
                affected_objects=[c.name for c in unconstrained],
                attack_path=(
                    "Compromise unconstrained host -> Coerce DC auth (PetitPotam/PrinterBug) -> "
                    "Capture DC TGT with Rubeus monitor -> DCSync"
                ),
                remediation=(
                    "1. Remove unconstrained delegation from non-DC computers\n"
                    "2. Migrate to constrained delegation or RBCD\n"
                    "3. Add sensitive accounts to 'Protected Users' group\n"
                    "4. Enable 'Account is sensitive and cannot be delegated'"
                ),
                mitre_technique="T1558.001",
            ))

        return findings

    def find_constrained_delegation(self) -> list[Finding]:
        """Identify constrained delegation abuse opportunities."""
        constrained = [
            c for c in self.computers.values()
            if c.allowed_to_delegate and c.enabled
        ]
        findings = []

        if constrained:
            findings.append(Finding(
                severity="high",
                category="Delegation Abuse",
                title=f"Found {len(constrained)} Computers with Constrained Delegation",
                description=(
                    f"{len(constrained)} computers have constrained delegation configured. "
                    f"If protocol transition is enabled (TrustedToAuthForDelegation), an attacker "
                    f"can abuse S4U2Self and S4U2Proxy to impersonate any user to the target service."
                ),
                affected_objects=[
                    f"{c.name} -> {', '.join(c.allowed_to_delegate)}" for c in constrained
                ],
                remediation=(
                    "1. Review all constrained delegation configurations\n"
                    "2. Disable protocol transition where not needed\n"
                    "3. Use RBCD instead of traditional constrained delegation\n"
                    "4. Add sensitive accounts to 'Protected Users' group"
                ),
                mitre_technique="T1550.003",
            ))

        return findings

    def run_full_analysis(self) -> list[Finding]:
        """Run all analysis checks and return findings."""
        self.findings = []
        self.findings.extend(self.find_kerberoastable_accounts())
        self.findings.extend(self.find_asrep_roastable_accounts())
        self.findings.extend(self.find_unconstrained_delegation())
        self.findings.extend(self.find_constrained_delegation())

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        self.findings.sort(key=lambda f: severity_order.get(f.severity, 99))

        return self.findings

    def generate_report(self) -> str:
        """Generate analysis report."""
        lines = []
        lines.append("=" * 70)
        lines.append("BLOODHOUND ACTIVE DIRECTORY ANALYSIS REPORT")
        lines.append("=" * 70)
        lines.append(f"\nDomain Statistics:")
        lines.append(f"  Users:     {len(self.users)}")
        lines.append(f"  Computers: {len(self.computers)}")
        lines.append(f"  Groups:    {len(self.groups)}")
        lines.append(f"  Findings:  {len(self.findings)}")

        # Summary by severity
        sev_counts = defaultdict(int)
        for f in self.findings:
            sev_counts[f.severity] += 1
        lines.append(f"\n  Critical: {sev_counts['critical']}")
        lines.append(f"  High:     {sev_counts['high']}")
        lines.append(f"  Medium:   {sev_counts['medium']}")
        lines.append(f"  Low:      {sev_counts['low']}")

        lines.append("\n" + "=" * 70)
        lines.append("DETAILED FINDINGS")
        lines.append("=" * 70)

        for i, finding in enumerate(self.findings, 1):
            lines.append(f"\n--- Finding #{i}: [{finding.severity.upper()}] {finding.title} ---")
            lines.append(f"Category: {finding.category}")
            lines.append(f"MITRE ATT&CK: {finding.mitre_technique}")
            lines.append(f"\nDescription:\n  {finding.description}")
            lines.append(f"\nAttack Path:\n  {finding.attack_path}")
            lines.append(f"\nAffected Objects ({len(finding.affected_objects)}):")
            for obj in finding.affected_objects[:10]:
                lines.append(f"  - {obj}")
            if len(finding.affected_objects) > 10:
                lines.append(f"  ... and {len(finding.affected_objects) - 10} more")
            lines.append(f"\nRemediation:\n  {finding.remediation}")

        return "\n".join(lines)


def main():
    """Demonstrate BloodHound data analysis."""
    analyzer = BloodHoundAnalyzer()

    # Create sample data for demonstration
    sample_users = {
        "meta": {"type": "users"},
        "data": [
            {"Properties": {"name": "SVC_SQL@CORP.LOCAL", "enabled": True, "hasspn": True,
                            "dontreqpreauth": False, "admincount": True, "description": "SQL Service Account"}},
            {"Properties": {"name": "SVC_WEB@CORP.LOCAL", "enabled": True, "hasspn": True,
                            "dontreqpreauth": False, "admincount": False, "description": "Web Service"}},
            {"Properties": {"name": "SVC_BACKUP@CORP.LOCAL", "enabled": True, "hasspn": True,
                            "dontreqpreauth": False, "admincount": True, "description": "Backup Service"}},
            {"Properties": {"name": "J.SMITH@CORP.LOCAL", "enabled": True, "hasspn": False,
                            "dontreqpreauth": True, "admincount": False}},
            {"Properties": {"name": "ADMIN@CORP.LOCAL", "enabled": True, "hasspn": False,
                            "dontreqpreauth": False, "admincount": True}},
        ],
    }

    sample_computers = {
        "meta": {"type": "computers"},
        "data": [
            {"Properties": {"name": "DC01.CORP.LOCAL", "enabled": True,
                            "unconstraineddelegation": True, "operatingsystem": "Windows Server 2022"}},
            {"Properties": {"name": "WEB01.CORP.LOCAL", "enabled": True,
                            "unconstraineddelegation": True, "operatingsystem": "Windows Server 2019"}},
            {"Properties": {"name": "SQL01.CORP.LOCAL", "enabled": True,
                            "unconstraineddelegation": False, "operatingsystem": "Windows Server 2019",
                            "allowedtodelegate": ["MSSQLSvc/DB01.CORP.LOCAL:1433"]}},
        ],
    }

    sample_groups = {
        "meta": {"type": "groups"},
        "data": [
            {"Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL", "highvalue": True},
             "Members": [{"MemberId": "S-1-5-21-xxx-500"}]},
            {"Properties": {"name": "BACKUP OPERATORS@CORP.LOCAL", "highvalue": True},
             "Members": []},
        ],
    }

    # Write sample data
    sample_dir = "./bloodhound_sample"
    os.makedirs(sample_dir, exist_ok=True)
    for name, data in [("users.json", sample_users), ("computers.json", sample_computers), ("groups.json", sample_groups)]:
        with open(os.path.join(sample_dir, name), "w") as f:
            json.dump(data, f)

    # Load and analyze
    analyzer.load_bloodhound_data(sample_dir)
    analyzer.run_full_analysis()
    print(analyzer.generate_report())

    # Cleanup
    import shutil
    shutil.rmtree(sample_dir)


if __name__ == "__main__":
    main()
