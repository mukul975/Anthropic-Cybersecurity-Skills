#!/usr/bin/env python3
"""
Privileged Account Access Review Automation

Discovers privileged accounts from Active Directory, AWS IAM, and Azure AD,
generates review campaigns, and tracks certification decisions.

Requirements:
    pip install ldap3 boto3 msal requests pandas openpyxl
"""

import json
import csv
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import ldap3
    HAS_LDAP = True
except ImportError:
    HAS_LDAP = False

try:
    import boto3
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False


class PrivilegedAccountDiscovery:
    """Discovers privileged accounts across multiple platforms."""

    def __init__(self):
        self.accounts = []

    def discover_ad_privileged_accounts(self, server_address, domain_dn,
                                         bind_user, bind_password):
        """Enumerate privileged accounts from Active Directory."""
        if not HAS_LDAP:
            print("[WARN] ldap3 not installed, skipping AD discovery")
            return []

        server = ldap3.Server(server_address, use_ssl=True, get_info=ldap3.ALL)
        conn = ldap3.Connection(server, user=bind_user, password=bind_password,
                                auto_bind=True)

        privileged_groups = [
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "Account Operators",
            "Backup Operators",
            "Server Operators",
            "Print Operators",
        ]

        discovered = []

        for group_name in privileged_groups:
            search_filter = f"(&(objectClass=group)(cn={group_name}))"
            conn.search(domain_dn, search_filter,
                        attributes=["member", "distinguishedName"])

            for entry in conn.entries:
                members = entry.member.values if hasattr(entry.member, "values") else []
                for member_dn in members:
                    conn.search(member_dn, "(objectClass=user)",
                                attributes=["sAMAccountName", "displayName",
                                             "mail", "lastLogonTimestamp",
                                             "whenCreated", "userAccountControl",
                                             "adminCount", "servicePrincipalName"])
                    for user_entry in conn.entries:
                        uac = int(str(user_entry.userAccountControl)) if user_entry.userAccountControl else 0
                        is_disabled = bool(uac & 0x0002)
                        is_service = bool(user_entry.servicePrincipalName)

                        account = {
                            "platform": "Active Directory",
                            "username": str(user_entry.sAMAccountName),
                            "display_name": str(user_entry.displayName) if user_entry.displayName else "",
                            "email": str(user_entry.mail) if user_entry.mail else "",
                            "privileged_group": group_name,
                            "account_type": "service" if is_service else "user",
                            "is_disabled": is_disabled,
                            "created_date": str(user_entry.whenCreated) if user_entry.whenCreated else "",
                            "last_logon": str(user_entry.lastLogonTimestamp) if user_entry.lastLogonTimestamp else "Never",
                            "admin_count": str(user_entry.adminCount) if user_entry.adminCount else "0",
                            "risk_level": "Critical" if group_name in ["Domain Admins", "Enterprise Admins"] else "High",
                        }
                        discovered.append(account)

        conn.unbind()
        self.accounts.extend(discovered)
        return discovered

    def discover_aws_privileged_accounts(self, profile_name=None):
        """Enumerate privileged IAM users and roles in AWS."""
        if not HAS_BOTO:
            print("[WARN] boto3 not installed, skipping AWS discovery")
            return []

        session = boto3.Session(profile_name=profile_name)
        iam = session.client("iam")
        discovered = []

        admin_policies = [
            "arn:aws:iam::aws:policy/AdministratorAccess",
            "arn:aws:iam::aws:policy/IAMFullAccess",
            "arn:aws:iam::aws:policy/PowerUserAccess",
        ]

        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                create_date = user["CreateDate"]

                attached_policies = iam.list_attached_user_policies(UserName=username)
                user_policies = [p["PolicyArn"] for p in attached_policies["AttachedPolicies"]]

                is_admin = any(p in admin_policies for p in user_policies)

                user_groups = iam.list_groups_for_user(UserName=username)
                for group in user_groups["Groups"]:
                    group_policies = iam.list_attached_group_policies(GroupName=group["GroupName"])
                    for gp in group_policies["AttachedPolicies"]:
                        if gp["PolicyArn"] in admin_policies:
                            is_admin = True

                if is_admin:
                    try:
                        last_used = iam.get_user(UserName=username)
                        password_last_used = user.get("PasswordLastUsed", "Never")
                    except Exception:
                        password_last_used = "Unknown"

                    mfa_devices = iam.list_mfa_devices(UserName=username)
                    has_mfa = len(mfa_devices["MFADevices"]) > 0

                    access_keys = iam.list_access_keys(UserName=username)
                    active_keys = [k for k in access_keys["AccessKeyMetadata"]
                                   if k["Status"] == "Active"]

                    account = {
                        "platform": "AWS IAM",
                        "username": username,
                        "display_name": username,
                        "email": "",
                        "privileged_group": ", ".join(user_policies),
                        "account_type": "user",
                        "is_disabled": False,
                        "created_date": create_date.isoformat(),
                        "last_logon": str(password_last_used),
                        "admin_count": str(len(active_keys)),
                        "risk_level": "Critical",
                        "mfa_enabled": has_mfa,
                        "active_access_keys": len(active_keys),
                    }
                    discovered.append(account)

        self.accounts.extend(discovered)
        return discovered

    def generate_review_report(self, output_path):
        """Generate CSV report of all discovered privileged accounts for review."""
        if not self.accounts:
            print("[INFO] No accounts discovered. Run discovery methods first.")
            return

        fieldnames = [
            "platform", "username", "display_name", "email",
            "privileged_group", "account_type", "is_disabled",
            "created_date", "last_logon", "risk_level",
            "reviewer", "decision", "justification", "review_date"
        ]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for account in self.accounts:
                account.setdefault("reviewer", "")
                account.setdefault("decision", "")
                account.setdefault("justification", "")
                account.setdefault("review_date", "")
                writer.writerow(account)

        print(f"[OK] Review report generated: {output_path}")
        print(f"[OK] Total privileged accounts: {len(self.accounts)}")

        critical = sum(1 for a in self.accounts if a["risk_level"] == "Critical")
        high = sum(1 for a in self.accounts if a["risk_level"] == "High")
        disabled = sum(1 for a in self.accounts if a.get("is_disabled"))

        print(f"     Critical: {critical} | High: {high} | Disabled: {disabled}")


class AccessReviewTracker:
    """Tracks review campaign progress and generates compliance reports."""

    def __init__(self, review_file):
        self.review_file = Path(review_file)
        self.accounts = []
        if self.review_file.exists():
            self._load_reviews()

    def _load_reviews(self):
        with open(self.review_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            self.accounts = list(reader)

    def get_review_status(self):
        """Calculate review campaign metrics."""
        total = len(self.accounts)
        reviewed = sum(1 for a in self.accounts if a.get("decision"))
        approved = sum(1 for a in self.accounts if a.get("decision") == "Approve")
        revoked = sum(1 for a in self.accounts if a.get("decision") == "Revoke")
        flagged = sum(1 for a in self.accounts if a.get("decision") == "Flag")
        pending = total - reviewed

        return {
            "total_accounts": total,
            "reviewed": reviewed,
            "pending": pending,
            "approved": approved,
            "revoked": revoked,
            "flagged": flagged,
            "completion_rate": f"{(reviewed/total*100):.1f}%" if total else "0%",
        }

    def identify_dormant_accounts(self, days_threshold=90):
        """Find accounts not used within the threshold period."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days_threshold)
        dormant = []

        for account in self.accounts:
            last_logon = account.get("last_logon", "")
            if last_logon in ("Never", "", "Unknown"):
                dormant.append(account)
                continue
            try:
                logon_date = datetime.fromisoformat(last_logon.replace("Z", "+00:00"))
                if logon_date < cutoff:
                    dormant.append(account)
            except (ValueError, TypeError):
                continue

        return dormant

    def generate_compliance_report(self, output_path):
        """Generate compliance-ready review summary."""
        status = self.get_review_status()
        dormant = self.identify_dormant_accounts()

        report = {
            "report_title": "Privileged Account Access Review - Compliance Report",
            "generated_date": datetime.now(timezone.utc).isoformat(),
            "review_period": "Quarterly",
            "metrics": status,
            "dormant_accounts": len(dormant),
            "dormant_account_list": [
                {"username": a["username"], "platform": a["platform"],
                 "last_logon": a.get("last_logon", "Unknown")}
                for a in dormant
            ],
            "findings": [],
        }

        if status["pending"] > 0:
            report["findings"].append({
                "finding": f"{status['pending']} accounts have not been reviewed",
                "severity": "High",
                "recommendation": "Complete reviews within SLA or auto-revoke"
            })

        if dormant:
            report["findings"].append({
                "finding": f"{len(dormant)} dormant privileged accounts detected",
                "severity": "Critical",
                "recommendation": "Disable dormant accounts and rotate credentials"
            })

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        print(f"[OK] Compliance report generated: {output_path}")
        return report


if __name__ == "__main__":
    discovery = PrivilegedAccountDiscovery()

    print("=" * 60)
    print("Privileged Account Access Review Tool")
    print("=" * 60)
    print()
    print("Usage:")
    print("  1. Run discovery against your environment")
    print("  2. Generate review CSV for reviewer certification")
    print("  3. Track review progress and generate compliance report")
    print()
    print("Example:")
    print("  discovery = PrivilegedAccountDiscovery()")
    print("  discovery.discover_ad_privileged_accounts(server, dn, user, pw)")
    print("  discovery.discover_aws_privileged_accounts(profile='prod')")
    print("  discovery.generate_review_report('review_campaign.csv')")
    print()
    print("  tracker = AccessReviewTracker('review_campaign.csv')")
    print("  print(tracker.get_review_status())")
    print("  tracker.generate_compliance_report('compliance_report.json')")
