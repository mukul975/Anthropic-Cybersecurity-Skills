#!/usr/bin/env python3
"""Agent for auditing service accounts across AD, cloud, and databases.

Discovers service accounts via LDAP queries, AWS IAM, and Azure AD,
checks password age, privilege levels, and orphan status, then
generates a risk-classified compliance report.
"""

import json
import sys
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict


class ServiceAccountAuditor:
    """Audits service accounts across enterprise infrastructure."""

    RISK_WEIGHTS = {"Domain Admins": 30, "Enterprise Admins": 30,
                    "Schema Admins": 25, "Administrators": 20,
                    "Account Operators": 15, "Backup Operators": 10}

    def __init__(self, domain=None, max_password_age_days=90):
        self.domain = domain
        self.max_password_age_days = max_password_age_days
        self.accounts = []

    def discover_ad_service_accounts(self):
        """Discover service accounts in Active Directory via PowerShell."""
        ps_cmd = (
            "Get-ADUser -Filter {ServicePrincipalName -ne '$null'} "
            "-Properties ServicePrincipalName,PasswordLastSet,LastLogonDate,"
            "Enabled,MemberOf,Description,PasswordNeverExpires "
            "| Select-Object Name,SamAccountName,Enabled,PasswordLastSet,"
            "LastLogonDate,PasswordNeverExpires,"
            "@{N='SPNs';E={$_.ServicePrincipalName -join ';'}},"
            "@{N='Groups';E={($_.MemberOf | ForEach-Object "
            "{($_ -split ',')[0] -replace 'CN=',''}) -join ';'}},"
            "Description | ConvertTo-Json -Depth 3"
        )
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for acct in data:
                    acct["source"] = "ActiveDirectory"
                self.accounts.extend(data)
                return data
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as exc:
            return {"error": str(exc)}
        return []

    def discover_aws_iam_users(self):
        """Discover AWS IAM service users via CLI."""
        try:
            result = subprocess.run(
                ["aws", "iam", "list-users", "--output", "json"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                users = json.loads(result.stdout).get("Users", [])
                svc_users = []
                for u in users:
                    name = u.get("UserName", "")
                    if any(p in name.lower() for p in ["svc", "service", "bot", "automation"]):
                        keys_result = subprocess.run(
                            ["aws", "iam", "list-access-keys",
                             "--user-name", name, "--output", "json"],
                            capture_output=True, text=True, timeout=30
                        )
                        keys = []
                        if keys_result.returncode == 0:
                            keys = json.loads(keys_result.stdout).get("AccessKeyMetadata", [])
                        svc_users.append({
                            "Name": name, "source": "AWS_IAM",
                            "CreateDate": u.get("CreateDate", ""),
                            "PasswordLastUsed": u.get("PasswordLastUsed", ""),
                            "AccessKeys": len(keys),
                            "OldestKeyDate": min(
                                (k.get("CreateDate", "") for k in keys), default=""
                            ),
                        })
                self.accounts.extend(svc_users)
                return svc_users
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        return []

    def assess_risk(self, account):
        """Classify account risk based on privilege, age, and activity."""
        score = 0
        issues = []

        groups = account.get("Groups", "").split(";") if account.get("Groups") else []
        for grp in groups:
            if grp in self.RISK_WEIGHTS:
                score += self.RISK_WEIGHTS[grp]
                issues.append(f"Member of {grp}")

        if account.get("PasswordNeverExpires"):
            score += 15
            issues.append("PasswordNeverExpires set")

        pwd_set = account.get("PasswordLastSet")
        if pwd_set:
            try:
                pwd_date = datetime.fromisoformat(pwd_set.replace("/Date(", "").rstrip(")/"))
            except (ValueError, AttributeError):
                pwd_date = None
            if pwd_date and (datetime.utcnow() - pwd_date).days > self.max_password_age_days:
                age_days = (datetime.utcnow() - pwd_date).days
                score += 10
                issues.append(f"Password age {age_days} days (>{self.max_password_age_days})")

        last_logon = account.get("LastLogonDate")
        if not last_logon:
            score += 10
            issues.append("No recorded logon (possible orphan)")

        if score >= 40:
            level = "Critical"
        elif score >= 25:
            level = "High"
        elif score >= 10:
            level = "Medium"
        else:
            level = "Low"

        return {"risk_level": level, "risk_score": score, "issues": issues}

    def generate_report(self):
        """Generate a compliance report for all discovered accounts."""
        report = {
            "audit_date": datetime.utcnow().isoformat(),
            "domain": self.domain,
            "total_accounts": len(self.accounts),
            "by_source": defaultdict(int),
            "by_risk": defaultdict(int),
            "accounts": [],
        }

        for acct in self.accounts:
            assessment = self.assess_risk(acct)
            report["by_source"][acct.get("source", "unknown")] += 1
            report["by_risk"][assessment["risk_level"]] += 1
            report["accounts"].append({
                "name": acct.get("Name") or acct.get("SamAccountName", ""),
                "source": acct.get("source", ""),
                **assessment,
            })

        report["by_source"] = dict(report["by_source"])
        report["by_risk"] = dict(report["by_risk"])
        report["accounts"].sort(key=lambda a: a["risk_score"], reverse=True)
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else None
    auditor = ServiceAccountAuditor(domain=domain)
    auditor.discover_ad_service_accounts()
    auditor.discover_aws_iam_users()
    auditor.generate_report()


if __name__ == "__main__":
    main()
