#!/usr/bin/env python3
"""
Zero Standing Privilege Audit Tool

Discovers standing privileged access across AWS, Azure, and GCP,
compares against CyberArk ZSP policies, and identifies accounts
that should be migrated to just-in-time access.

Requirements:
    pip install boto3 requests
"""

import json
import logging
import sys
from datetime import datetime, timedelta, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("zsp_audit")


class StandingPrivilegeDiscovery:
    """Discover standing privileged access across cloud environments."""

    def __init__(self):
        self.findings = []

    def discover_aws_standing_privileges(self, profile_name=None):
        """Find AWS IAM users/roles with standing admin access."""
        try:
            import boto3
        except ImportError:
            logger.error("boto3 required: pip install boto3")
            return []

        session = boto3.Session(profile_name=profile_name)
        iam = session.client("iam")

        admin_policy_arns = {
            "arn:aws:iam::aws:policy/AdministratorAccess",
            "arn:aws:iam::aws:policy/PowerUserAccess",
            "arn:aws:iam::aws:policy/IAMFullAccess",
        }

        standing = []

        # Check IAM users
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                attached = iam.list_attached_user_policies(UserName=username)
                user_policies = {p["PolicyArn"] for p in attached["AttachedPolicies"]}

                has_admin = bool(user_policies & admin_policy_arns)

                # Check groups
                groups = iam.list_groups_for_user(UserName=username)
                for group in groups["Groups"]:
                    grp_policies = iam.list_attached_group_policies(
                        GroupName=group["GroupName"]
                    )
                    for gp in grp_policies["AttachedPolicies"]:
                        if gp["PolicyArn"] in admin_policy_arns:
                            has_admin = True

                if has_admin:
                    access_keys = iam.list_access_keys(UserName=username)
                    active_keys = [
                        k for k in access_keys["AccessKeyMetadata"]
                        if k["Status"] == "Active"
                    ]

                    standing.append({
                        "cloud": "AWS",
                        "identity_type": "User",
                        "identity": username,
                        "privilege_level": "Admin",
                        "policies": list(user_policies & admin_policy_arns),
                        "active_access_keys": len(active_keys),
                        "created": user["CreateDate"].isoformat(),
                        "last_used": str(user.get("PasswordLastUsed", "Never")),
                        "recommendation": "Migrate to CyberArk ZSP",
                    })

        # Check IAM roles (non-service-linked)
        role_paginator = iam.get_paginator("list_roles")
        for page in role_paginator.paginate():
            for role in page["Roles"]:
                if role["Path"].startswith("/aws-service-role/"):
                    continue

                role_policies = iam.list_attached_role_policies(
                    RoleName=role["RoleName"]
                )
                role_admin_policies = {
                    p["PolicyArn"] for p in role_policies["AttachedPolicies"]
                } & admin_policy_arns

                if role_admin_policies:
                    standing.append({
                        "cloud": "AWS",
                        "identity_type": "Role",
                        "identity": role["RoleName"],
                        "privilege_level": "Admin",
                        "policies": list(role_admin_policies),
                        "created": role["CreateDate"].isoformat(),
                        "recommendation": "Convert to ephemeral CyberArk SCA role",
                    })

        self.findings.extend(standing)
        logger.info(f"Discovered {len(standing)} AWS standing privileged identities")
        return standing

    def generate_migration_plan(self):
        """Generate a migration plan to move from standing to ZSP."""
        if not self.findings:
            return {"status": "No standing privileges found"}

        plan = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_standing_privileges": len(self.findings),
            "by_cloud": {},
            "by_type": {},
            "migration_waves": [],
        }

        # Categorize
        for finding in self.findings:
            cloud = finding["cloud"]
            plan["by_cloud"][cloud] = plan["by_cloud"].get(cloud, 0) + 1
            id_type = finding["identity_type"]
            plan["by_type"][id_type] = plan["by_type"].get(id_type, 0) + 1

        # Create migration waves
        users = [f for f in self.findings if f["identity_type"] == "User"]
        roles = [f for f in self.findings if f["identity_type"] == "Role"]

        wave_size = 5
        wave_num = 1

        for i in range(0, len(users), wave_size):
            batch = users[i:i + wave_size]
            plan["migration_waves"].append({
                "wave": wave_num,
                "type": "Users",
                "identities": [u["identity"] for u in batch],
                "count": len(batch),
                "suggested_week": f"Week {wave_num}",
            })
            wave_num += 1

        for i in range(0, len(roles), wave_size):
            batch = roles[i:i + wave_size]
            plan["migration_waves"].append({
                "wave": wave_num,
                "type": "Roles",
                "identities": [r["identity"] for r in batch],
                "count": len(batch),
                "suggested_week": f"Week {wave_num}",
            })
            wave_num += 1

        return plan

    def export_report(self, output_path):
        """Export standing privilege findings and migration plan."""
        report = {
            "report_title": "Standing Privilege Discovery Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings": self.findings,
            "migration_plan": self.generate_migration_plan(),
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"Report exported to {output_path}")
        return report


if __name__ == "__main__":
    print("=" * 60)
    print("Zero Standing Privilege Audit Tool")
    print("=" * 60)
    print()
    print("Usage:")
    print("  discovery = StandingPrivilegeDiscovery()")
    print("  discovery.discover_aws_standing_privileges(profile='prod')")
    print("  plan = discovery.generate_migration_plan()")
    print("  discovery.export_report('zsp_report.json')")
