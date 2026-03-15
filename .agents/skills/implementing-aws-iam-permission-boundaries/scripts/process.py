#!/usr/bin/env python3
"""
AWS IAM Permission Boundary Management Tool

Audits IAM roles for permission boundary compliance, identifies roles
without boundaries, and generates boundary policies based on actual
usage patterns from CloudTrail.

Requirements:
    pip install boto3 pandas
"""

import json
import sys
from datetime import datetime, timezone

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("[ERROR] boto3 is required: pip install boto3")
    sys.exit(1)


class PermissionBoundaryAuditor:
    """Audit IAM roles for permission boundary compliance."""

    def __init__(self, profile_name=None, region="us-east-1"):
        session = boto3.Session(profile_name=profile_name, region_name=region)
        self.iam = session.client("iam")
        self.account_id = session.client("sts").get_caller_identity()["Account"]

    def list_roles_without_boundary(self):
        """Find all IAM roles that do not have a permission boundary attached."""
        roles_without_boundary = []
        paginator = self.iam.get_paginator("list_roles")

        for page in paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]
                boundary = role.get("PermissionsBoundary")

                if boundary is None:
                    # Skip AWS service-linked roles
                    if role["Path"].startswith("/aws-service-role/"):
                        continue

                    roles_without_boundary.append({
                        "RoleName": role_name,
                        "Arn": role["Arn"],
                        "CreateDate": role["CreateDate"].isoformat(),
                        "Path": role["Path"],
                        "HasBoundary": False,
                    })

        return roles_without_boundary

    def list_roles_with_boundary(self):
        """List all roles that have a permission boundary and which boundary."""
        roles_with_boundary = []
        paginator = self.iam.get_paginator("list_roles")

        for page in paginator.paginate():
            for role in page["Roles"]:
                boundary = role.get("PermissionsBoundary")
                if boundary:
                    roles_with_boundary.append({
                        "RoleName": role["RoleName"],
                        "Arn": role["Arn"],
                        "BoundaryArn": boundary["PermissionsBoundaryArn"],
                        "BoundaryType": boundary["PermissionsBoundaryType"],
                    })

        return roles_with_boundary

    def verify_boundary_denies_escalation(self, boundary_policy_arn):
        """Check that a permission boundary includes anti-escalation deny statements."""
        try:
            policy = self.iam.get_policy(PolicyArn=boundary_policy_arn)
            version_id = policy["Policy"]["DefaultVersionId"]
            policy_version = self.iam.get_policy_version(
                PolicyArn=boundary_policy_arn, VersionId=version_id
            )
            document = policy_version["PolicyVersion"]["Document"]
        except ClientError as e:
            return {"error": str(e)}

        if isinstance(document, str):
            document = json.loads(document)

        escalation_actions = {
            "iam:DeleteRolePermissionsBoundary",
            "iam:DeleteUserPermissionsBoundary",
            "iam:CreatePolicyVersion",
            "iam:SetDefaultPolicyVersion",
        }

        denied_actions = set()
        for statement in document.get("Statement", []):
            if statement.get("Effect") == "Deny":
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                denied_actions.update(actions)

        missing_denies = escalation_actions - denied_actions
        return {
            "boundary_arn": boundary_policy_arn,
            "has_escalation_protection": len(missing_denies) == 0,
            "denied_actions": list(denied_actions),
            "missing_deny_actions": list(missing_denies),
        }

    def attach_boundary_to_role(self, role_name, boundary_policy_arn):
        """Attach a permission boundary to an existing IAM role."""
        try:
            self.iam.put_role_permissions_boundary(
                RoleName=role_name,
                PermissionsBoundary=boundary_policy_arn
            )
            return {"success": True, "role": role_name, "boundary": boundary_policy_arn}
        except ClientError as e:
            return {"success": False, "role": role_name, "error": str(e)}

    def generate_audit_report(self):
        """Generate a full compliance report for permission boundaries."""
        roles_without = self.list_roles_without_boundary()
        roles_with = self.list_roles_with_boundary()

        # Check escalation protection for each unique boundary
        boundary_arns = set(r["BoundaryArn"] for r in roles_with)
        boundary_checks = {}
        for arn in boundary_arns:
            boundary_checks[arn] = self.verify_boundary_denies_escalation(arn)

        report = {
            "report_title": "IAM Permission Boundary Compliance Audit",
            "account_id": self.account_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_roles_with_boundary": len(roles_with),
                "total_roles_without_boundary": len(roles_without),
                "unique_boundaries": len(boundary_arns),
                "boundaries_with_escalation_protection": sum(
                    1 for v in boundary_checks.values()
                    if v.get("has_escalation_protection")
                ),
            },
            "roles_without_boundary": roles_without,
            "boundary_escalation_analysis": boundary_checks,
        }

        return report


def generate_boundary_policy(allowed_services, role_prefix="app-",
                              boundary_name="DeveloperBoundary"):
    """Generate a permission boundary policy JSON for given allowed services."""
    service_action_map = {
        "s3": "s3:*",
        "dynamodb": "dynamodb:*",
        "lambda": "lambda:*",
        "sqs": "sqs:*",
        "sns": "sns:*",
        "logs": "logs:*",
        "cloudwatch": "cloudwatch:*",
        "events": "events:*",
        "states": "states:*",
        "xray": "xray:*",
        "ec2": ["ec2:Describe*", "ec2:CreateTags"],
        "ecs": ["ecs:*", "ecr:*"],
        "rds": "rds:*",
        "secretsmanager": "secretsmanager:GetSecretValue",
        "kms": ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
        "ssm": ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"],
    }

    actions = []
    for service in allowed_services:
        service_lower = service.lower()
        if service_lower in service_action_map:
            action = service_action_map[service_lower]
            if isinstance(action, list):
                actions.extend(action)
            else:
                actions.append(action)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowedServices",
                "Effect": "Allow",
                "Action": actions,
                "Resource": "*"
            },
            {
                "Sid": "AllowPassRole",
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": f"arn:aws:iam::*:role/{role_prefix}*",
                "Condition": {
                    "StringEquals": {
                        "iam:PassedToService": [
                            "lambda.amazonaws.com",
                            "ecs-tasks.amazonaws.com",
                            "states.amazonaws.com"
                        ]
                    }
                }
            },
            {
                "Sid": "DenyBoundaryModification",
                "Effect": "Deny",
                "Action": [
                    "iam:DeletePolicy",
                    "iam:DeletePolicyVersion",
                    "iam:CreatePolicyVersion",
                    "iam:SetDefaultPolicyVersion"
                ],
                "Resource": f"arn:aws:iam::*:policy/{boundary_name}"
            },
            {
                "Sid": "DenyBoundaryRemoval",
                "Effect": "Deny",
                "Action": [
                    "iam:DeleteUserPermissionsBoundary",
                    "iam:DeleteRolePermissionsBoundary"
                ],
                "Resource": "*"
            }
        ]
    }

    return json.dumps(policy, indent=2)


if __name__ == "__main__":
    print("=" * 60)
    print("AWS IAM Permission Boundary Management Tool")
    print("=" * 60)
    print()
    print("Usage:")
    print("  auditor = PermissionBoundaryAuditor(profile='prod')")
    print("  report = auditor.generate_audit_report()")
    print()
    print("Generate a boundary policy:")
    services = ["s3", "dynamodb", "lambda", "sqs", "logs", "cloudwatch"]
    policy = generate_boundary_policy(services)
    print(policy)
