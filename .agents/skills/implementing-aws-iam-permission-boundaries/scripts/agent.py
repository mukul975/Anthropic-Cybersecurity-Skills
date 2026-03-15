#!/usr/bin/env python3
"""AWS IAM permission boundary management agent using boto3."""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    sys.exit("boto3 required: pip install boto3")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def get_iam_client(profile: str = "", region: str = "us-east-1"):
    """Create IAM client with optional profile."""
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    return session.client("iam", region_name=region)


def create_permission_boundary(client, policy_name: str, allowed_services: List[str],
                                allowed_regions: List[str] = None) -> dict:
    """Create a permission boundary policy restricting services and regions."""
    statements = [{
        "Sid": "AllowedServices",
        "Effect": "Allow",
        "Action": [f"{svc}:*" for svc in allowed_services],
        "Resource": "*",
    }]
    if allowed_regions:
        statements[0]["Condition"] = {
            "StringEquals": {"aws:RequestedRegion": allowed_regions}
        }
    statements.append({
        "Sid": "DenyBoundaryChanges",
        "Effect": "Deny",
        "Action": ["iam:DeleteRolePermissionsBoundary", "iam:PutRolePermissionsBoundary"],
        "Resource": "*",
    })
    policy_doc = {"Version": "2012-10-17", "Statement": statements}
    try:
        resp = client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_doc),
            Description=f"Permission boundary: {', '.join(allowed_services)}",
        )
        arn = resp["Policy"]["Arn"]
        logger.info("Created boundary policy: %s", arn)
        return {"policy_arn": arn, "policy_document": policy_doc}
    except ClientError as exc:
        return {"error": str(exc)}


def attach_boundary_to_role(client, role_name: str, boundary_arn: str) -> dict:
    """Attach permission boundary to an IAM role."""
    try:
        client.put_role_permissions_boundary(
            RoleName=role_name, PermissionsBoundary=boundary_arn)
        logger.info("Attached boundary %s to role %s", boundary_arn, role_name)
        return {"role": role_name, "boundary_arn": boundary_arn, "attached": True}
    except ClientError as exc:
        return {"role": role_name, "error": str(exc)}


def audit_roles_without_boundary(client) -> List[dict]:
    """Find IAM roles that lack a permission boundary."""
    paginator = client.get_paginator("list_roles")
    unbounded = []
    for page in paginator.paginate():
        for role in page["Roles"]:
            if "PermissionsBoundary" not in role:
                unbounded.append({
                    "role_name": role["RoleName"],
                    "arn": role["Arn"],
                    "created": role["CreateDate"].isoformat(),
                })
    logger.info("Found %d roles without permission boundary", len(unbounded))
    return unbounded


def audit_boundary_effectiveness(client, role_name: str) -> dict:
    """Audit effective permissions for a role with boundary."""
    try:
        role = client.get_role(RoleName=role_name)["Role"]
        boundary = role.get("PermissionsBoundary", {})
        policies_resp = client.list_attached_role_policies(RoleName=role_name)
        inline_resp = client.list_role_policies(RoleName=role_name)
        return {
            "role": role_name,
            "boundary_arn": boundary.get("PermissionsBoundaryArn", "NONE"),
            "attached_policies": [p["PolicyName"] for p in policies_resp["AttachedPolicies"]],
            "inline_policies": inline_resp["PolicyNames"],
        }
    except ClientError as exc:
        return {"role": role_name, "error": str(exc)}


def generate_report(client) -> dict:
    """Generate permission boundary compliance report."""
    unbounded = audit_roles_without_boundary(client)
    report = {
        "analysis_date": datetime.utcnow().isoformat(),
        "roles_without_boundary": unbounded,
        "roles_without_boundary_count": len(unbounded),
        "recommendations": [],
    }
    if unbounded:
        report["recommendations"].append(
            f"Attach permission boundaries to {len(unbounded)} roles lacking boundaries")
    return report


def main():
    parser = argparse.ArgumentParser(description="AWS IAM Permission Boundary Agent")
    parser.add_argument("--profile", default="", help="AWS CLI profile name")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--audit", action="store_true", help="Audit roles without boundaries")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--output", default="iam_boundary_report.json")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    client = get_iam_client(args.profile, args.region)
    report = generate_report(client)
    out_path = os.path.join(args.output_dir, args.output)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Report saved to %s", out_path)
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
