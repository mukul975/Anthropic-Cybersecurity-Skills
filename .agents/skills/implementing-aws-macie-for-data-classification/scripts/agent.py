#!/usr/bin/env python3
"""AWS Macie data classification agent using boto3 for S3 sensitive data discovery."""

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


def get_macie_client(profile: str = "", region: str = "us-east-1"):
    """Create Macie2 client."""
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    return session.client("macie2", region_name=region)


def enable_macie(client) -> dict:
    """Enable Macie in the account if not already enabled."""
    try:
        client.get_macie_session()
        return {"status": "already_enabled"}
    except ClientError:
        try:
            client.enable_macie(status="ENABLED")
            return {"status": "enabled"}
        except ClientError as exc:
            return {"error": str(exc)}


def list_s3_buckets_summary(client) -> List[dict]:
    """Get Macie's summary of S3 bucket inventory."""
    try:
        resp = client.describe_buckets(criteria={}, maxResults=50)
        buckets = []
        for b in resp.get("buckets", []):
            buckets.append({
                "name": b.get("bucketName", ""),
                "region": b.get("region", ""),
                "classifiable_objects": b.get("classifiableObjectCount", 0),
                "classifiable_size": b.get("classifiableSizeInBytes", 0),
                "encryption": b.get("serverSideEncryption", {}).get("type", "NONE"),
                "public_access": b.get("publicAccess", {}).get("effectivePermission", "NOT_PUBLIC"),
                "shared_access": b.get("sharedAccess", "NOT_SHARED"),
            })
        return buckets
    except ClientError as exc:
        logger.error("describe_buckets failed: %s", exc)
        return []


def create_classification_job(client, bucket_names: List[str], job_name: str) -> dict:
    """Create a one-time sensitive data discovery job for specified buckets."""
    try:
        resp = client.create_classification_job(
            jobType="ONE_TIME",
            name=job_name,
            s3JobDefinition={
                "bucketDefinitions": [{
                    "accountId": boto3.client("sts").get_caller_identity()["Account"],
                    "buckets": bucket_names,
                }]
            },
            description=f"Scan {len(bucket_names)} buckets for sensitive data",
        )
        return {"job_id": resp["jobId"], "job_arn": resp["jobArn"]}
    except ClientError as exc:
        return {"error": str(exc)}


def get_finding_statistics(client) -> dict:
    """Get statistics on Macie findings by severity and type."""
    try:
        by_severity = client.get_finding_statistics(
            groupBy="severity.description",
        )
        by_type = client.get_finding_statistics(
            groupBy="type",
        )
        return {
            "by_severity": by_severity.get("countsBySeverity", []),
            "by_type": by_type.get("countsByGroup", []),
        }
    except ClientError as exc:
        return {"error": str(exc)}


def list_findings(client, severity: str = "High", max_results: int = 50) -> List[dict]:
    """List recent Macie findings filtered by severity."""
    try:
        resp = client.list_findings(
            findingCriteria={
                "criterion": {
                    "severity.description": {"eq": [severity]}
                }
            },
            maxResults=max_results,
        )
        finding_ids = resp.get("findingIds", [])
        if not finding_ids:
            return []
        details = client.get_findings(findingIds=finding_ids[:20])
        return [{
            "id": f.get("id", ""),
            "type": f.get("type", ""),
            "severity": f.get("severity", {}).get("description", ""),
            "title": f.get("title", ""),
            "bucket": f.get("resourcesAffected", {}).get("s3Bucket", {}).get("name", ""),
            "count": f.get("count", 0),
            "created": f.get("createdAt", ""),
        } for f in details.get("findings", [])]
    except ClientError as exc:
        return [{"error": str(exc)}]


def generate_report(client) -> dict:
    """Generate Macie data classification report."""
    report = {"analysis_date": datetime.utcnow().isoformat()}
    report["macie_status"] = enable_macie(client)
    report["bucket_inventory"] = list_s3_buckets_summary(client)
    report["finding_statistics"] = get_finding_statistics(client)
    report["high_findings"] = list_findings(client, "High")
    report["critical_findings"] = list_findings(client, "Critical")
    public_buckets = [b for b in report["bucket_inventory"]
                      if b.get("public_access") != "NOT_PUBLIC"]
    report["public_buckets"] = public_buckets
    report["summary"] = {
        "total_buckets": len(report["bucket_inventory"]),
        "public_buckets": len(public_buckets),
        "high_findings": len(report["high_findings"]),
        "critical_findings": len(report["critical_findings"]),
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="AWS Macie Data Classification Agent")
    parser.add_argument("--profile", default="", help="AWS CLI profile")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--output", default="macie_report.json")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    client = get_macie_client(args.profile, args.region)
    report = generate_report(client)
    out_path = os.path.join(args.output_dir, args.output)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Report saved to %s", out_path)
    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
