#!/usr/bin/env python3
"""
AWS Macie Data Classification Management Script

Automates Macie configuration, job creation, and findings analysis.
"""

import boto3
import json
import sys
from datetime import datetime


def enable_macie(session):
    """Enable Macie in the current account."""
    client = session.client('macie2')
    try:
        client.enable_macie(status='ENABLED')
        print("[+] Macie enabled successfully")
    except client.exceptions.ConflictException:
        print("[*] Macie is already enabled")

    # Enable automated discovery
    try:
        client.update_automated_discovery_configuration(status='ENABLED')
        print("[+] Automated discovery enabled")
    except Exception as e:
        print(f"[!] Could not enable automated discovery: {e}")


def create_classification_job(session, bucket_names, account_id, job_name=None):
    """Create a one-time classification job for specified buckets."""
    client = session.client('macie2')

    if not job_name:
        job_name = f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    response = client.create_classification_job(
        jobType='ONE_TIME',
        name=job_name,
        s3JobDefinition={
            'bucketDefinitions': [{
                'accountId': account_id,
                'buckets': bucket_names
            }]
        },
        managedDataIdentifierSelector='ALL'
    )

    job_id = response['jobId']
    print(f"[+] Classification job created: {job_id}")
    return job_id


def list_findings(session, severity=None, max_results=25):
    """List Macie findings with optional severity filter."""
    client = session.client('macie2')

    criteria = {}
    if severity:
        criteria['severity.description'] = {'eq': [severity]}

    response = client.list_findings(
        findingCriteria={'criterion': criteria} if criteria else {},
        sortCriteria={'attributeName': 'updatedAt', 'orderBy': 'DESC'},
        maxResults=max_results
    )

    finding_ids = response.get('findingIds', [])
    print(f"[+] Found {len(finding_ids)} findings")

    if finding_ids:
        details = client.get_findings(findingIds=finding_ids[:20])
        for finding in details.get('findings', []):
            severity_desc = finding['severity']['description']
            category = finding.get('category', 'N/A')
            title = finding.get('title', 'N/A')
            bucket = finding.get('resourcesAffected', {}).get('s3Bucket', {}).get('name', 'N/A')
            print(f"  [{severity_desc}] {title}")
            print(f"    Bucket: {bucket} | Category: {category}")

    return finding_ids


def get_bucket_statistics(session):
    """Get Macie statistics for all monitored S3 buckets."""
    client = session.client('macie2')

    response = client.describe_buckets(
        criteria={},
        maxResults=50
    )

    buckets = response.get('buckets', [])
    print(f"\n[+] Monitoring {len(buckets)} S3 buckets:")
    print(f"{'Bucket':<40} {'Encryption':<15} {'Public':<10} {'Shared':<10} {'Objects':<10}")
    print("-" * 85)

    for bucket in buckets:
        name = bucket.get('bucketName', 'N/A')
        encryption = bucket.get('serverSideEncryption', {}).get('type', 'NONE')
        public_access = bucket.get('publicAccess', {}).get('effectivePermission', 'NOT_PUBLIC')
        shared = bucket.get('sharedAccess', 'NOT_SHARED')
        obj_count = bucket.get('objectCount', 0)

        public_flag = "YES" if public_access == "PUBLIC" else "NO"
        shared_flag = "YES" if shared != "NOT_SHARED" else "NO"

        print(f"{name:<40} {encryption:<15} {public_flag:<10} {shared_flag:<10} {obj_count:<10}")

    return buckets


def get_usage_stats(session):
    """Get Macie usage statistics."""
    client = session.client('macie2')

    response = client.get_usage_totals()
    usage = response.get('usageTotals', [])

    print("\n[+] Macie Usage Statistics:")
    for item in usage:
        usage_type = item.get('type', 'N/A')
        amount = item.get('estimatedCost', 0)
        currency = item.get('currency', 'USD')
        print(f"  {usage_type}: ${amount:.2f} {currency}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AWS Macie Management")
    parser.add_argument("--enable", action="store_true", help="Enable Macie")
    parser.add_argument("--scan", nargs="+", help="Create scan job for buckets")
    parser.add_argument("--account-id", type=str, help="AWS account ID for scan")
    parser.add_argument("--findings", action="store_true", help="List findings")
    parser.add_argument("--severity", type=str, choices=["Low", "Medium", "High"], help="Filter by severity")
    parser.add_argument("--buckets", action="store_true", help="Show bucket statistics")
    parser.add_argument("--usage", action="store_true", help="Show usage statistics")
    parser.add_argument("--region", type=str, default="us-east-1", help="AWS region")
    parser.add_argument("--profile", type=str, help="AWS profile name")

    args = parser.parse_args()

    session_kwargs = {"region_name": args.region}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    session = boto3.Session(**session_kwargs)

    if args.enable:
        enable_macie(session)
    if args.scan:
        if not args.account_id:
            sts = session.client('sts')
            args.account_id = sts.get_caller_identity()['Account']
        create_classification_job(session, args.scan, args.account_id)
    if args.findings:
        list_findings(session, severity=args.severity)
    if args.buckets:
        get_bucket_statistics(session)
    if args.usage:
        get_usage_stats(session)
