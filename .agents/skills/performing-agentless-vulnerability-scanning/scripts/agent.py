#!/usr/bin/env python3
"""Agentless Vulnerability Scanning agent - uses AWS Inspector2 and SSM APIs
via boto3 to perform agentless scans of EC2 instances through EBS snapshot
analysis without requiring installed agents."""

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("Install boto3: pip install boto3", file=sys.stderr)
    sys.exit(1)


def get_inspector_client(region: str = "us-east-1", profile: str = None):
    """Create AWS Inspector2 client."""
    session = boto3.Session(profile_name=profile, region_name=region)
    return session.client("inspector2")


def get_ec2_client(region: str = "us-east-1", profile: str = None):
    """Create EC2 client."""
    session = boto3.Session(profile_name=profile, region_name=region)
    return session.client("ec2")


def check_inspector_status(client) -> dict:
    """Check Inspector2 enablement status."""
    try:
        response = client.batch_get_account_status(
            accountIds=[boto3.client("sts").get_caller_identity()["Account"]]
        )
        accounts = response.get("accounts", [])
        if accounts:
            status = accounts[0].get("state", {}).get("status", "UNKNOWN")
            return {"enabled": status == "ENABLED", "status": status}
        return {"enabled": False, "status": "NO_DATA"}
    except ClientError as e:
        return {"enabled": False, "error": str(e)}


def list_ec2_scan_coverage(client) -> list[dict]:
    """List EC2 instances and their scan coverage status."""
    coverage = []
    paginator = client.get_paginator("list_coverage")
    for page in paginator.paginate(
        filterCriteria={"resourceType": [{"comparison": "EQUALS", "value": "AWS_EC2_INSTANCE"}]}
    ):
        for item in page.get("coveredResources", []):
            coverage.append({
                "resource_id": item.get("resourceId", ""),
                "resource_type": item.get("resourceType", ""),
                "scan_status": item.get("scanStatus", {}).get("statusCode", "UNKNOWN"),
                "scan_type": item.get("scanType", ""),
                "account_id": item.get("accountId", ""),
            })
    return coverage


def list_findings(client, severity_filter: list[str] = None,
                  max_results: int = 500) -> list[dict]:
    """List vulnerability findings from Inspector2."""
    filter_criteria = {}
    if severity_filter:
        filter_criteria["severity"] = [
            {"comparison": "EQUALS", "value": s} for s in severity_filter
        ]
    findings = []
    paginator = client.get_paginator("list_findings")
    params = {"filterCriteria": filter_criteria, "maxResults": min(max_results, 100)}
    count = 0
    for page in paginator.paginate(**params):
        for finding in page.get("findings", []):
            findings.append({
                "finding_arn": finding.get("findingArn", ""),
                "title": finding.get("title", ""),
                "severity": finding.get("severity", ""),
                "status": finding.get("status", ""),
                "type": finding.get("type", ""),
                "resource_id": finding.get("resources", [{}])[0].get("id", ""),
                "resource_type": finding.get("resources", [{}])[0].get("type", ""),
                "vulnerability_id": finding.get("packageVulnerabilityDetails", {}).get("vulnerabilityId", ""),
                "cvss_score": finding.get("packageVulnerabilityDetails", {}).get("cvss", [{}])[0].get("baseScore", 0),
                "fixed_in": finding.get("packageVulnerabilityDetails", {}).get("fixedInVersion", ""),
                "first_observed": str(finding.get("firstObservedAt", "")),
            })
            count += 1
            if count >= max_results:
                return findings
    return findings


def create_ebs_snapshot_scan(ec2_client, instance_id: str) -> dict:
    """Create EBS snapshots for agentless scanning."""
    try:
        volumes = ec2_client.describe_volumes(
            Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
        )
        snapshots = []
        for vol in volumes.get("Volumes", []):
            snap = ec2_client.create_snapshot(
                VolumeId=vol["VolumeId"],
                Description=f"Agentless scan snapshot for {instance_id}",
                TagSpecifications=[{
                    "ResourceType": "snapshot",
                    "Tags": [{"Key": "Purpose", "Value": "AgentlessVulnScan"},
                             {"Key": "SourceInstance", "Value": instance_id}]
                }]
            )
            snapshots.append({"volume_id": vol["VolumeId"], "snapshot_id": snap["SnapshotId"]})
        return {"instance_id": instance_id, "snapshots": snapshots}
    except ClientError as e:
        return {"instance_id": instance_id, "error": str(e)}


def generate_report(region: str, profile: str = None,
                    severity_filter: list[str] = None) -> dict:
    """Run agentless scanning assessment and build report."""
    inspector = get_inspector_client(region, profile)
    status = check_inspector_status(inspector)
    coverage = list_ec2_scan_coverage(inspector)
    findings = list_findings(inspector, severity_filter)

    severity_counts = Counter(f["severity"] for f in findings)
    uncovered = [c for c in coverage if c["scan_status"] != "ACTIVE"]
    return {
        "report": "agentless_vulnerability_scanning",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "region": region,
        "inspector_status": status,
        "total_resources_scanned": len(coverage),
        "uncovered_resources": len(uncovered),
        "total_findings": len(findings),
        "severity_summary": dict(severity_counts),
        "uncovered_resources_list": uncovered[:20],
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="Agentless Vulnerability Scanning Agent")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--severity", nargs="+", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        help="Filter by severity")
    parser.add_argument("--output", help="Output JSON file path")
    args = parser.parse_args()

    report = generate_report(args.region, args.profile, args.severity)
    output = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
