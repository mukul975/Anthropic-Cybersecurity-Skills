#!/usr/bin/env python3
"""AWS Security Hub CSPM agent using boto3 securityhub client."""

import json
import sys
import argparse
from datetime import datetime
from collections import Counter

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("Install boto3: pip install boto3")
    sys.exit(1)


def get_hub_client(region="us-east-1"):
    """Create Security Hub client."""
    return boto3.client("securityhub", region_name=region)


def enable_security_hub(client):
    """Enable Security Hub with default standards."""
    try:
        client.enable_security_hub(EnableDefaultStandards=True,
                                   Tags={"ManagedBy": "security-agent"})
        return {"status": "enabled"}
    except ClientError as e:
        if "already enabled" in str(e).lower():
            return {"status": "already_enabled"}
        return {"error": str(e)}


def enable_standards(client, standards):
    """Enable specific compliance standards."""
    standard_arns = {
        "cis": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/5.0.0",
        "fsbp": "arn:aws:securityhub:{region}::standards/aws-foundational-security-best-practices/v/1.0.0",
        "pci": "arn:aws:securityhub:{region}::standards/pci-dss/v/3.2.1",
        "nist": "arn:aws:securityhub:{region}::standards/nist-800-53/v/5.0.0",
    }
    region = client.meta.region_name
    requests = []
    for s in standards:
        if s in standard_arns:
            arn = standard_arns[s].replace("{region}", region)
            requests.append({"StandardsArn": arn})
    if requests:
        try:
            resp = client.batch_enable_standards(StandardsSubscriptionRequests=requests)
            return [{"arn": s["StandardsArn"], "status": s["StandardsStatus"]}
                    for s in resp.get("StandardsSubscriptions", [])]
        except ClientError as e:
            return [{"error": str(e)}]
    return []


def get_enabled_standards(client):
    """List all enabled security standards and their status."""
    try:
        resp = client.get_enabled_standards()
        return [{"arn": s["StandardsArn"], "status": s["StandardsStatus"]}
                for s in resp.get("StandardsSubscriptions", [])]
    except ClientError as e:
        return [{"error": str(e)}]


def get_findings_summary(client, max_results=100):
    """Retrieve active findings grouped by severity."""
    try:
        resp = client.get_findings(
            Filters={"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                     "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}]},
            SortCriteria=[{"Field": "SeverityNormalized", "SortOrder": "desc"}],
            MaxResults=max_results)
        findings = resp.get("Findings", [])
        severity_counts = Counter(f["Severity"]["Label"] for f in findings)
        failed_controls = Counter()
        for f in findings:
            if f.get("Compliance", {}).get("Status") == "FAILED":
                failed_controls[f.get("Title", "Unknown")] += 1
        return {"total": len(findings), "by_severity": dict(severity_counts),
                "top_failed_controls": dict(failed_controls.most_common(10)),
                "findings": findings}
    except ClientError as e:
        return {"error": str(e)}


def get_compliance_scores(client):
    """Get compliance scores for all enabled standards."""
    standards = get_enabled_standards(client)
    scores = []
    for std in standards:
        if "error" in std:
            continue
        scores.append({"standard": std["arn"].split("/")[-3] if "/" in std["arn"] else std["arn"],
                        "status": std["status"]})
    return scores


def create_custom_insight(client, name, group_by, filters):
    """Create a custom Security Hub insight."""
    try:
        resp = client.create_insight(Name=name, Filters=filters, GroupByAttribute=group_by)
        return {"insight_arn": resp["InsightArn"], "status": "created"}
    except ClientError as e:
        return {"error": str(e)}


def batch_update_findings(client, finding_ids, workflow_status, note):
    """Update findings workflow status in batch."""
    identifiers = [{"Id": fid["Id"], "ProductArn": fid["ProductArn"]} for fid in finding_ids]
    try:
        client.batch_update_findings(
            FindingIdentifiers=identifiers,
            Workflow={"Status": workflow_status},
            Note={"Text": note, "UpdatedBy": "security-hub-agent"})
        return {"updated": len(identifiers), "status": workflow_status}
    except ClientError as e:
        return {"error": str(e)}


def run_security_hub_audit(region="us-east-1"):
    """Run a full Security Hub audit and print report."""
    client = get_hub_client(region)

    print(f"\n{'='*60}")
    print(f"  AWS SECURITY HUB AUDIT REPORT")
    print(f"  Region: {region}")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    standards = get_enabled_standards(client)
    print(f"--- ENABLED STANDARDS ({len(standards)}) ---")
    for s in standards:
        print(f"  {s.get('arn', 'N/A')}: {s.get('status', 'N/A')}")

    summary = get_findings_summary(client)
    print(f"\n--- FINDINGS SUMMARY ---")
    print(f"  Total Active: {summary.get('total', 0)}")
    for sev, count in summary.get("by_severity", {}).items():
        print(f"  {sev}: {count}")

    print(f"\n--- TOP FAILED CONTROLS ---")
    for control, count in summary.get("top_failed_controls", {}).items():
        print(f"  [{count:3d}] {control[:70]}")

    print(f"\n{'='*60}\n")
    return {"standards": standards, "findings": summary}


def main():
    parser = argparse.ArgumentParser(description="AWS Security Hub Agent")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--enable", action="store_true", help="Enable Security Hub")
    parser.add_argument("--standards", nargs="+", choices=["cis", "fsbp", "pci", "nist"],
                        help="Enable specific standards")
    parser.add_argument("--audit", action="store_true", help="Run Security Hub audit")
    parser.add_argument("--output", help="Save report to JSON")
    args = parser.parse_args()

    if args.enable:
        result = enable_security_hub(get_hub_client(args.region))
        print(f"Security Hub: {result}")
    if args.standards:
        results = enable_standards(get_hub_client(args.region), args.standards)
        for r in results:
            print(f"  Standard: {r}")
    if args.audit:
        report = run_security_hub_audit(args.region)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"[+] Report saved to {args.output}")
    if not any([args.enable, args.standards, args.audit]):
        parser.print_help()


if __name__ == "__main__":
    main()
