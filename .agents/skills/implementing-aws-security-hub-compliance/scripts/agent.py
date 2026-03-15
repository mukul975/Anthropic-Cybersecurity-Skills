#!/usr/bin/env python3
"""AWS Security Hub compliance monitoring agent with automated remediation."""

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


def get_clients(region="us-east-1"):
    """Create Security Hub and S3 clients."""
    return (boto3.client("securityhub", region_name=region),
            boto3.client("s3", region_name=region))


def get_compliance_findings(hub_client, standard_filter=None, max_results=100):
    """Get failed compliance findings, optionally filtered by standard."""
    filters = {
        "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
    }
    if standard_filter:
        filters["GeneratorId"] = [{"Value": standard_filter, "Comparison": "PREFIX"}]
    try:
        resp = hub_client.get_findings(
            Filters=filters,
            SortCriteria=[{"Field": "SeverityNormalized", "SortOrder": "desc"}],
            MaxResults=max_results)
        return resp.get("Findings", [])
    except ClientError as e:
        print(f"[!] Error getting findings: {e}")
        return []


def analyze_compliance_gaps(findings):
    """Analyze findings to identify compliance gaps by control and account."""
    by_control = Counter()
    by_severity = Counter()
    by_account = Counter()
    control_details = {}
    for f in findings:
        title = f.get("Title", "Unknown")
        severity = f["Severity"]["Label"]
        account = f.get("AwsAccountId", "Unknown")
        by_control[title] += 1
        by_severity[severity] += 1
        by_account[account] += 1
        if title not in control_details:
            control_details[title] = {
                "severity": severity,
                "generator": f.get("GeneratorId", ""),
                "accounts": set(),
                "resource_types": set(),
            }
        control_details[title]["accounts"].add(account)
        for r in f.get("Resources", []):
            control_details[title]["resource_types"].add(r.get("Type", ""))
    for k in control_details:
        control_details[k]["accounts"] = list(control_details[k]["accounts"])
        control_details[k]["resource_types"] = list(control_details[k]["resource_types"])
    return {"by_control": dict(by_control.most_common(20)),
            "by_severity": dict(by_severity), "by_account": dict(by_account.most_common(10)),
            "control_details": control_details}


def remediate_s3_public_access(s3_client, bucket_name):
    """Block public access on an S3 bucket."""
    try:
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
        return {"bucket": bucket_name, "status": "remediated"}
    except ClientError as e:
        return {"bucket": bucket_name, "status": "error", "message": str(e)}


def auto_remediate_findings(hub_client, s3_client, findings):
    """Auto-remediate safe-to-fix findings (S3 public access)."""
    remediated = []
    for f in findings:
        title = f.get("Title", "").lower()
        if "s3" in title and "public" in title:
            for r in f.get("Resources", []):
                if r["Type"] == "AwsS3Bucket":
                    bucket = r["Id"].split(":::")[-1]
                    result = remediate_s3_public_access(s3_client, bucket)
                    if result["status"] == "remediated":
                        hub_client.batch_update_findings(
                            FindingIdentifiers=[{"Id": f["Id"], "ProductArn": f["ProductArn"]}],
                            Workflow={"Status": "RESOLVED"},
                            Note={"Text": "Auto-remediated: public access blocked",
                                  "UpdatedBy": "compliance-agent"})
                    remediated.append(result)
    return remediated


def create_compliance_insight(hub_client, name, group_by_attr, severity_filter=None):
    """Create a custom Security Hub insight for compliance tracking."""
    filters = {"ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}]}
    if severity_filter:
        filters["SeverityLabel"] = [{"Value": s, "Comparison": "EQUALS"} for s in severity_filter]
    try:
        resp = hub_client.create_insight(Name=name, Filters=filters, GroupByAttribute=group_by_attr)
        return {"insight_arn": resp["InsightArn"]}
    except ClientError as e:
        return {"error": str(e)}


def run_compliance_report(region="us-east-1"):
    """Generate full compliance report."""
    hub_client, s3_client = get_clients(region)

    print(f"\n{'='*60}")
    print(f"  AWS SECURITY HUB COMPLIANCE REPORT")
    print(f"  Region: {region}")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    findings = get_compliance_findings(hub_client)
    analysis = analyze_compliance_gaps(findings)

    print(f"--- FINDINGS BY SEVERITY ---")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = analysis["by_severity"].get(sev, 0)
        bar = "#" * min(count, 40)
        print(f"  {sev:<12} {count:>4} {bar}")

    print(f"\n--- TOP FAILED CONTROLS ---")
    for control, count in list(analysis["by_control"].items())[:10]:
        detail = analysis["control_details"].get(control, {})
        acct_count = len(detail.get("accounts", []))
        print(f"  [{count:3d}] {control[:60]}")
        print(f"        Severity: {detail.get('severity', 'N/A')} | Accounts: {acct_count}")

    print(f"\n--- TOP AFFECTED ACCOUNTS ---")
    for acct, count in list(analysis["by_account"].items())[:5]:
        print(f"  {acct}: {count} failed controls")

    print(f"\n  Total failed findings: {len(findings)}")
    print(f"{'='*60}\n")
    return {"findings_count": len(findings), "analysis": analysis}


def main():
    parser = argparse.ArgumentParser(description="AWS Security Hub Compliance Agent")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--audit", action="store_true", help="Run compliance audit")
    parser.add_argument("--remediate", action="store_true", help="Auto-remediate safe findings")
    parser.add_argument("--output", help="Save report to JSON")
    args = parser.parse_args()

    if args.audit:
        report = run_compliance_report(args.region)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
    elif args.remediate:
        hub, s3 = get_clients(args.region)
        findings = get_compliance_findings(hub)
        results = auto_remediate_findings(hub, s3, findings)
        for r in results:
            print(f"  [{r['status']}] {r.get('bucket', 'unknown')}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
