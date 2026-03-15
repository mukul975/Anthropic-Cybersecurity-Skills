#!/usr/bin/env python3
"""AWS Config compliance monitoring agent using boto3."""

import json
import sys
import argparse
from datetime import datetime

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("Install boto3: pip install boto3")
    sys.exit(1)


MANAGED_RULES = {
    "s3-bucket-public-read-prohibited": "S3_BUCKET_PUBLIC_READ_PROHIBITED",
    "s3-bucket-server-side-encryption-enabled": "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED",
    "s3-bucket-ssl-requests-only": "S3_BUCKET_SSL_REQUESTS_ONLY",
    "iam-root-access-key-check": "IAM_ROOT_ACCESS_KEY_CHECK",
    "mfa-enabled-for-iam-console-access": "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS",
    "restricted-ssh": "INCOMING_SSH_DISABLED",
    "vpc-flow-logs-enabled": "VPC_FLOW_LOGS_ENABLED",
    "rds-storage-encrypted": "RDS_STORAGE_ENCRYPTED",
    "encrypted-volumes": "ENCRYPTED_VOLUMES",
    "cloudtrail-enabled": "CLOUD_TRAIL_ENABLED",
    "iam-password-policy": "IAM_PASSWORD_POLICY",
}


def get_config_client(region="us-east-1"):
    """Create AWS Config client."""
    return boto3.client("config", region_name=region)


def check_recorder_status(client):
    """Verify AWS Config recorder is running."""
    try:
        recorders = client.describe_configuration_recorder_status()
        for r in recorders.get("ConfigurationRecordersStatus", []):
            return {"name": r["name"], "recording": r["recording"],
                    "lastStatus": r.get("lastStatus", "Unknown")}
    except ClientError as e:
        return {"error": str(e)}
    return {"error": "No recorder found"}


def deploy_managed_rules(client, rules=None):
    """Deploy AWS-managed Config rules for CIS compliance."""
    if rules is None:
        rules = MANAGED_RULES
    deployed = []
    for rule_name, source_id in rules.items():
        try:
            client.put_config_rule(ConfigRule={
                "ConfigRuleName": rule_name,
                "Source": {"Owner": "AWS", "SourceIdentifier": source_id}
            })
            deployed.append({"rule": rule_name, "status": "deployed"})
        except ClientError as e:
            deployed.append({"rule": rule_name, "status": "error", "message": str(e)})
    return deployed


def get_compliance_summary(client):
    """Get compliance summary across all Config rules."""
    try:
        response = client.get_compliance_summary_by_config_rule()
        summary = response.get("ComplianceSummary", {})
        compliant = summary.get("CompliantResourceCount", {}).get("CappedCount", 0)
        non_compliant = summary.get("NonCompliantResourceCount", {}).get("CappedCount", 0)
        return {"compliant": compliant, "non_compliant": non_compliant,
                "total": compliant + non_compliant,
                "compliance_pct": round(compliant / max(compliant + non_compliant, 1) * 100, 1)}
    except ClientError as e:
        return {"error": str(e)}


def get_non_compliant_resources(client, rule_name):
    """List non-compliant resources for a specific rule."""
    try:
        response = client.get_compliance_details_by_config_rule(
            ConfigRuleName=rule_name, ComplianceTypes=["NON_COMPLIANT"], Limit=25)
        resources = []
        for result in response.get("EvaluationResults", []):
            qual = result.get("EvaluationResultIdentifier", {}).get("EvaluationResultQualifier", {})
            resources.append({
                "resource_type": qual.get("ResourceType"),
                "resource_id": qual.get("ResourceId"),
                "annotation": result.get("Annotation", ""),
                "timestamp": str(result.get("ResultRecordedTime", ""))
            })
        return resources
    except ClientError as e:
        return [{"error": str(e)}]


def configure_remediation(client, rule_name, ssm_document, params):
    """Set up auto-remediation for a Config rule."""
    try:
        client.put_remediation_configurations(RemediationConfigurations=[{
            "ConfigRuleName": rule_name,
            "TargetType": "SSM_DOCUMENT",
            "TargetId": ssm_document,
            "Parameters": params,
            "Automatic": True,
            "MaximumAutomaticAttempts": 3,
            "RetryAttemptSeconds": 60,
        }])
        return {"rule": rule_name, "remediation": ssm_document, "status": "configured"}
    except ClientError as e:
        return {"rule": rule_name, "status": "error", "message": str(e)}


def run_compliance_audit(region="us-east-1"):
    """Run a full compliance audit and generate report."""
    client = get_config_client(region)

    print(f"\n{'='*60}")
    print(f"  AWS CONFIG COMPLIANCE AUDIT")
    print(f"  Region: {region}")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    recorder = check_recorder_status(client)
    print(f"--- CONFIG RECORDER ---")
    print(f"  Status: {'RECORDING' if recorder.get('recording') else 'STOPPED'}")
    print(f"  Last Status: {recorder.get('lastStatus', 'N/A')}\n")

    summary = get_compliance_summary(client)
    print(f"--- COMPLIANCE SUMMARY ---")
    print(f"  Compliant:     {summary.get('compliant', 0)}")
    print(f"  Non-Compliant: {summary.get('non_compliant', 0)}")
    print(f"  Compliance:    {summary.get('compliance_pct', 0)}%\n")

    print(f"--- NON-COMPLIANT DETAILS ---")
    try:
        rules_resp = client.describe_config_rules()
        for rule in rules_resp.get("ConfigRules", []):
            name = rule["ConfigRuleName"]
            resources = get_non_compliant_resources(client, name)
            if resources and not resources[0].get("error"):
                print(f"  Rule: {name} ({len(resources)} non-compliant)")
                for r in resources[:3]:
                    print(f"    - {r['resource_type']}: {r['resource_id']}")
    except ClientError as e:
        print(f"  Error listing rules: {e}")

    print(f"\n{'='*60}\n")
    return {"recorder": recorder, "summary": summary}


def main():
    parser = argparse.ArgumentParser(description="AWS Config Compliance Agent")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--deploy-rules", action="store_true", help="Deploy managed Config rules")
    parser.add_argument("--audit", action="store_true", help="Run compliance audit")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    if args.deploy_rules:
        client = get_config_client(args.region)
        results = deploy_managed_rules(client)
        for r in results:
            print(f"  [{r['status']}] {r['rule']}")
    elif args.audit:
        report = run_compliance_audit(args.region)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"[+] Report saved to {args.output}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
