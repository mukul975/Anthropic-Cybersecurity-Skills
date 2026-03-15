#!/usr/bin/env python3
"""Cloud DLP agent for sensitive data discovery using Google Cloud DLP and AWS Macie."""

import json
import sys
import argparse
from datetime import datetime

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None

try:
    from google.cloud import dlp_v2
except ImportError:
    dlp_v2 = None


INFO_TYPES_PII = [
    "PERSON_NAME", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SOCIAL_SECURITY_NUMBER",
    "CREDIT_CARD_NUMBER", "US_DRIVERS_LICENSE_NUMBER", "DATE_OF_BIRTH",
    "STREET_ADDRESS", "IP_ADDRESS", "PASSPORT",
]

INFO_TYPES_FINANCIAL = [
    "CREDIT_CARD_NUMBER", "IBAN_CODE", "SWIFT_CODE",
    "US_BANK_ROUTING_MICR", "US_EMPLOYER_IDENTIFICATION_NUMBER",
]

INFO_TYPES_HEALTH = [
    "US_HEALTHCARE_NPI", "US_DEA_NUMBER", "MEDICAL_RECORD_NUMBER",
]


def scan_text_with_gcp_dlp(project_id, text, info_types=None):
    """Scan text content for sensitive data using Google Cloud DLP."""
    if dlp_v2 is None:
        print("[!] Install google-cloud-dlp: pip install google-cloud-dlp")
        return None
    client = dlp_v2.DlpServiceClient()
    parent = f"projects/{project_id}"
    if info_types is None:
        info_types = INFO_TYPES_PII
    inspect_config = {
        "info_types": [{"name": it} for it in info_types],
        "min_likelihood": dlp_v2.Likelihood.LIKELY,
        "include_quote": True,
        "limits": {"max_findings_per_request": 50},
    }
    item = {"value": text}
    response = client.inspect_content(
        request={"parent": parent, "inspect_config": inspect_config, "item": item})
    findings = []
    for f in response.result.findings:
        findings.append({
            "info_type": f.info_type.name,
            "likelihood": dlp_v2.Likelihood(f.likelihood).name,
            "quote": f.quote[:50] + "..." if len(f.quote) > 50 else f.quote,
            "location": {"start": f.location.byte_range.start, "end": f.location.byte_range.end},
        })
    return findings


def deidentify_text_with_gcp(project_id, text, info_types=None):
    """De-identify sensitive data in text using masking."""
    if dlp_v2 is None:
        return None
    client = dlp_v2.DlpServiceClient()
    parent = f"projects/{project_id}"
    if info_types is None:
        info_types = INFO_TYPES_PII
    deidentify_config = {
        "info_type_transformations": {
            "transformations": [{
                "primitive_transformation": {
                    "character_mask_config": {"masking_character": "*", "number_to_mask": 0}
                },
                "info_types": [{"name": it} for it in info_types],
            }]
        }
    }
    inspect_config = {"info_types": [{"name": it} for it in info_types]}
    item = {"value": text}
    response = client.deidentify_content(
        request={"parent": parent, "deidentify_config": deidentify_config,
                 "inspect_config": inspect_config, "item": item})
    return response.item.value


def enable_macie(region="us-east-1"):
    """Enable Amazon Macie for S3 sensitive data discovery."""
    if boto3 is None:
        print("[!] Install boto3: pip install boto3")
        return None
    client = boto3.client("macie2", region_name=region)
    try:
        client.enable_macie(status="ENABLED", findingPublishingFrequency="FIFTEEN_MINUTES")
        return {"status": "enabled"}
    except ClientError as e:
        if "already enabled" in str(e).lower():
            return {"status": "already_enabled"}
        return {"error": str(e)}


def create_macie_classification_job(region, bucket_names, job_name):
    """Create a Macie classification job to scan S3 buckets."""
    if boto3 is None:
        return None
    client = boto3.client("macie2", region_name=region)
    try:
        resp = client.create_classification_job(
            jobType="ONE_TIME", name=job_name,
            s3JobDefinition={
                "bucketDefinitions": [{"accountId": boto3.client("sts").get_caller_identity()["Account"],
                                       "buckets": bucket_names}]
            },
            description=f"DLP scan for sensitive data in {', '.join(bucket_names)}")
        return {"job_id": resp["jobId"], "status": "created"}
    except ClientError as e:
        return {"error": str(e)}


def get_macie_findings(region="us-east-1", max_results=50):
    """Retrieve Macie findings for sensitive data discoveries."""
    if boto3 is None:
        return []
    client = boto3.client("macie2", region_name=region)
    try:
        resp = client.list_findings(
            sortCriteria={"attributeName": "severity.score", "orderBy": "DESC"},
            maxResults=max_results)
        finding_ids = resp.get("findingIds", [])
        if not finding_ids:
            return []
        details = client.get_findings(findingIds=finding_ids)
        return [{"id": f["id"], "type": f["type"], "severity": f["severity"]["score"],
                 "title": f["title"], "bucket": f.get("resourcesAffected", {}).get(
                     "s3Bucket", {}).get("name", ""),
                 "count": f.get("count", 1)}
                for f in details.get("findings", [])]
    except ClientError as e:
        return [{"error": str(e)}]


def run_dlp_report(project_id=None, region="us-east-1"):
    """Generate a DLP discovery report."""
    print(f"\n{'='*60}")
    print(f"  CLOUD DLP DATA PROTECTION REPORT")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    if boto3:
        print(f"--- AWS MACIE STATUS ---")
        macie_status = enable_macie(region)
        print(f"  Macie: {macie_status}")
        findings = get_macie_findings(region)
        print(f"  Findings: {len(findings)}")
        for f in findings[:5]:
            print(f"  [{f.get('severity', 'N/A')}] {f.get('title', 'N/A')} - {f.get('bucket', 'N/A')}")

    if dlp_v2 and project_id:
        print(f"\n--- GCP DLP SCAN ---")
        sample = "Contact John Doe at john@example.com, SSN 123-45-6789, CC 4111-1111-1111-1111"
        findings = scan_text_with_gcp_dlp(project_id, sample)
        if findings:
            for f in findings:
                print(f"  [{f['likelihood']}] {f['info_type']}: {f['quote']}")

    print(f"\n{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(description="Cloud DLP Data Protection Agent")
    parser.add_argument("--gcp-project", help="GCP project ID for DLP API")
    parser.add_argument("--aws-region", default="us-east-1", help="AWS region for Macie")
    parser.add_argument("--scan-text", help="Text to scan for sensitive data")
    parser.add_argument("--scan-buckets", nargs="+", help="S3 bucket names to scan with Macie")
    parser.add_argument("--report", action="store_true", help="Generate DLP report")
    parser.add_argument("--output", help="Save report to JSON")
    args = parser.parse_args()

    if args.scan_text and args.gcp_project:
        findings = scan_text_with_gcp_dlp(args.gcp_project, args.scan_text)
        print(json.dumps(findings, indent=2))
    elif args.scan_buckets:
        result = create_macie_classification_job(args.aws_region, args.scan_buckets, "dlp-agent-scan")
        print(json.dumps(result, indent=2))
    elif args.report:
        run_dlp_report(args.gcp_project, args.aws_region)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
