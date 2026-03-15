#!/usr/bin/env python3
"""AWS GuardDuty findings automation and detection agent."""

import json
import sys
import argparse
from datetime import datetime

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("Install: pip install boto3")
    sys.exit(1)


def get_guardduty_detector(session):
    """Get the active GuardDuty detector ID."""
    gd = session.client("guardduty")
    detectors = gd.list_detectors()["DetectorIds"]
    if not detectors:
        return None
    return detectors[0]


def list_findings(session, detector_id, severity_min=4.0, max_results=50):
    """List GuardDuty findings filtered by severity."""
    gd = session.client("guardduty")
    criteria = {
        "Criterion": {
            "severity": {"Gte": severity_min},
            "service.archived": {"Eq": ["false"]},
        }
    }
    finding_ids = gd.list_findings(
        DetectorId=detector_id,
        FindingCriteria=criteria,
        SortCriteria={"AttributeName": "severity", "OrderBy": "DESC"},
        MaxResults=max_results,
    )["FindingIds"]

    if not finding_ids:
        return []

    details = gd.get_findings(
        DetectorId=detector_id, FindingIds=finding_ids
    )["Findings"]

    results = []
    for f in details:
        results.append({
            "id": f.get("Id", ""),
            "type": f.get("Type", ""),
            "severity": f.get("Severity", 0),
            "title": f.get("Title", ""),
            "description": f.get("Description", "")[:200],
            "resource_type": f.get("Resource", {}).get("ResourceType", ""),
            "region": f.get("Region", ""),
            "first_seen": f.get("Service", {}).get("EventFirstSeen", ""),
            "last_seen": f.get("Service", {}).get("EventLastSeen", ""),
            "count": f.get("Service", {}).get("Count", 0),
            "action_type": f.get("Service", {}).get("Action", {}).get("ActionType", ""),
        })
    return results


def get_finding_statistics(session, detector_id):
    """Get finding count grouped by type and severity."""
    gd = session.client("guardduty")
    stats = gd.get_findings_statistics(
        DetectorId=detector_id,
        FindingStatisticTypes=["COUNT_BY_SEVERITY"],
    )
    return stats.get("FindingStatistics", {})


def check_detector_configuration(session, detector_id):
    """Audit GuardDuty detector configuration for coverage gaps."""
    gd = session.client("guardduty")
    findings = []

    detector = gd.get_detector(DetectorId=detector_id)
    status = detector.get("Status", "")
    if status != "ENABLED":
        findings.append({
            "check": "Detector status",
            "status": status,
            "severity": "CRITICAL",
            "issue": "GuardDuty detector is not enabled",
        })

    features = detector.get("Features", [])
    expected_features = {
        "S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "EBS_MALWARE_PROTECTION",
        "RDS_LOGIN_EVENTS", "LAMBDA_NETWORK_LOGS", "RUNTIME_MONITORING",
    }
    enabled_features = set()
    for feat in features:
        if feat.get("Status") == "ENABLED":
            enabled_features.add(feat.get("Name", ""))

    missing = expected_features - enabled_features
    for m in missing:
        findings.append({
            "check": f"Feature: {m}",
            "status": "DISABLED",
            "severity": "HIGH",
            "issue": f"GuardDuty feature {m} not enabled — reduced detection coverage",
        })

    return findings


def check_member_accounts(session, detector_id):
    """Check GuardDuty member account enrollment in multi-account setup."""
    gd = session.client("guardduty")
    members = gd.list_members(
        DetectorId=detector_id, OnlyAssociated="true"
    ).get("Members", [])

    results = []
    for m in members:
        status = m.get("RelationshipStatus", "")
        results.append({
            "account_id": m.get("AccountId", ""),
            "email": m.get("Email", ""),
            "status": status,
            "detector_id": m.get("DetectorId", ""),
        })
        if status != "Enabled":
            results[-1]["finding"] = f"Member account not fully enabled: {status}"
            results[-1]["severity"] = "HIGH"
    return results


def auto_archive_low_severity(session, detector_id, threshold=2.0):
    """Auto-archive findings below severity threshold."""
    gd = session.client("guardduty")
    criteria = {
        "Criterion": {
            "severity": {"Lt": threshold},
            "service.archived": {"Eq": ["false"]},
        }
    }
    finding_ids = gd.list_findings(
        DetectorId=detector_id,
        FindingCriteria=criteria,
        MaxResults=100,
    )["FindingIds"]

    if finding_ids:
        gd.archive_findings(DetectorId=detector_id, FindingIds=finding_ids)
    return {"archived_count": len(finding_ids)}


def run_audit(args):
    """Execute GuardDuty findings automation audit."""
    print(f"\n{'='*60}")
    print(f"  AWS GUARDDUTY FINDINGS AUTOMATION")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    report = {}

    detector_id = get_guardduty_detector(session)
    if not detector_id:
        print("ERROR: No GuardDuty detector found")
        return {"error": "No detector found"}

    report["detector_id"] = detector_id
    print(f"Detector ID: {detector_id}\n")

    config_findings = check_detector_configuration(session, detector_id)
    report["configuration_findings"] = config_findings
    print(f"--- CONFIGURATION AUDIT ({len(config_findings)} findings) ---")
    for f in config_findings:
        print(f"  [{f['severity']}] {f['check']}: {f['issue']}")

    findings = list_findings(session, detector_id, args.min_severity)
    report["active_findings"] = len(findings)
    print(f"\n--- ACTIVE FINDINGS ({len(findings)}, severity >= {args.min_severity}) ---")
    for f in findings[:15]:
        print(f"  [{f['severity']:.1f}] {f['type']}")
        print(f"         {f['title'][:80]}")

    members = check_member_accounts(session, detector_id)
    report["member_accounts"] = members
    print(f"\n--- MEMBER ACCOUNTS ({len(members)}) ---")
    for m in members:
        status_icon = "OK" if m["status"] == "Enabled" else "WARN"
        print(f"  [{status_icon}] {m['account_id']}: {m['status']}")

    return report


def main():
    parser = argparse.ArgumentParser(description="GuardDuty Findings Automation Agent")
    parser.add_argument("--profile", default=None, help="AWS profile name")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--min-severity", type=float, default=4.0,
                        help="Minimum severity threshold (default: 4.0)")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
