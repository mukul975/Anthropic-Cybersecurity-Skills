#!/usr/bin/env python3
"""
AWS GuardDuty Findings Management Script

Lists, analyzes, and exports GuardDuty findings for security operations.
"""

import boto3
import json
import sys
from datetime import datetime
from collections import Counter


def get_detector_id(session):
    """Get the GuardDuty detector ID for the current region."""
    client = session.client('guardduty')
    response = client.list_detectors()
    detectors = response.get('DetectorIds', [])
    if not detectors:
        print("[!] No GuardDuty detector found. Enable GuardDuty first.")
        return None
    return detectors[0]


def list_findings(session, severity_min=0, max_results=50):
    """List GuardDuty findings filtered by severity."""
    client = session.client('guardduty')
    detector_id = get_detector_id(session)
    if not detector_id:
        return []

    criteria = {}
    if severity_min > 0:
        criteria['severity'] = {'Gte': severity_min}

    response = client.list_findings(
        DetectorId=detector_id,
        FindingCriteria={'Criterion': criteria} if criteria else {},
        SortCriteria={'AttributeName': 'severity', 'OrderBy': 'DESC'},
        MaxResults=max_results
    )

    finding_ids = response.get('FindingIds', [])
    if not finding_ids:
        print("[+] No findings found")
        return []

    details = client.get_findings(
        DetectorId=detector_id,
        FindingIds=finding_ids
    )

    findings = details.get('Findings', [])
    print(f"[+] Retrieved {len(findings)} findings\n")

    for f in findings:
        sev = f['Severity']
        sev_label = 'HIGH' if sev >= 7 else 'MEDIUM' if sev >= 4 else 'LOW'
        print(f"  [{sev_label} {sev}] {f['Type']}")
        print(f"    Account: {f['AccountId']} | Region: {f['Region']}")
        print(f"    Description: {f.get('Description', 'N/A')[:100]}")
        print()

    return findings


def get_findings_statistics(session):
    """Get statistical summary of GuardDuty findings."""
    client = session.client('guardduty')
    detector_id = get_detector_id(session)
    if not detector_id:
        return

    response = client.get_findings_statistics(
        DetectorId=detector_id,
        FindingStatisticTypes=['COUNT_BY_SEVERITY']
    )

    stats = response.get('FindingStatistics', {})
    severity_counts = stats.get('CountBySeverity', {})

    print("[+] GuardDuty Findings Statistics:")
    for severity, count in sorted(severity_counts.items(), reverse=True):
        print(f"  Severity {severity}: {count} findings")


def analyze_findings(findings):
    """Analyze findings for patterns and top threats."""
    if not findings:
        return

    type_counter = Counter(f['Type'] for f in findings)
    severity_counter = Counter(
        'HIGH' if f['Severity'] >= 7 else 'MEDIUM' if f['Severity'] >= 4 else 'LOW'
        for f in findings
    )

    print("\n[+] Finding Type Distribution:")
    for finding_type, count in type_counter.most_common(10):
        print(f"  {count:3d} - {finding_type}")

    print("\n[+] Severity Distribution:")
    for level in ['HIGH', 'MEDIUM', 'LOW']:
        print(f"  {level}: {severity_counter.get(level, 0)}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="GuardDuty Findings Manager")
    parser.add_argument("--list", action="store_true", help="List findings")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    parser.add_argument("--severity", type=float, default=0, help="Minimum severity filter")
    parser.add_argument("--max-results", type=int, default=50)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--profile", type=str)
    args = parser.parse_args()

    kwargs = {"region_name": args.region}
    if args.profile:
        kwargs["profile_name"] = args.profile
    session = boto3.Session(**kwargs)

    if args.list:
        findings = list_findings(session, args.severity, args.max_results)
        analyze_findings(findings)
    if args.stats:
        get_findings_statistics(session)
