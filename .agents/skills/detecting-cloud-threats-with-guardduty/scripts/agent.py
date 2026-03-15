#!/usr/bin/env python3
"""Amazon GuardDuty threat detection and response automation agent."""

import json
import subprocess
import sys
from datetime import datetime


def aws_cli(args):
    """Execute AWS CLI command and return parsed JSON."""
    cmd = ["aws"] + args + ["--output", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return json.loads(result.stdout) if result.stdout.strip() else {}
        return {"error": result.stderr.strip()}
    except Exception as e:
        return {"error": str(e)}


def get_detector_id():
    """Retrieve the GuardDuty detector ID."""
    result = aws_cli(["guardduty", "list-detectors"])
    ids = result.get("DetectorIds", [])
    return ids[0] if ids else None


def enable_guardduty():
    """Enable GuardDuty with all protection plans."""
    result = aws_cli([
        "guardduty", "create-detector",
        "--enable",
        "--finding-publishing-frequency", "FIFTEEN_MINUTES",
        "--data-sources", json.dumps({
            "S3Logs": {"Enable": True},
            "Kubernetes": {"AuditLogs": {"Enable": True}},
            "MalwareProtection": {"ScanEc2InstanceWithFindings": {"EbsVolumes": True}},
        }),
    ])
    return result


def get_detector_status(detector_id=None):
    """Get GuardDuty detector configuration and status."""
    if not detector_id:
        detector_id = get_detector_id()
    if not detector_id:
        return {"error": "No detector found. Run enable_guardduty first."}
    return aws_cli(["guardduty", "get-detector", "--detector-id", detector_id])


def list_findings(detector_id=None, severity_min=4.0, max_results=50):
    """List active GuardDuty findings filtered by minimum severity."""
    if not detector_id:
        detector_id = get_detector_id()
    if not detector_id:
        return {"error": "No detector found"}

    criteria = {
        "Criterion": {
            "severity": {"Gte": int(severity_min)},
            "service.archived": {"Eq": ["false"]},
        }
    }
    result = aws_cli([
        "guardduty", "list-findings",
        "--detector-id", detector_id,
        "--finding-criteria", json.dumps(criteria),
        "--max-results", str(max_results),
        "--sort-criteria", json.dumps({"AttributeName": "severity", "OrderBy": "DESC"}),
    ])
    return result


def get_finding_details(detector_id, finding_ids):
    """Get detailed information about specific findings."""
    if isinstance(finding_ids, str):
        finding_ids = [finding_ids]
    result = aws_cli([
        "guardduty", "get-findings",
        "--detector-id", detector_id,
        "--finding-ids"] + finding_ids[:25]
    )
    findings = []
    for f in result.get("Findings", []):
        resource = f.get("Resource", {})
        service = f.get("Service", {})
        findings.append({
            "id": f.get("Id"),
            "type": f.get("Type"),
            "severity": f.get("Severity"),
            "title": f.get("Title"),
            "description": f.get("Description", "")[:200],
            "region": f.get("Region"),
            "account_id": f.get("AccountId"),
            "resource_type": resource.get("ResourceType"),
            "instance_id": resource.get("InstanceDetails", {}).get("InstanceId"),
            "action": service.get("Action", {}),
            "first_seen": service.get("EventFirstSeen"),
            "last_seen": service.get("EventLastSeen"),
            "count": service.get("Count"),
        })
    return findings


def archive_finding(detector_id, finding_ids):
    """Archive (suppress) GuardDuty findings."""
    if isinstance(finding_ids, str):
        finding_ids = [finding_ids]
    return aws_cli([
        "guardduty", "archive-findings",
        "--detector-id", detector_id,
        "--finding-ids"] + finding_ids
    )


def create_ip_threat_intel_set(detector_id, name, s3_uri):
    """Create a custom threat intelligence IP set."""
    return aws_cli([
        "guardduty", "create-threat-intel-set",
        "--detector-id", detector_id,
        "--name", name,
        "--format", "TXT",
        "--location", s3_uri,
        "--activate",
    ])


def create_suppression_filter(detector_id, name, criterion):
    """Create a suppression filter to auto-archive known benign findings."""
    return aws_cli([
        "guardduty", "create-filter",
        "--detector-id", detector_id,
        "--name", name,
        "--action", "ARCHIVE",
        "--finding-criteria", json.dumps({"Criterion": criterion}),
    ])


def generate_report(detector_id=None):
    """Generate a GuardDuty findings summary report."""
    if not detector_id:
        detector_id = get_detector_id()
    if not detector_id:
        return {"error": "No detector found"}

    findings_result = list_findings(detector_id, severity_min=1)
    finding_ids = findings_result.get("FindingIds", [])

    details = []
    if finding_ids:
        details = get_finding_details(detector_id, finding_ids[:25])

    severity_dist = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    type_counts = {}
    for f in details:
        sev = f.get("severity", 0)
        if sev >= 7:
            severity_dist["HIGH"] += 1
        elif sev >= 4:
            severity_dist["MEDIUM"] += 1
        else:
            severity_dist["LOW"] += 1
        ftype = f.get("type", "unknown")
        type_counts[ftype] = type_counts.get(ftype, 0) + 1

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "detector_id": detector_id,
        "total_active_findings": len(finding_ids),
        "severity_distribution": severity_dist,
        "finding_types": type_counts,
        "critical_findings": [f for f in details if f.get("severity", 0) >= 7],
    }


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "report"
    det = get_detector_id()
    if action == "report":
        print(json.dumps(generate_report(det), indent=2, default=str))
    elif action == "enable":
        print(json.dumps(enable_guardduty(), indent=2))
    elif action == "status":
        print(json.dumps(get_detector_status(det), indent=2))
    elif action == "findings":
        sev = float(sys.argv[2]) if len(sys.argv) > 2 else 4.0
        print(json.dumps(list_findings(det, sev), indent=2))
    elif action == "details" and len(sys.argv) > 2:
        print(json.dumps(get_finding_details(det, sys.argv[2:]), indent=2, default=str))
    elif action == "archive" and len(sys.argv) > 2:
        print(json.dumps(archive_finding(det, sys.argv[2:]), indent=2))
    else:
        print("Usage: agent.py [report|enable|status|findings [min_severity]|details <id>|archive <id>]")
