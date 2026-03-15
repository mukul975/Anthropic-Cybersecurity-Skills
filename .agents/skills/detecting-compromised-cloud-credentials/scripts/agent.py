#!/usr/bin/env python3
"""Compromised cloud credential detection agent using AWS CloudTrail and GuardDuty."""

import json
import subprocess
import sys
from datetime import datetime, timedelta


def aws_cli(args):
    """Execute AWS CLI command and return JSON output."""
    cmd = ["aws"] + args + ["--output", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
        return {"error": result.stderr.strip()} if result.returncode != 0 else {}
    except Exception as e:
        return {"error": str(e)}


def get_guardduty_credential_findings():
    """Get GuardDuty findings related to credential compromise."""
    det_result = aws_cli(["guardduty", "list-detectors"])
    detector_id = det_result.get("DetectorIds", [None])[0]
    if not detector_id:
        return {"error": "No GuardDuty detector found"}

    credential_types = [
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
        "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
        "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
        "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
        "Recon:IAMUser/MaliciousIPCaller.Custom",
        "Discovery:IAMUser/AnomalousBehavior",
        "InitialAccess:IAMUser/AnomalousBehavior",
        "Persistence:IAMUser/AnomalousBehavior",
    ]
    criteria = {"Criterion": {"type": {"Eq": credential_types}, "service.archived": {"Eq": ["false"]}}}
    findings_result = aws_cli([
        "guardduty", "list-findings",
        "--detector-id", detector_id,
        "--finding-criteria", json.dumps(criteria),
    ])
    finding_ids = findings_result.get("FindingIds", [])
    if not finding_ids:
        return {"findings": [], "count": 0}

    details = aws_cli(["guardduty", "get-findings", "--detector-id", detector_id, "--finding-ids"] + finding_ids[:25])
    parsed = []
    for f in details.get("Findings", []):
        parsed.append({
            "type": f.get("Type"),
            "severity": f.get("Severity"),
            "title": f.get("Title"),
            "account": f.get("AccountId"),
            "region": f.get("Region"),
            "resource": f.get("Resource", {}).get("AccessKeyDetails", {}),
            "action": f.get("Service", {}).get("Action", {}),
        })
    return {"count": len(parsed), "findings": parsed}


def query_cloudtrail_for_key(access_key_id, hours=24):
    """Query CloudTrail for all API calls made with a specific access key."""
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)
    result = aws_cli([
        "cloudtrail", "lookup-events",
        "--lookup-attributes", json.dumps([{"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id}]),
        "--start-time", start_time.isoformat() + "Z",
        "--end-time", end_time.isoformat() + "Z",
        "--max-results", "50",
    ])
    events = []
    for e in result.get("Events", []):
        detail = json.loads(e.get("CloudTrailEvent", "{}"))
        events.append({
            "time": e.get("EventTime"),
            "event_name": e.get("EventName"),
            "source_ip": detail.get("sourceIPAddress"),
            "user_agent": detail.get("userAgent", "")[:100],
            "region": detail.get("awsRegion"),
            "resources": e.get("Resources", []),
        })
    return {"access_key": access_key_id, "events": events, "total": len(events)}


def detect_anomalous_api_calls(access_key_id, hours=24):
    """Detect anomalous API patterns from a potentially compromised key."""
    trail = query_cloudtrail_for_key(access_key_id, hours)
    events = trail.get("events", [])

    regions = set()
    ips = set()
    api_calls = {}
    recon_apis = ["ListBuckets", "DescribeInstances", "ListUsers", "GetCallerIdentity",
                  "ListRoles", "ListAccessKeys", "DescribeRegions", "ListFunctions"]
    recon_count = 0

    for e in events:
        if e.get("region"):
            regions.add(e["region"])
        if e.get("source_ip"):
            ips.add(e["source_ip"])
        name = e.get("event_name", "")
        api_calls[name] = api_calls.get(name, 0) + 1
        if name in recon_apis:
            recon_count += 1

    anomaly_score = 0
    indicators = []
    if len(regions) > 3:
        anomaly_score += 30
        indicators.append(f"Multi-region activity: {len(regions)} regions")
    if len(ips) > 3:
        anomaly_score += 25
        indicators.append(f"Multiple source IPs: {len(ips)}")
    if recon_count > 5:
        anomaly_score += 25
        indicators.append(f"Reconnaissance APIs: {recon_count} calls")
    if any(api in api_calls for api in ["CreateUser", "CreateAccessKey", "AttachUserPolicy"]):
        anomaly_score += 40
        indicators.append("Persistence API calls detected")

    return {
        "access_key": access_key_id,
        "anomaly_score": min(100, anomaly_score),
        "indicators": indicators,
        "unique_regions": list(regions),
        "unique_ips": list(ips),
        "top_apis": sorted(api_calls.items(), key=lambda x: x[1], reverse=True)[:15],
    }


def revoke_iam_sessions(username):
    """Revoke all active sessions for an IAM user by adding inline deny policy."""
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "DateLessThan": {"aws:TokenIssueTime": datetime.utcnow().isoformat() + "Z"}
            },
        }],
    })
    return aws_cli([
        "iam", "put-user-policy",
        "--user-name", username,
        "--policy-name", "RevokeOldSessions",
        "--policy-document", policy,
    ])


def deactivate_access_key(access_key_id, username):
    """Deactivate a compromised access key."""
    return aws_cli([
        "iam", "update-access-key",
        "--access-key-id", access_key_id,
        "--user-name", username,
        "--status", "Inactive",
    ])


def generate_report():
    """Generate a credential compromise detection report."""
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "guardduty_findings": get_guardduty_credential_findings(),
    }


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "report"
    if action == "report":
        print(json.dumps(generate_report(), indent=2, default=str))
    elif action == "findings":
        print(json.dumps(get_guardduty_credential_findings(), indent=2, default=str))
    elif action == "trail" and len(sys.argv) > 2:
        hours = int(sys.argv[3]) if len(sys.argv) > 3 else 24
        print(json.dumps(query_cloudtrail_for_key(sys.argv[2], hours), indent=2, default=str))
    elif action == "analyze" and len(sys.argv) > 2:
        print(json.dumps(detect_anomalous_api_calls(sys.argv[2]), indent=2, default=str))
    elif action == "deactivate" and len(sys.argv) > 3:
        print(json.dumps(deactivate_access_key(sys.argv[2], sys.argv[3]), indent=2))
    elif action == "revoke" and len(sys.argv) > 2:
        print(json.dumps(revoke_iam_sessions(sys.argv[2]), indent=2))
    else:
        print("Usage: agent.py [report|findings|trail <key_id> [hours]|analyze <key_id>|deactivate <key_id> <user>|revoke <user>]")
