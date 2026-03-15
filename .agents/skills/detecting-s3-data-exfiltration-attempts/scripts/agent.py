#!/usr/bin/env python3
"""S3 data exfiltration detection agent using CloudTrail and GuardDuty."""

import json
import subprocess
import sys
from collections import Counter
from datetime import datetime, timedelta


def aws_cli(args):
    """Execute AWS CLI command and return parsed JSON."""
    cmd = ["aws"] + args + ["--output", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
        return {"error": result.stderr.strip()} if result.returncode != 0 else {}
    except Exception as e:
        return {"error": str(e)}


def get_guardduty_s3_findings():
    """Get GuardDuty findings for S3 exfiltration activity."""
    det = aws_cli(["guardduty", "list-detectors"])
    detector_id = det.get("DetectorIds", [None])[0]
    if not detector_id:
        return {"error": "No GuardDuty detector found"}

    s3_types = [
        "Exfiltration:S3/MaliciousIPCaller",
        "Exfiltration:S3/AnomalousBehavior",
        "UnauthorizedAccess:S3/MaliciousIPCaller.Custom",
        "UnauthorizedAccess:S3/TorIPCaller",
        "Discovery:S3/MaliciousIPCaller",
        "Discovery:S3/AnomalousBehavior",
        "Impact:S3/AnomalousBehavior.Delete",
        "Impact:S3/AnomalousBehavior.Permission",
        "Impact:S3/AnomalousBehavior.Write",
    ]
    criteria = {"Criterion": {"type": {"Eq": s3_types}, "service.archived": {"Eq": ["false"]}}}
    result = aws_cli([
        "guardduty", "list-findings",
        "--detector-id", detector_id,
        "--finding-criteria", json.dumps(criteria),
    ])
    finding_ids = result.get("FindingIds", [])
    if not finding_ids:
        return {"count": 0, "findings": []}

    details = aws_cli(["guardduty", "get-findings", "--detector-id", detector_id,
                        "--finding-ids"] + finding_ids[:25])
    parsed = []
    for f in details.get("Findings", []):
        s3 = f.get("Resource", {}).get("S3BucketDetails", [{}])
        bucket = s3[0] if s3 else {}
        parsed.append({
            "type": f.get("Type"),
            "severity": f.get("Severity"),
            "bucket": bucket.get("Name"),
            "region": f.get("Region"),
            "action": f.get("Service", {}).get("Action", {}),
        })
    return {"count": len(parsed), "findings": parsed}


def query_cloudtrail_s3_gets(bucket_name, hours=24):
    """Query CloudTrail for GetObject events on a specific bucket."""
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)
    result = aws_cli([
        "cloudtrail", "lookup-events",
        "--lookup-attributes", json.dumps([
            {"AttributeKey": "EventName", "AttributeValue": "GetObject"}
        ]),
        "--start-time", start_time.isoformat() + "Z",
        "--end-time", end_time.isoformat() + "Z",
        "--max-results", "50",
    ])
    events = []
    for e in result.get("Events", []):
        detail = json.loads(e.get("CloudTrailEvent", "{}"))
        req = detail.get("requestParameters", {})
        if bucket_name and req.get("bucketName") != bucket_name:
            continue
        events.append({
            "time": e.get("EventTime"),
            "user": e.get("Username"),
            "source_ip": detail.get("sourceIPAddress"),
            "bucket": req.get("bucketName"),
            "key": req.get("key", "")[:100],
            "user_agent": detail.get("userAgent", "")[:80],
        })
    return {"bucket": bucket_name, "get_events": events, "count": len(events)}


def detect_bulk_download_patterns(bucket_name, hours=24):
    """Detect anomalous bulk download patterns from S3."""
    trail = query_cloudtrail_s3_gets(bucket_name, hours)
    events = trail.get("get_events", [])

    by_user = Counter()
    by_ip = Counter()
    for e in events:
        by_user[e.get("user", "unknown")] += 1
        by_ip[e.get("source_ip", "unknown")] += 1

    anomalies = []
    for user, count in by_user.items():
        if count > 50:
            anomalies.append({
                "type": "BULK_DOWNLOAD",
                "severity": "HIGH",
                "user": user,
                "object_count": count,
                "period_hours": hours,
            })
    for ip, count in by_ip.items():
        if count > 100:
            anomalies.append({
                "type": "HIGH_VOLUME_SOURCE",
                "severity": "HIGH",
                "source_ip": ip,
                "object_count": count,
            })

    return {
        "bucket": bucket_name,
        "total_gets": len(events),
        "unique_users": len(by_user),
        "unique_ips": len(by_ip),
        "anomalies": anomalies,
        "top_users": by_user.most_common(10),
        "top_ips": by_ip.most_common(10),
    }


def check_bucket_policy(bucket_name):
    """Check S3 bucket policy for overly permissive access."""
    result = aws_cli(["s3api", "get-bucket-policy", "--bucket", bucket_name])
    if "error" in result:
        return result

    policy = json.loads(result.get("Policy", "{}")) if isinstance(result.get("Policy"), str) else result
    issues = []
    for stmt in policy.get("Statement", []):
        principal = stmt.get("Principal", "")
        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
            if stmt.get("Effect") == "Allow":
                issues.append({
                    "severity": "CRITICAL",
                    "finding": "Bucket allows public access",
                    "action": stmt.get("Action"),
                    "sid": stmt.get("Sid", ""),
                })

    return {"bucket": bucket_name, "policy_issues": issues, "issue_count": len(issues)}


def check_s3_access_logging(bucket_name):
    """Verify S3 server access logging is enabled."""
    result = aws_cli(["s3api", "get-bucket-logging", "--bucket", bucket_name])
    enabled = bool(result.get("LoggingEnabled"))
    return {
        "bucket": bucket_name,
        "logging_enabled": enabled,
        "target_bucket": result.get("LoggingEnabled", {}).get("TargetBucket") if enabled else None,
    }


def block_external_access(bucket_name):
    """Restrict S3 bucket to VPC endpoint access only."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyNonVPCAccess",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket_name}/*",
            "Condition": {
                "StringNotEquals": {"aws:sourceVpce": "vpce-REPLACE_WITH_ENDPOINT_ID"}
            },
        }],
    }
    return aws_cli([
        "s3api", "put-bucket-policy",
        "--bucket", bucket_name,
        "--policy", json.dumps(policy),
    ])


def generate_report(bucket_name=None):
    """Generate S3 exfiltration detection report."""
    report = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "guardduty_s3": get_guardduty_s3_findings(),
    }
    if bucket_name:
        report["bulk_download_analysis"] = detect_bulk_download_patterns(bucket_name)
        report["bucket_policy"] = check_bucket_policy(bucket_name)
        report["access_logging"] = check_s3_access_logging(bucket_name)
    return report


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "report"
    if action == "report":
        bucket = sys.argv[2] if len(sys.argv) > 2 else None
        print(json.dumps(generate_report(bucket), indent=2, default=str))
    elif action == "findings":
        print(json.dumps(get_guardduty_s3_findings(), indent=2, default=str))
    elif action == "gets" and len(sys.argv) > 2:
        hours = int(sys.argv[3]) if len(sys.argv) > 3 else 24
        print(json.dumps(query_cloudtrail_s3_gets(sys.argv[2], hours), indent=2, default=str))
    elif action == "bulk" and len(sys.argv) > 2:
        print(json.dumps(detect_bulk_download_patterns(sys.argv[2]), indent=2, default=str))
    elif action == "policy" and len(sys.argv) > 2:
        print(json.dumps(check_bucket_policy(sys.argv[2]), indent=2))
    else:
        print("Usage: agent.py [report [bucket]|findings|gets <bucket> [hours]|bulk <bucket>|policy <bucket>]")
