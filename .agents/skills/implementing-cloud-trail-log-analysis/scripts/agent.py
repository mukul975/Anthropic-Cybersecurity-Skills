#!/usr/bin/env python3
"""CloudTrail log analysis agent for security monitoring and threat detection."""

import json
import sys
import argparse
from datetime import datetime, timedelta
from collections import Counter

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("Install boto3: pip install boto3")
    sys.exit(1)


SUSPICIOUS_EVENTS = {
    "ConsoleLogin": "Potential unauthorized console access",
    "StopLogging": "CloudTrail logging disabled - cover tracks",
    "DeleteTrail": "CloudTrail trail deleted - evidence destruction",
    "CreateUser": "New IAM user created - possible persistence",
    "CreateAccessKey": "New access key - potential credential theft",
    "AttachUserPolicy": "Policy attached to user - privilege escalation",
    "PutBucketPolicy": "S3 bucket policy changed - data exposure risk",
    "AuthorizeSecurityGroupIngress": "Security group opened - lateral movement",
    "RunInstances": "EC2 instances launched - cryptomining or C2",
    "CreateRole": "New IAM role created - privilege escalation",
    "AssumeRole": "Role assumed - potential lateral movement",
    "PutUserPolicy": "Inline policy added to user",
    "DeleteBucketEncryption": "Bucket encryption removed",
    "DisableKey": "KMS key disabled - ransomware indicator",
    "ModifyInstanceAttribute": "Instance attribute changed",
}


def get_cloudtrail_client(region="us-east-1"):
    """Create CloudTrail client."""
    return boto3.client("cloudtrail", region_name=region)


def lookup_events(client, event_name=None, hours=24, max_results=50):
    """Look up CloudTrail events with optional filtering."""
    start_time = datetime.utcnow() - timedelta(hours=hours)
    kwargs = {"StartTime": start_time, "MaxResults": max_results,
              "LookupAttributes": []}
    if event_name:
        kwargs["LookupAttributes"] = [{"AttributeKey": "EventName", "AttributeValue": event_name}]
    try:
        resp = client.lookup_events(**kwargs)
        events = []
        for e in resp.get("Events", []):
            detail = json.loads(e.get("CloudTrailEvent", "{}"))
            events.append({
                "event_name": e.get("EventName"),
                "event_time": str(e.get("EventTime")),
                "username": e.get("Username", "unknown"),
                "source_ip": detail.get("sourceIPAddress", "unknown"),
                "user_agent": detail.get("userAgent", "unknown"),
                "region": detail.get("awsRegion", "unknown"),
                "error_code": detail.get("errorCode"),
                "error_message": detail.get("errorMessage"),
                "resources": [r.get("ResourceName", "") for r in e.get("Resources", [])],
            })
        return events
    except ClientError as e:
        return [{"error": str(e)}]


def detect_suspicious_activity(client, hours=24):
    """Scan CloudTrail for suspicious API calls."""
    detections = []
    for event_name, description in SUSPICIOUS_EVENTS.items():
        events = lookup_events(client, event_name=event_name, hours=hours)
        for e in events:
            if e.get("error"):
                continue
            severity = "CRITICAL" if event_name in ["StopLogging", "DeleteTrail", "DisableKey"] \
                else "HIGH" if event_name in ["CreateUser", "CreateAccessKey", "AttachUserPolicy"] \
                else "MEDIUM"
            detections.append({
                "event": event_name, "description": description,
                "severity": severity, "user": e["username"],
                "source_ip": e["source_ip"], "time": e["event_time"],
                "resources": e["resources"],
            })
    return sorted(detections, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["severity"], 3))


def detect_failed_auth(client, hours=24):
    """Detect failed authentication attempts."""
    events = lookup_events(client, event_name="ConsoleLogin", hours=hours, max_results=100)
    failed = [e for e in events if e.get("error_code")]
    by_ip = Counter(e["source_ip"] for e in failed)
    by_user = Counter(e["username"] for e in failed)
    return {"total_failed": len(failed), "by_source_ip": dict(by_ip.most_common(10)),
            "by_username": dict(by_user.most_common(10))}


def detect_unauthorized_regions(client, authorized_regions, hours=24):
    """Detect API calls from unauthorized AWS regions."""
    events = lookup_events(client, hours=hours, max_results=100)
    unauthorized = [e for e in events if e.get("region") and
                    e["region"] not in authorized_regions and not e.get("error")]
    return unauthorized


def analyze_user_activity(client, username, hours=24):
    """Analyze all activity for a specific user."""
    kwargs = {"StartTime": datetime.utcnow() - timedelta(hours=hours),
              "MaxResults": 50,
              "LookupAttributes": [{"AttributeKey": "Username", "AttributeValue": username}]}
    try:
        resp = client.lookup_events(**kwargs)
        actions = Counter()
        timeline = []
        for e in resp.get("Events", []):
            actions[e.get("EventName")] += 1
            timeline.append({"event": e.get("EventName"), "time": str(e.get("EventTime"))})
        return {"user": username, "total_events": len(timeline),
                "actions": dict(actions.most_common(20)), "timeline": timeline[:20]}
    except ClientError as e:
        return {"error": str(e)}


def run_cloudtrail_analysis(region="us-east-1", hours=24):
    """Run comprehensive CloudTrail security analysis."""
    client = get_cloudtrail_client(region)

    print(f"\n{'='*60}")
    print(f"  CLOUDTRAIL SECURITY ANALYSIS")
    print(f"  Region: {region} | Lookback: {hours}h")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    detections = detect_suspicious_activity(client, hours)
    print(f"--- SUSPICIOUS ACTIVITY ({len(detections)} detections) ---")
    for d in detections[:15]:
        print(f"  [{d['severity']}] {d['event']}: {d['description']}")
        print(f"    User: {d['user']} | IP: {d['source_ip']} | Time: {d['time']}")

    auth = detect_failed_auth(client, hours)
    print(f"\n--- FAILED AUTHENTICATION ---")
    print(f"  Total failures: {auth['total_failed']}")
    print(f"  Top IPs: {auth['by_source_ip']}")
    print(f"  Top Users: {auth['by_username']}")

    print(f"\n{'='*60}\n")
    return {"detections": detections, "auth_failures": auth}


def main():
    parser = argparse.ArgumentParser(description="CloudTrail Log Analysis Agent")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--hours", type=int, default=24, help="Lookback period in hours")
    parser.add_argument("--analyze", action="store_true", help="Run full analysis")
    parser.add_argument("--user", help="Analyze specific user activity")
    parser.add_argument("--output", help="Save report to JSON")
    args = parser.parse_args()

    if args.user:
        client = get_cloudtrail_client(args.region)
        result = analyze_user_activity(client, args.user, args.hours)
        print(json.dumps(result, indent=2, default=str))
    elif args.analyze:
        report = run_cloudtrail_analysis(args.region, args.hours)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"[+] Report saved to {args.output}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
