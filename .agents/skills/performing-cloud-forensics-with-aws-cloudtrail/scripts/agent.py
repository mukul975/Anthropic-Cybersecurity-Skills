#!/usr/bin/env python3
"""AWS CloudTrail Forensics Agent - investigates API activity for incident response using boto3."""

import json
import argparse
import logging
from collections import defaultdict
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import ClientError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

SUSPICIOUS_EVENTS = [
    "CreateUser", "CreateAccessKey", "AttachUserPolicy", "AttachRolePolicy",
    "PutUserPolicy", "CreateRole", "AssumeRole", "CreateLoginProfile",
    "UpdateLoginProfile", "CreateFunction20150331", "UpdateFunctionCode20150331v2",
    "AuthorizeSecurityGroupIngress", "RunInstances", "StopLogging", "DeleteTrail",
    "PutBucketPolicy", "PutBucketAcl", "GetSecretValue", "GetParametersByPath",
]

PERSISTENCE_EVENTS = [
    "CreateUser", "CreateAccessKey", "CreateRole", "CreateLoginProfile",
    "CreateFunction20150331", "CreateEventSourceMapping20150331",
]


def lookup_events(client, start_time, end_time, username=None, access_key_id=None, event_name=None):
    """Query CloudTrail using lookup_events with pagination."""
    kwargs = {
        "StartTime": start_time,
        "EndTime": end_time,
        "MaxResults": 50,
    }
    lookup_attrs = []
    if username:
        lookup_attrs.append({"AttributeKey": "Username", "AttributeValue": username})
    if access_key_id:
        lookup_attrs.append({"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id})
    if event_name:
        lookup_attrs.append({"AttributeKey": "EventName", "AttributeValue": event_name})
    if lookup_attrs:
        kwargs["LookupAttributes"] = lookup_attrs

    events = []
    paginator = client.get_paginator("lookup_events")
    for page in paginator.paginate(**kwargs):
        for event in page.get("Events", []):
            ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
            events.append({
                "event_time": str(event.get("EventTime", "")),
                "event_name": event.get("EventName", ""),
                "event_source": ct_event.get("eventSource", ""),
                "username": event.get("Username", ""),
                "source_ip": ct_event.get("sourceIPAddress", ""),
                "user_agent": ct_event.get("userAgent", ""),
                "access_key_id": ct_event.get("userIdentity", {}).get("accessKeyId", ""),
                "arn": ct_event.get("userIdentity", {}).get("arn", ""),
                "error_code": ct_event.get("errorCode", ""),
                "error_message": ct_event.get("errorMessage", ""),
                "request_params": ct_event.get("requestParameters", {}),
                "response_elements": ct_event.get("responseElements", {}),
                "aws_region": ct_event.get("awsRegion", ""),
            })
    logger.info("Retrieved %d CloudTrail events", len(events))
    return events


def detect_suspicious_activity(events):
    """Flag events matching suspicious API calls."""
    suspicious = []
    for event in events:
        if event["event_name"] in SUSPICIOUS_EVENTS:
            event["indicator"] = "suspicious_api_call"
            event["severity"] = "high" if event["event_name"] in PERSISTENCE_EVENTS else "medium"
            suspicious.append(event)
        if event["error_code"] == "AccessDenied":
            event["indicator"] = "access_denied_enumeration"
            event["severity"] = "medium"
            suspicious.append(event)
    return suspicious


def detect_persistence(events):
    """Identify persistence mechanisms created by attacker."""
    persistence = []
    for event in events:
        if event["event_name"] in PERSISTENCE_EVENTS and not event["error_code"]:
            details = {}
            resp = event.get("response_elements", {})
            if event["event_name"] == "CreateUser":
                details["created_user"] = resp.get("user", {}).get("userName", "")
            elif event["event_name"] == "CreateAccessKey":
                details["access_key_id"] = resp.get("accessKey", {}).get("accessKeyId", "")
                details["for_user"] = resp.get("accessKey", {}).get("userName", "")
            elif event["event_name"] == "CreateRole":
                details["role_name"] = resp.get("role", {}).get("roleName", "")
            persistence.append({**event, "persistence_details": details})
    return persistence


def analyze_source_ips(events):
    """Analyze source IP distribution for anomalies."""
    ip_activity = defaultdict(lambda: {"count": 0, "events": set(), "users": set()})
    for event in events:
        ip = event["source_ip"]
        if ip:
            ip_activity[ip]["count"] += 1
            ip_activity[ip]["events"].add(event["event_name"])
            ip_activity[ip]["users"].add(event["username"])
    result = {}
    for ip, data in ip_activity.items():
        result[ip] = {
            "request_count": data["count"],
            "unique_events": len(data["events"]),
            "unique_users": len(data["users"]),
            "event_types": list(data["events"])[:10],
        }
    return dict(sorted(result.items(), key=lambda x: x[1]["request_count"], reverse=True))


def analyze_user_agents(events):
    """Analyze user agents for tool identification."""
    ua_counts = defaultdict(int)
    for event in events:
        ua = event.get("user_agent", "unknown")
        ua_counts[ua] += 1
    suspicious_uas = {}
    for ua, count in ua_counts.items():
        if any(tool in ua.lower() for tool in ["pacu", "prowler", "scoutsuite", "boto", "python", "curl", "custom"]):
            suspicious_uas[ua] = count
    return {
        "all_user_agents": dict(sorted(ua_counts.items(), key=lambda x: x[1], reverse=True)[:15]),
        "suspicious_user_agents": suspicious_uas,
    }


def build_timeline(events):
    """Build chronological attack timeline."""
    return sorted(
        [{"time": e["event_time"], "event": e["event_name"], "user": e["username"],
          "source_ip": e["source_ip"], "error": e.get("error_code", "")}
         for e in events],
        key=lambda x: x["time"]
    )


def generate_report(events, suspicious, persistence, ip_analysis, ua_analysis):
    """Generate forensic investigation report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "investigation_type": "AWS CloudTrail Forensic Analysis",
        "total_events_analyzed": len(events),
        "suspicious_events": len(suspicious),
        "persistence_mechanisms_found": len(persistence),
        "unique_source_ips": len(ip_analysis),
        "source_ip_analysis": dict(list(ip_analysis.items())[:10]),
        "user_agent_analysis": ua_analysis,
        "persistence_details": persistence[:10],
        "top_suspicious_events": suspicious[:20],
        "timeline": build_timeline(events)[:50],
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="AWS CloudTrail Forensics Agent")
    parser.add_argument("--hours-back", type=int, default=24, help="Hours to look back (default: 24)")
    parser.add_argument("--username", help="Filter by IAM username")
    parser.add_argument("--access-key-id", help="Filter by access key ID")
    parser.add_argument("--event-name", help="Filter by specific event name")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--output", default="cloudtrail_forensics_report.json")
    args = parser.parse_args()

    if not HAS_BOTO3:
        logger.error("boto3 is required: pip install boto3")
        return

    session_kwargs = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    session = boto3.Session(**session_kwargs)
    client = session.client("cloudtrail", region_name=args.region)

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=args.hours_back)
    logger.info("Querying CloudTrail: %s to %s", start_time.isoformat(), end_time.isoformat())

    events = lookup_events(client, start_time, end_time, args.username, args.access_key_id, args.event_name)
    suspicious = detect_suspicious_activity(events)
    persistence = detect_persistence(events)
    ip_analysis = analyze_source_ips(events)
    ua_analysis = analyze_user_agents(events)

    report = generate_report(events, suspicious, persistence, ip_analysis, ua_analysis)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Forensics: %d events, %d suspicious, %d persistence mechanisms",
                len(events), len(suspicious), len(persistence))
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
