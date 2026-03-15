#!/usr/bin/env python3
"""Agent for detecting anomalies in AWS CloudTrail logs.

Queries CloudTrail events via boto3, builds behavioral baselines,
and detects unusual API patterns indicating credential compromise,
privilege escalation, or unauthorized access.
"""

import argparse
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

try:
    import boto3
except ImportError:
    boto3 = None

SENSITIVE_EVENTS = {
    "CreateUser", "CreateAccessKey", "AttachUserPolicy", "AttachRolePolicy",
    "PutUserPolicy", "PutRolePolicy", "CreateRole", "AssumeRole",
    "ConsoleLogin", "PutBucketPolicy", "PutBucketAcl",
    "CreateKeyPair", "RunInstances", "StopLogging", "DeleteTrail",
    "DisableKey", "ScheduleKeyDeletion", "CreateGrante",
    "AuthorizeSecurityGroupIngress", "ModifyInstanceAttribute",
}

ERROR_INDICATORS = {"AccessDenied", "UnauthorizedAccess", "Client.UnauthorizedAccess"}


class CloudTrailAnomalyDetector:
    """Detects anomalies in AWS CloudTrail API activity."""

    def __init__(self, profile=None, region=None, lookback_hours=24,
                 output_dir="./cloudtrail_anomalies"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.lookback_hours = lookback_hours
        self.findings = []
        self.client = None
        if boto3:
            session = boto3.Session(profile_name=profile, region_name=region or "us-east-1")
            self.client = session.client("cloudtrail")

    def fetch_events(self, max_results=1000):
        """Fetch CloudTrail events using lookup_events with pagination."""
        if not self.client:
            return []
        start_time = datetime.utcnow() - timedelta(hours=self.lookback_hours)
        events = []
        paginator = self.client.get_paginator("lookup_events")
        page_iter = paginator.paginate(
            StartTime=start_time,
            EndTime=datetime.utcnow(),
            PaginationConfig={"MaxItems": max_results, "PageSize": 50},
        )
        for page in page_iter:
            for event in page.get("Events", []):
                ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
                events.append({
                    "event_name": event.get("EventName", ""),
                    "event_source": event.get("EventSource", ""),
                    "event_time": event.get("EventTime", "").isoformat()
                        if hasattr(event.get("EventTime", ""), "isoformat")
                        else str(event.get("EventTime", "")),
                    "username": event.get("Username", ""),
                    "source_ip": ct_event.get("sourceIPAddress", ""),
                    "user_agent": ct_event.get("userAgent", ""),
                    "error_code": ct_event.get("errorCode", ""),
                    "error_message": ct_event.get("errorMessage", ""),
                    "aws_region": ct_event.get("awsRegion", ""),
                    "read_only": event.get("ReadOnly", ""),
                })
        return events

    def build_baseline(self, events):
        """Build behavioral baseline from events."""
        user_events = defaultdict(list)
        user_ips = defaultdict(set)
        user_sources = defaultdict(set)
        for e in events:
            user = e["username"]
            user_events[user].append(e["event_name"])
            user_ips[user].add(e["source_ip"])
            user_sources[user].add(e["event_source"])
        return {
            "user_event_counts": {u: len(evts) for u, evts in user_events.items()},
            "user_unique_ips": {u: len(ips) for u, ips in user_ips.items()},
            "user_unique_sources": {u: len(srcs) for u, srcs in user_sources.items()},
        }

    def detect_anomalies(self, events):
        """Detect anomalous patterns in CloudTrail events."""
        user_events = defaultdict(list)
        for e in events:
            user_events[e["username"]].append(e)

        sensitive_calls = [e for e in events if e["event_name"] in SENSITIVE_EVENTS]
        for e in sensitive_calls:
            self.findings.append({
                "severity": "high", "type": "Sensitive API Call",
                "detail": f"{e['username']} called {e['event_name']} from {e['source_ip']}",
            })

        error_events = [e for e in events if e["error_code"] in ERROR_INDICATORS]
        error_by_user = Counter(e["username"] for e in error_events)
        for user, count in error_by_user.items():
            if count >= 5:
                self.findings.append({
                    "severity": "high", "type": "High Access Denied Rate",
                    "detail": f"{user} received {count} AccessDenied errors",
                })

        for user, evts in user_events.items():
            ips = {e["source_ip"] for e in evts}
            if len(ips) >= 5:
                self.findings.append({
                    "severity": "medium", "type": "Multiple Source IPs",
                    "detail": f"{user} accessed from {len(ips)} distinct IPs",
                })

        trail_tampering = [e for e in events
                           if e["event_name"] in ("StopLogging", "DeleteTrail", "UpdateTrail")]
        for e in trail_tampering:
            self.findings.append({
                "severity": "critical", "type": "CloudTrail Tampering",
                "detail": f"{e['username']} called {e['event_name']}",
            })

        return {
            "sensitive_api_calls": len(sensitive_calls),
            "access_denied_events": len(error_events),
            "trail_tampering_events": len(trail_tampering),
        }

    def generate_report(self):
        events = self.fetch_events()
        baseline = self.build_baseline(events)
        anomalies = self.detect_anomalies(events)

        event_name_counts = Counter(e["event_name"] for e in events).most_common(20)
        source_counts = Counter(e["event_source"] for e in events).most_common(10)

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "lookback_hours": self.lookback_hours,
            "total_events": len(events),
            "top_event_names": event_name_counts,
            "top_event_sources": source_counts,
            "baseline": baseline,
            "anomaly_summary": anomalies,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "cloudtrail_anomaly_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    parser = argparse.ArgumentParser(
        description="Detect anomalies in AWS CloudTrail API activity"
    )
    parser.add_argument("--profile", default=None, help="AWS CLI profile name")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--hours", type=int, default=24, help="Lookback window in hours")
    parser.add_argument("--output-dir", default="./cloudtrail_anomalies")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    detector = CloudTrailAnomalyDetector(
        profile=args.profile, region=args.region,
        lookback_hours=args.hours, output_dir=args.output_dir,
    )
    detector.generate_report()


if __name__ == "__main__":
    main()
