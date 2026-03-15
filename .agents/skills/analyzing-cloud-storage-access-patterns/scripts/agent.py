#!/usr/bin/env python3
"""Cloud Storage Access Pattern Analyzer - Detects abnormal S3/GCS/Azure Blob access via CloudTrail."""

import json
import logging
import argparse
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def query_cloudtrail_s3_events(bucket_name, hours_back=24):
    """Query CloudTrail for S3 data events on a specific bucket."""
    start_time = (datetime.utcnow() - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cmd = [
        "aws", "cloudtrail", "lookup-events",
        "--lookup-attributes", f"AttributeKey=ResourceType,AttributeValue=AWS::S3::Object",
        "--start-time", start_time,
        "--output", "json",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        logger.error("CloudTrail query failed: %s", result.stderr[:200])
        return []
    events = json.loads(result.stdout).get("Events", [])
    s3_events = []
    for event in events:
        ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
        req_params = ct_event.get("requestParameters", {})
        if req_params.get("bucketName") == bucket_name or not bucket_name:
            s3_events.append({
                "timestamp": event.get("EventTime", ""),
                "event_name": event.get("EventName", ""),
                "username": event.get("Username", ""),
                "source_ip": ct_event.get("sourceIPAddress", ""),
                "user_agent": ct_event.get("userAgent", ""),
                "bucket": req_params.get("bucketName", ""),
                "key": req_params.get("key", ""),
                "user_arn": ct_event.get("userIdentity", {}).get("arn", ""),
            })
    logger.info("Retrieved %d S3 events for bucket '%s'", len(s3_events), bucket_name or "all")
    return s3_events


def detect_bulk_downloads(events, threshold=100):
    """Detect bulk GetObject operations from a single principal."""
    user_downloads = defaultdict(list)
    for event in events:
        if event["event_name"] == "GetObject":
            user_downloads[event["user_arn"]].append(event)
    alerts = []
    for user_arn, downloads in user_downloads.items():
        if len(downloads) >= threshold:
            keys = [d["key"] for d in downloads]
            alerts.append({
                "user_arn": user_arn,
                "download_count": len(downloads),
                "unique_keys": len(set(keys)),
                "source_ips": list({d["source_ip"] for d in downloads}),
                "first_access": downloads[0]["timestamp"],
                "last_access": downloads[-1]["timestamp"],
                "severity": "critical",
                "indicator": "Bulk download (potential exfiltration)",
            })
    logger.info("Found %d bulk download alerts", len(alerts))
    return alerts


def detect_after_hours_access(events, business_start=8, business_end=18):
    """Detect access outside business hours."""
    after_hours = []
    for event in events:
        try:
            ts = event["timestamp"]
            if isinstance(ts, str):
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            else:
                dt = ts
            hour = dt.hour
            if hour < business_start or hour >= business_end:
                event["indicator"] = f"After-hours access at {hour:02d}:00 UTC"
                event["severity"] = "medium"
                after_hours.append(event)
        except (ValueError, AttributeError):
            continue
    logger.info("Found %d after-hours access events", len(after_hours))
    return after_hours


def detect_new_source_ips(events, known_ips=None):
    """Detect access from IP addresses not in the known baseline."""
    if known_ips is None:
        known_ips = set()
    new_ip_events = []
    for event in events:
        ip = event["source_ip"]
        if ip and ip not in known_ips and not ip.startswith("AWS Internal"):
            event["indicator"] = f"New source IP: {ip}"
            event["severity"] = "high"
            new_ip_events.append(event)
    unique_new = len({e["source_ip"] for e in new_ip_events})
    logger.info("Found %d events from %d new source IPs", len(new_ip_events), unique_new)
    return new_ip_events


def detect_enumeration(events, threshold=20):
    """Detect ListBucket/ListObjects enumeration patterns."""
    user_listings = defaultdict(int)
    for event in events:
        if event["event_name"] in ("ListBucket", "ListObjects", "ListObjectsV2"):
            user_listings[event["user_arn"]] += 1
    alerts = []
    for user_arn, count in user_listings.items():
        if count >= threshold:
            alerts.append({
                "user_arn": user_arn,
                "list_count": count,
                "severity": "high",
                "indicator": "Bucket enumeration spike (reconnaissance)",
            })
    return alerts


def build_access_baseline(events):
    """Build statistical baseline of normal access patterns."""
    hourly_counts = defaultdict(int)
    user_counts = defaultdict(int)
    ip_set = set()
    for event in events:
        try:
            ts = event["timestamp"]
            if isinstance(ts, str):
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                hourly_counts[dt.hour] += 1
        except (ValueError, AttributeError):
            pass
        user_counts[event["user_arn"]] += 1
        if event["source_ip"]:
            ip_set.add(event["source_ip"])
    return {
        "hourly_distribution": dict(hourly_counts),
        "user_request_counts": dict(user_counts),
        "known_ips": list(ip_set),
        "total_events": len(events),
    }


def generate_report(events, bulk_alerts, after_hours, new_ips, enum_alerts, baseline):
    """Generate cloud storage access analysis report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_events_analyzed": len(events),
        "bulk_download_alerts": bulk_alerts,
        "after_hours_access": len(after_hours),
        "new_source_ip_events": len(new_ips),
        "enumeration_alerts": enum_alerts,
        "baseline_summary": {
            "known_ips": len(baseline.get("known_ips", [])),
            "total_baseline_events": baseline.get("total_events", 0),
        },
        "sample_after_hours": after_hours[:10],
        "sample_new_ips": new_ips[:10],
    }
    total_alerts = len(bulk_alerts) + len(enum_alerts) + (1 if new_ips else 0)
    print(f"CLOUD STORAGE REPORT: {len(events)} events, {total_alerts} alerts")
    return report


def main():
    parser = argparse.ArgumentParser(description="Cloud Storage Access Pattern Analyzer")
    parser.add_argument("--bucket", default="", help="S3 bucket name to analyze")
    parser.add_argument("--hours-back", type=int, default=24)
    parser.add_argument("--bulk-threshold", type=int, default=100)
    parser.add_argument("--known-ips-file", help="File with known IP baselines")
    parser.add_argument("--output", default="s3_access_report.json")
    args = parser.parse_args()

    events = query_cloudtrail_s3_events(args.bucket, args.hours_back)
    baseline = build_access_baseline(events)
    known_ips = set(baseline.get("known_ips", []))
    if args.known_ips_file:
        with open(args.known_ips_file) as f:
            known_ips.update(line.strip() for line in f if line.strip())

    bulk_alerts = detect_bulk_downloads(events, args.bulk_threshold)
    after_hours = detect_after_hours_access(events)
    new_ips = detect_new_source_ips(events, known_ips)
    enum_alerts = detect_enumeration(events)

    report = generate_report(events, bulk_alerts, after_hours, new_ips, enum_alerts, baseline)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
