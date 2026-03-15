#!/usr/bin/env python3
"""Agent for managing Microsoft Sentinel SIEM operations."""

import os
import json
import argparse
from datetime import datetime, timedelta

from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from azure.mgmt.securityinsight import SecurityInsights


def get_credential(tenant_id=None, client_id=None, client_secret=None):
    """Get Azure credential for authentication."""
    if client_id and client_secret and tenant_id:
        return ClientSecretCredential(tenant_id, client_id, client_secret)
    return DefaultAzureCredential()


def run_kql_query(credential, workspace_id, query, timespan_hours=24):
    """Execute a KQL query against a Log Analytics workspace."""
    client = LogsQueryClient(credential)
    timespan = timedelta(hours=timespan_hours)
    response = client.query_workspace(workspace_id, query, timespan=timespan)
    if response.status == LogsQueryStatus.SUCCESS:
        rows = []
        for table in response.tables:
            columns = [col.name for col in table.columns]
            for row in table.rows:
                rows.append(dict(zip(columns, row)))
        return rows
    return []


def detect_impossible_travel(credential, workspace_id):
    """Detect impossible travel sign-ins using KQL."""
    query = """
    SigninLogs
    | where ResultType == 0
    | project TimeGenerated, UserPrincipalName, IPAddress,
              Latitude = toreal(LocationDetails.geoCoordinates.latitude),
              Longitude = toreal(LocationDetails.geoCoordinates.longitude)
    | sort by UserPrincipalName asc, TimeGenerated asc
    | extend PrevLat = prev(Latitude), PrevLon = prev(Longitude),
             PrevTime = prev(TimeGenerated), PrevUser = prev(UserPrincipalName)
    | where UserPrincipalName == PrevUser
    | extend TimeDiff = datetime_diff('minute', TimeGenerated, PrevTime)
    | where TimeDiff < 60
    | extend Distance = geo_distance_2points(Longitude, Latitude, PrevLon, PrevLat) / 1000
    | where Distance > 500
    | project TimeGenerated, UserPrincipalName, IPAddress, Distance, TimeDiff
    """
    return run_kql_query(credential, workspace_id, query, 24)


def detect_aws_credential_abuse(credential, workspace_id):
    """Detect AWS credential abuse via CloudTrail in Sentinel."""
    query = """
    AWSCloudTrail
    | where EventName in ("ConsoleLogin", "AssumeRole", "GetSessionToken")
    | where ErrorCode == ""
    | summarize LoginCount = count(), DistinctIPs = dcount(SourceIpAddress),
                IPList = make_set(SourceIpAddress, 10)
                by UserIdentityArn, bin(TimeGenerated, 1h)
    | where DistinctIPs > 3
    """
    return run_kql_query(credential, workspace_id, query, 24)


def detect_mass_deletion(credential, workspace_id):
    """Detect mass S3 object deletion (potential ransomware)."""
    query = """
    AWSCloudTrail
    | where EventName in ("DeleteObject", "DeleteObjects")
    | summarize DeleteCount = count(), Buckets = dcount(RequestParameters_bucketName)
                by UserIdentityArn, bin(TimeGenerated, 10m)
    | where DeleteCount > 100
    """
    return run_kql_query(credential, workspace_id, query, 24)


def get_incident_summary(credential, workspace_id, days=7):
    """Get incident summary from Sentinel."""
    query = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize count() by Severity
    | order by Severity
    """
    return run_kql_query(credential, workspace_id, query, days * 24)


def match_threat_intelligence(credential, workspace_id):
    """Match network traffic against threat intelligence indicators."""
    query = """
    let TI_IPs = ThreatIntelligenceIndicator
    | where isnotempty(NetworkIP)
    | distinct NetworkIP;
    CommonSecurityLog
    | where DestinationIP in (TI_IPs)
    | project TimeGenerated, SourceIP, DestinationIP, DestinationPort, DeviceAction
    | take 100
    """
    return run_kql_query(credential, workspace_id, query, 24)


def list_analytics_rules(credential, subscription_id, resource_group, workspace_name):
    """List active Sentinel analytics rules."""
    client = SecurityInsights(credential, subscription_id)
    rules = client.alert_rules.list(resource_group, workspace_name)
    result = []
    for rule in rules:
        result.append({
            "name": rule.display_name if hasattr(rule, "display_name") else rule.name,
            "severity": getattr(rule, "severity", "Unknown"),
            "enabled": getattr(rule, "enabled", True),
        })
    return result


def main():
    parser = argparse.ArgumentParser(description="Microsoft Sentinel SIEM Agent")
    parser.add_argument("--workspace-id", default=os.getenv("SENTINEL_WORKSPACE_ID"))
    parser.add_argument("--tenant-id", default=os.getenv("AZURE_TENANT_ID"))
    parser.add_argument("--client-id", default=os.getenv("AZURE_CLIENT_ID"))
    parser.add_argument("--client-secret", default=os.getenv("AZURE_CLIENT_SECRET"))
    parser.add_argument("--output", default="sentinel_report.json")
    parser.add_argument("--action", choices=[
        "impossible_travel", "aws_abuse", "mass_deletion",
        "incidents", "threat_intel", "full_hunt"
    ], default="full_hunt")
    args = parser.parse_args()

    credential = get_credential(args.tenant_id, args.client_id, args.client_secret)
    report = {"scan_date": datetime.utcnow().isoformat(), "findings": {}}

    if args.action in ("impossible_travel", "full_hunt"):
        results = detect_impossible_travel(credential, args.workspace_id)
        report["findings"]["impossible_travel"] = results
        print(f"[+] Impossible travel detections: {len(results)}")

    if args.action in ("aws_abuse", "full_hunt"):
        results = detect_aws_credential_abuse(credential, args.workspace_id)
        report["findings"]["aws_credential_abuse"] = results
        print(f"[+] AWS credential abuse events: {len(results)}")

    if args.action in ("mass_deletion", "full_hunt"):
        results = detect_mass_deletion(credential, args.workspace_id)
        report["findings"]["mass_deletion"] = results
        print(f"[+] Mass deletion events: {len(results)}")

    if args.action in ("incidents", "full_hunt"):
        results = get_incident_summary(credential, args.workspace_id)
        report["findings"]["incidents_7d"] = results
        print(f"[+] Incident summary (7d): {results}")

    if args.action in ("threat_intel", "full_hunt"):
        results = match_threat_intelligence(credential, args.workspace_id)
        report["findings"]["ti_matches"] = results
        print(f"[+] Threat intel matches: {len(results)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
