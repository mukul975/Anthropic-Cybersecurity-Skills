#!/usr/bin/env python3
"""Agent for analyzing Azure activity logs for threat detection."""

import os
import json
import argparse
from datetime import datetime, timedelta

from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus


def get_credential(tenant_id=None, client_id=None, client_secret=None):
    """Get Azure credential."""
    if client_id and client_secret and tenant_id:
        return ClientSecretCredential(tenant_id, client_id, client_secret)
    return DefaultAzureCredential()


def run_kql(credential, workspace_id, query, hours=24):
    """Execute KQL query against Log Analytics workspace."""
    client = LogsQueryClient(credential)
    response = client.query_workspace(
        workspace_id, query, timespan=timedelta(hours=hours)
    )
    rows = []
    if response.status == LogsQueryStatus.SUCCESS:
        for table in response.tables:
            columns = [col.name for col in table.columns]
            for row in table.rows:
                rows.append(dict(zip(columns, row)))
    return rows


def detect_privilege_escalation(credential, workspace_id):
    """Detect role assignment changes indicating privilege escalation."""
    query = """
    AzureActivity
    | where OperationNameValue has_any (
        "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
        "MICROSOFT.AUTHORIZATION/ROLEDEFINITIONS/WRITE"
    )
    | where ActivityStatusValue == "Success"
    | project TimeGenerated, Caller, CallerIpAddress,
              OperationNameValue, ResourceGroup, Properties_d
    | order by TimeGenerated desc
    """
    return run_kql(credential, workspace_id, query)


def detect_nsg_changes(credential, workspace_id):
    """Detect Network Security Group rule modifications."""
    query = """
    AzureActivity
    | where OperationNameValue has_any (
        "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
        "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/DELETE"
    )
    | where ActivityStatusValue == "Success"
    | project TimeGenerated, Caller, CallerIpAddress,
              OperationNameValue, ResourceGroup
    | order by TimeGenerated desc
    """
    return run_kql(credential, workspace_id, query)


def detect_keyvault_access(credential, workspace_id):
    """Detect Key Vault secret access from unusual sources."""
    query = """
    AzureDiagnostics
    | where ResourceProvider == "MICROSOFT.KEYVAULT"
    | where OperationName in ("SecretGet", "SecretList", "SecretSet")
    | summarize AccessCount = count(), DistinctIPs = dcount(CallerIPAddress),
                IPList = make_set(CallerIPAddress, 10)
                by identity_claim_upn_s, OperationName, Resource
    | where DistinctIPs > 2 or AccessCount > 50
    | order by AccessCount desc
    """
    return run_kql(credential, workspace_id, query)


def detect_impossible_travel(credential, workspace_id):
    """Detect sign-ins from geographically distant locations in short time."""
    query = """
    SigninLogs
    | where ResultType == 0
    | project TimeGenerated, UserPrincipalName, IPAddress,
              Lat = toreal(LocationDetails.geoCoordinates.latitude),
              Lon = toreal(LocationDetails.geoCoordinates.longitude)
    | sort by UserPrincipalName asc, TimeGenerated asc
    | extend PrevLat = prev(Lat), PrevLon = prev(Lon),
             PrevTime = prev(TimeGenerated), PrevUser = prev(UserPrincipalName)
    | where UserPrincipalName == PrevUser
    | extend TimeDiffMin = datetime_diff('minute', TimeGenerated, PrevTime)
    | where TimeDiffMin < 60 and TimeDiffMin > 0
    | extend DistKm = geo_distance_2points(Lon, Lat, PrevLon, PrevLat) / 1000
    | where DistKm > 500
    | project TimeGenerated, UserPrincipalName, IPAddress, DistKm, TimeDiffMin
    """
    return run_kql(credential, workspace_id, query)


def detect_resource_deletion(credential, workspace_id):
    """Detect mass resource deletion events."""
    query = """
    AzureActivity
    | where OperationNameValue endswith "/DELETE"
    | where ActivityStatusValue == "Success"
    | summarize DeleteCount = count(), Resources = make_set(Resource, 20)
                by Caller, bin(TimeGenerated, 1h)
    | where DeleteCount > 10
    | order by DeleteCount desc
    """
    return run_kql(credential, workspace_id, query)


def detect_conditional_access_changes(credential, workspace_id):
    """Detect modifications to Conditional Access policies."""
    query = """
    AuditLogs
    | where OperationName has_any (
        "Update conditional access policy",
        "Delete conditional access policy"
    )
    | project TimeGenerated, InitiatedBy, OperationName,
              TargetResources, Result
    | order by TimeGenerated desc
    """
    return run_kql(credential, workspace_id, query)


def main():
    parser = argparse.ArgumentParser(description="Azure Activity Log Threat Detection Agent")
    parser.add_argument("--workspace-id", default=os.getenv("AZURE_WORKSPACE_ID"))
    parser.add_argument("--tenant-id", default=os.getenv("AZURE_TENANT_ID"))
    parser.add_argument("--client-id", default=os.getenv("AZURE_CLIENT_ID"))
    parser.add_argument("--client-secret", default=os.getenv("AZURE_CLIENT_SECRET"))
    parser.add_argument("--output", default="azure_threat_report.json")
    parser.add_argument("--action", choices=[
        "privesc", "nsg", "keyvault", "travel", "deletion", "full_hunt"
    ], default="full_hunt")
    args = parser.parse_args()

    cred = get_credential(args.tenant_id, args.client_id, args.client_secret)
    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.action in ("privesc", "full_hunt"):
        results = detect_privilege_escalation(cred, args.workspace_id)
        report["findings"]["privilege_escalation"] = results
        print(f"[+] Privilege escalation events: {len(results)}")

    if args.action in ("nsg", "full_hunt"):
        results = detect_nsg_changes(cred, args.workspace_id)
        report["findings"]["nsg_changes"] = results
        print(f"[+] NSG changes: {len(results)}")

    if args.action in ("keyvault", "full_hunt"):
        results = detect_keyvault_access(cred, args.workspace_id)
        report["findings"]["keyvault_anomalies"] = results
        print(f"[+] Key Vault anomalies: {len(results)}")

    if args.action in ("travel", "full_hunt"):
        results = detect_impossible_travel(cred, args.workspace_id)
        report["findings"]["impossible_travel"] = results
        print(f"[+] Impossible travel: {len(results)}")

    if args.action in ("deletion", "full_hunt"):
        results = detect_resource_deletion(cred, args.workspace_id)
        report["findings"]["mass_deletion"] = results
        print(f"[+] Mass deletion events: {len(results)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
