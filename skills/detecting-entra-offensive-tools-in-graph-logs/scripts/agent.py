#!/usr/bin/env python3
"""
agent.py - Hunt Entra offensive-tool fingerprints in Graph activity logs.

Runs curated KQL hunts against an Azure Log Analytics / Microsoft Sentinel
workspace using the Azure Monitor Query REST API. Authentication uses an
AAD bearer token (pass --token, or set AZ_MONITOR_TOKEN). Obtain one with:

    az account get-access-token --resource https://api.loganalytics.io \
        --query accessToken -o tsv

Defensive/blue-team tool. Use with appropriate Log Analytics read permissions.

References:
  - Azure Monitor Query API  https://learn.microsoft.com/rest/api/loganalytics/dataaccess/query/get
  - AADGraphActivityLogs      https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadgraphactivitylogs
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error

API = "https://api.loganalytics.io/v1/workspaces/{ws}/query"

HUNTS = {
    "ingestion": """
union withsource=Tbl MicrosoftGraphActivityLogs, AADGraphActivityLogs
| where TimeGenerated > ago({days}d)
| summarize Records=count(), LastSeen=max(TimeGenerated) by Tbl
""",
    "roadtools-ua": """
AADGraphActivityLogs
| where TimeGenerated > ago({days}d)
| where RequestMethod == "GET"
| where UserAgent contains "python" and UserAgent contains "aiohttp"
| summarize RequestCount = count() by CallerIpAddress, AppId, UserAgent, UserId
| sort by RequestCount desc
""",
    "tool-agents": """
union MicrosoftGraphActivityLogs, AADGraphActivityLogs
| where TimeGenerated > ago({days}d)
| where UserAgent has_any ("AADInternals","aad-internals","azurehound","BloodHound","Go-http-client")
| project TimeGenerated, UserAgent, CallerIpAddress, AppId, UserId, RequestUri
| sort by TimeGenerated desc
""",
    "endpoint-sweep": """
AADGraphActivityLogs
| where TimeGenerated > ago({days}d)
| where RequestMethod == "GET"
| extend TopLevelResource = tolower(tostring(split(split(RequestUri, "?")[0], "/")[3]))
| summarize TopLevelResources = make_set(TopLevelResource), AppIds = make_set(AppId),
    CallerIPs = make_set(CallerIpAddress), UserAgents = make_set(UserAgent),
    StartTime = min(TimeGenerated), EndTime = max(TimeGenerated)
    by UserId, bin(TimeGenerated, 5m)
| where TopLevelResources has_all ("users","tenantdetails","groups","applications",
    "serviceprincipals","devices","directoryroles","roledefinitions","contacts",
    "oauth2permissiongrants","authorizationpolicy")
| project StartTime, EndTime, UserId, AppIds, CallerIPs, UserAgents
""",
    "volume-outlier": """
MicrosoftGraphActivityLogs
| where TimeGenerated > ago({days}d)
| where RequestMethod == "GET"
| where RequestUri has_any ("/users","/groups","/servicePrincipals","/applications","/directoryRoles","/roleManagement")
| summarize Reads=count(), Resources=dcount(RequestUri) by UserId, AppId, CallerIpAddress, bin(TimeGenerated, 10m)
| where Reads > {threshold}
| sort by Reads desc
""",
}


def run_query(workspace, token, kql):
    url = API.format(ws=workspace)
    body = json.dumps({"query": kql}).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise SystemExit(f"[!] query failed HTTP {e.code}: {e.read().decode(errors='replace')[:300]}")
    except urllib.error.URLError as e:
        raise SystemExit(f"[!] network error: {e.reason}")


def print_table(result):
    tables = result.get("tables", [])
    if not tables:
        print("    (no tables returned)")
        return
    t = tables[0]
    cols = [c["name"] for c in t.get("columns", [])]
    rows = t.get("rows", [])
    print("    " + " | ".join(cols))
    if not rows:
        print("    (0 rows)")
    for row in rows[:50]:
        print("    " + " | ".join(str(v) for v in row))
    if len(rows) > 50:
        print(f"    ... {len(rows) - 50} more rows")


def main():
    p = argparse.ArgumentParser(description="Hunt Entra offensive-tool fingerprints in Graph logs.")
    p.add_argument("--workspace", required=True, help="Log Analytics workspace ID (GUID)")
    p.add_argument("--token", default=os.environ.get("AZ_MONITOR_TOKEN"),
                   help="AAD bearer token for api.loganalytics.io (or set AZ_MONITOR_TOKEN)")
    p.add_argument("--hunt", choices=list(HUNTS) + ["all"], default="all",
                   help="Which hunt to run")
    p.add_argument("--days", type=int, default=7, help="Lookback window in days")
    p.add_argument("--threshold", type=int, default=200,
                   help="Read-count threshold for volume-outlier hunt")
    args = p.parse_args()

    if not args.token:
        raise SystemExit("[!] provide --token or set AZ_MONITOR_TOKEN "
                         "(az account get-access-token --resource https://api.loganalytics.io)")

    selected = list(HUNTS) if args.hunt == "all" else [args.hunt]
    for name in selected:
        kql = HUNTS[name].format(days=args.days, threshold=args.threshold)
        print(f"\n=== HUNT: {name} (last {args.days}d) ===")
        result = run_query(args.workspace, args.token, kql)
        print_table(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
