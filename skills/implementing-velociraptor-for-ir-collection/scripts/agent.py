#!/usr/bin/env python3
"""Velociraptor incident response collection agent.

Interfaces with the Velociraptor DFIR platform API to schedule artifact
collections on endpoints, retrieve results, and generate IR reports.
Supports common forensic artifacts including process listings, network
connections, autoruns, event logs, and file system evidence.
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("[!] 'requests' library required: pip install requests", file=sys.stderr)
    sys.exit(1)

try:
    import grpc
    HAS_GRPC = True
except ImportError:
    HAS_GRPC = False


def get_velo_config():
    """Return Velociraptor API configuration."""
    api_url = os.environ.get("VELOCIRAPTOR_API_URL", "https://localhost:8001")
    api_key = os.environ.get("VELOCIRAPTOR_API_KEY", "")
    cert_path = os.environ.get("VELOCIRAPTOR_CERT", "")
    return api_url.rstrip("/"), api_key, cert_path


def velo_api_call(api_url, api_key, endpoint, method="GET", data=None, cert_path=None):
    """Make an authenticated API call to Velociraptor."""
    url = f"{api_url}{endpoint}"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    verify = cert_path if cert_path else False
    if method == "POST":
        resp = requests.post(url, headers=headers, json=data, verify=verify, timeout=60)
    else:
        resp = requests.get(url, headers=headers, verify=verify, timeout=60)
    resp.raise_for_status()
    return resp.json()


def search_clients(api_url, api_key, query, cert_path=None):
    """Search for Velociraptor clients by hostname, label, or client ID."""
    print(f"[*] Searching for clients: {query}")
    data = {"query": query, "count": 100}
    result = velo_api_call(api_url, api_key, "/api/v1/SearchClients", "POST", data, cert_path)
    clients = result.get("items", [])
    print(f"[+] Found {len(clients)} client(s)")
    for c in clients:
        os_info = c.get("os_info", {})
        print(f"    {c.get('client_id', 'N/A'):20s} | "
              f"{os_info.get('hostname', 'unknown'):20s} | "
              f"{os_info.get('system', 'unknown'):10s} | "
              f"Last seen: {c.get('last_seen_at', 'N/A')}")
    return clients


def collect_artifact(api_url, api_key, client_id, artifacts, parameters=None, cert_path=None):
    """Schedule an artifact collection on a specific client."""
    print(f"[*] Scheduling collection on {client_id}: {', '.join(artifacts)}")
    specs = []
    for artifact in artifacts:
        spec = {"artifact": artifact}
        if parameters and artifact in parameters:
            spec["parameters"] = {"env": [
                {"key": k, "value": v} for k, v in parameters[artifact].items()
            ]}
        specs.append(spec)

    data = {
        "client_id": client_id,
        "artifacts": artifacts,
        "specs": specs,
    }
    result = velo_api_call(api_url, api_key, "/api/v1/CollectArtifact", "POST", data, cert_path)
    flow_id = result.get("flow_id", "")
    print(f"[+] Collection started, flow ID: {flow_id}")
    return flow_id


def get_flow_status(api_url, api_key, client_id, flow_id, cert_path=None):
    """Check the status of a collection flow."""
    data = {"client_id": client_id, "flow_id": flow_id}
    result = velo_api_call(api_url, api_key, "/api/v1/GetFlowDetails", "POST", data, cert_path)
    context = result.get("context", {})
    state = context.get("state", "UNSET")
    return state, context


def wait_for_collection(api_url, api_key, client_id, flow_id, max_wait=300, cert_path=None):
    """Poll until a collection flow completes."""
    print(f"[*] Waiting for collection to complete (max {max_wait}s)...")
    elapsed = 0
    interval = 10
    while elapsed < max_wait:
        state, context = get_flow_status(api_url, api_key, client_id, flow_id, cert_path)
        if state == "FINISHED":
            total_rows = context.get("total_collected_rows", 0)
            total_bytes = context.get("total_uploaded_bytes", 0)
            print(f"[+] Collection complete: {total_rows} rows, "
                  f"{total_bytes / 1024:.1f} KB uploaded")
            return True, context
        if state == "ERROR":
            print(f"[!] Collection failed: {context.get('status', 'unknown')}", file=sys.stderr)
            return False, context
        print(f"    State: {state} ({elapsed}s elapsed)")
        time.sleep(interval)
        elapsed += interval
    print("[!] Timed out waiting for collection", file=sys.stderr)
    return False, {}


def get_flow_results(api_url, api_key, client_id, flow_id, artifact, cert_path=None):
    """Retrieve collected artifact results."""
    print(f"[*] Retrieving results for {artifact}")
    data = {
        "client_id": client_id,
        "flow_id": flow_id,
        "artifact": artifact,
        "count": 10000,
    }
    result = velo_api_call(api_url, api_key, "/api/v1/GetTable", "POST", data, cert_path)
    rows = result.get("rows", [])
    columns = result.get("columns", [])
    print(f"[+] Retrieved {len(rows)} row(s), {len(columns)} column(s)")
    return rows, columns


IR_ARTIFACT_SETS = {
    "triage": [
        "Windows.System.Pslist",
        "Windows.Network.Netstat",
        "Windows.Sys.Users",
        "Windows.System.TaskScheduler",
        "Generic.System.Pstree",
    ],
    "persistence": [
        "Windows.Sysinternals.Autoruns",
        "Windows.System.TaskScheduler",
        "Windows.Registry.Run",
        "Windows.System.Services",
    ],
    "network": [
        "Windows.Network.Netstat",
        "Windows.Network.ArpCache",
        "Windows.Network.DNSCache",
        "Windows.Network.InterfaceAddresses",
    ],
    "logs": [
        "Windows.EventLogs.Cleared",
        "Windows.EventLogs.RDPAuth",
        "Windows.EventLogs.PowershellScriptblock",
    ],
    "linux_triage": [
        "Linux.Sys.Pslist",
        "Linux.Network.Netstat",
        "Linux.Sys.Users",
        "Linux.Sys.Crontab",
        "Linux.Sys.LastUserLogin",
    ],
}


def format_summary(client_id, artifacts, flow_context, results_summary):
    """Print collection summary."""
    print(f"\n{'='*60}")
    print("  Velociraptor IR Collection Report")
    print(f"{'='*60}")
    print(f"  Client ID   : {client_id}")
    print(f"  Flow ID     : {flow_context.get('session_id', 'N/A')}")
    print(f"  State       : {flow_context.get('state', 'N/A')}")
    print(f"  Artifacts   : {len(artifacts)}")
    print(f"  Total Rows  : {flow_context.get('total_collected_rows', 0)}")

    for artifact_name, row_count in results_summary.items():
        print(f"    {artifact_name:50s}: {row_count} rows")


def main():
    parser = argparse.ArgumentParser(
        description="Velociraptor IR collection agent"
    )
    sub = parser.add_subparsers(dest="command")

    p_search = sub.add_parser("search", help="Search for clients")
    p_search.add_argument("--query", required=True, help="Search query (hostname, label, client ID)")

    p_collect = sub.add_parser("collect", help="Collect artifacts from client")
    p_collect.add_argument("--client-id", required=True, help="Velociraptor client ID")
    p_collect.add_argument("--artifacts", nargs="+", help="Specific artifact names to collect")
    p_collect.add_argument("--preset", choices=list(IR_ARTIFACT_SETS.keys()),
                          help="Use a predefined IR artifact set")
    p_collect.add_argument("--wait", type=int, default=300, help="Max wait time in seconds")

    p_status = sub.add_parser("status", help="Check collection status")
    p_status.add_argument("--client-id", required=True)
    p_status.add_argument("--flow-id", required=True)

    parser.add_argument("--api-url", help="Velociraptor API URL (or VELOCIRAPTOR_API_URL env)")
    parser.add_argument("--api-key", help="API key (or VELOCIRAPTOR_API_KEY env)")
    parser.add_argument("--cert", help="CA cert path (or VELOCIRAPTOR_CERT env)")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.api_url:
        os.environ["VELOCIRAPTOR_API_URL"] = args.api_url
    if args.api_key:
        os.environ["VELOCIRAPTOR_API_KEY"] = args.api_key
    if args.cert:
        os.environ["VELOCIRAPTOR_CERT"] = args.cert

    api_url, api_key, cert_path = get_velo_config()
    if not api_key:
        print("[!] Set VELOCIRAPTOR_API_KEY env var or use --api-key", file=sys.stderr)
        sys.exit(1)

    result = {}

    if args.command == "search":
        clients = search_clients(api_url, api_key, args.query, cert_path)
        result = {"action": "search", "query": args.query, "clients": clients}

    elif args.command == "collect":
        artifacts = args.artifacts or IR_ARTIFACT_SETS.get(args.preset, [])
        if not artifacts:
            print("[!] Specify --artifacts or --preset", file=sys.stderr)
            sys.exit(1)
        flow_id = collect_artifact(api_url, api_key, args.client_id, artifacts, cert_path=cert_path)
        success, context = wait_for_collection(api_url, api_key, args.client_id, flow_id, args.wait, cert_path)
        results_summary = {}
        if success:
            for artifact in artifacts:
                try:
                    rows, cols = get_flow_results(api_url, api_key, args.client_id, flow_id, artifact, cert_path)
                    results_summary[artifact] = len(rows)
                except Exception as e:
                    results_summary[artifact] = f"Error: {e}"
        format_summary(args.client_id, artifacts, context, results_summary)
        result = {"action": "collect", "client_id": args.client_id, "flow_id": flow_id,
                  "state": context.get("state", "UNKNOWN"), "artifacts": results_summary}

    elif args.command == "status":
        state, context = get_flow_status(api_url, api_key, args.client_id, args.flow_id, cert_path)
        print(f"[*] Flow {args.flow_id}: {state}")
        result = {"action": "status", "flow_id": args.flow_id, "state": state, "context": context}

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "Velociraptor",
        "result": result,
    }
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
