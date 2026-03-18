#!/usr/bin/env python3
"""
AWS Detective Automated Entity Investigation

Automates the investigation workflow for AWS Detective, including:
- Listing and selecting behavior graphs
- Searching entities by ARN or keyword
- Starting investigations on suspicious entities
- Collecting indicators of compromise
- Exporting investigation results to JSON

Requirements:
    pip install boto3

Usage:
    python process.py --entity-arn arn:aws:iam::123456789012:user/suspect-user
    python process.py --entity-arn arn:aws:iam::123456789012:user/suspect-user --days 14
    python process.py --investigation-id inv-0abcdef1234567890 --collect-indicators
    python process.py --list-finding-groups --severity CRITICAL
"""

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("Error: boto3 is required. Install with: pip install boto3", file=sys.stderr)
    sys.exit(1)


def get_detective_client(region: str | None = None) -> boto3.client:
    """Create an AWS Detective client."""
    kwargs = {}
    if region:
        kwargs["region_name"] = region
    return boto3.client("detective", **kwargs)


def list_graphs(client) -> list:
    """List all behavior graphs in the account."""
    graphs = []
    try:
        response = client.list_graphs()
        graphs = response.get("GraphList", [])
    except ClientError as e:
        print(f"Error listing graphs: {e}", file=sys.stderr)
    return graphs


def get_graph_arn(client, graph_arn: str | None = None) -> str:
    """Get or auto-detect the behavior graph ARN."""
    if graph_arn:
        return graph_arn

    graphs = list_graphs(client)
    if not graphs:
        print("Error: No behavior graphs found. Enable AWS Detective first.", file=sys.stderr)
        sys.exit(1)

    if len(graphs) == 1:
        arn = graphs[0]["Arn"]
        print(f"Auto-detected graph: {arn}")
        return arn

    print("Multiple graphs found. Please specify --graph-arn:")
    for g in graphs:
        print(f"  {g['Arn']} (created: {g.get('CreatedTime', 'unknown')})")
    sys.exit(1)


def search_entities(client, graph_arn: str, search_string: str) -> list:
    """Search for entities in the behavior graph."""
    try:
        # Note: search-entities may not be available in all SDK versions.
        # Fall back to get-entity-profile if needed.
        response = client.search_entities(
            GraphArn=graph_arn,
            SearchString=search_string,
        )
        return response.get("Entities", [])
    except ClientError as e:
        print(f"Error searching entities: {e}", file=sys.stderr)
        return []
    except AttributeError:
        print("Warning: search_entities not available in this SDK version.", file=sys.stderr)
        return []


def start_investigation(
    client,
    graph_arn: str,
    entity_arn: str,
    days: int = 7,
) -> dict:
    """Start an automated investigation on an entity."""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)

    try:
        response = client.start_investigation(
            GraphArn=graph_arn,
            EntityArn=entity_arn,
            ScopeStartTime=start_time,
            ScopeEndTime=end_time,
        )
        investigation_id = response.get("InvestigationId")
        print(f"Investigation started: {investigation_id}")
        return response
    except ClientError as e:
        print(f"Error starting investigation: {e}", file=sys.stderr)
        return {}


def get_investigation(client, graph_arn: str, investigation_id: str) -> dict:
    """Get investigation details and status."""
    try:
        response = client.get_investigation(
            GraphArn=graph_arn,
            InvestigationId=investigation_id,
        )
        return response
    except ClientError as e:
        print(f"Error getting investigation: {e}", file=sys.stderr)
        return {}


def list_indicators(client, graph_arn: str, investigation_id: str) -> list:
    """List all indicators of compromise for an investigation."""
    indicators = []
    try:
        response = client.list_indicators(
            GraphArn=graph_arn,
            InvestigationId=investigation_id,
        )
        indicators = response.get("Indicators", [])

        # Handle pagination
        while response.get("NextToken"):
            response = client.list_indicators(
                GraphArn=graph_arn,
                InvestigationId=investigation_id,
                NextToken=response["NextToken"],
            )
            indicators.extend(response.get("Indicators", []))

    except ClientError as e:
        print(f"Error listing indicators: {e}", file=sys.stderr)
    return indicators


def list_finding_groups(client, graph_arn: str, severity: str | None = None) -> list:
    """List finding groups, optionally filtered by severity."""
    try:
        kwargs = {"GraphArn": graph_arn}
        if severity:
            kwargs["FilterCriteria"] = {"Severity": {"Value": severity}}
        response = client.list_finding_groups(**kwargs)
        return response.get("FindingGroups", [])
    except ClientError as e:
        print(f"Error listing finding groups: {e}", file=sys.stderr)
        return []
    except AttributeError:
        print("Warning: list_finding_groups not available in this SDK version.", file=sys.stderr)
        return []


def export_results(data: dict, output_path: str) -> None:
    """Export investigation results to a JSON file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Convert datetime objects to ISO format strings
    def serialize(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=serialize)
    print(f"Results exported to: {path}")


def run_full_investigation(
    client,
    graph_arn: str,
    entity_arn: str,
    days: int = 7,
    output_dir: str = "investigation-output",
) -> dict:
    """Run a complete investigation workflow and export results."""
    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "graph_arn": graph_arn,
        "entity_arn": entity_arn,
        "scope_days": days,
    }

    # Step 1: Search for the entity
    print(f"\n[1/4] Searching for entity: {entity_arn}")
    search_term = entity_arn.split("/")[-1] if "/" in entity_arn else entity_arn
    entities = search_entities(client, graph_arn, search_term)
    results["entities_found"] = len(entities)
    print(f"  Found {len(entities)} matching entities")

    # Step 2: Start investigation
    print(f"\n[2/4] Starting investigation (scope: {days} days)")
    inv_response = start_investigation(client, graph_arn, entity_arn, days)
    investigation_id = inv_response.get("InvestigationId")
    results["investigation_id"] = investigation_id

    if not investigation_id:
        print("Error: Failed to start investigation.", file=sys.stderr)
        return results

    # Step 3: Get investigation details
    print(f"\n[3/4] Retrieving investigation details: {investigation_id}")
    inv_details = get_investigation(client, graph_arn, investigation_id)
    results["investigation"] = inv_details
    state = inv_details.get("State", "UNKNOWN")
    severity = inv_details.get("Severity", "UNKNOWN")
    print(f"  State: {state} | Severity: {severity}")

    # Step 4: Collect indicators
    print("\n[4/4] Collecting indicators of compromise")
    indicators = list_indicators(client, graph_arn, investigation_id)
    results["indicators"] = indicators
    results["indicator_count"] = len(indicators)
    print(f"  Collected {len(indicators)} indicators")

    # Summarize indicator types
    indicator_types = {}
    for ind in indicators:
        itype = ind.get("IndicatorType", "UNKNOWN")
        indicator_types[itype] = indicator_types.get(itype, 0) + 1
    results["indicator_summary"] = indicator_types

    if indicator_types:
        print("  Indicator breakdown:")
        for itype, count in sorted(indicator_types.items()):
            print(f"    {itype}: {count}")

    # Export results
    output_path = f"{output_dir}/investigation-{investigation_id}.json"
    export_results(results, output_path)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="AWS Detective Automated Entity Investigation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --entity-arn arn:aws:iam::123456789012:user/suspect-user
  %(prog)s --entity-arn arn:aws:iam::123456789012:user/suspect-user --days 14
  %(prog)s --investigation-id inv-0abcdef --collect-indicators
  %(prog)s --list-finding-groups --severity CRITICAL
  %(prog)s --list-graphs
        """,
    )
    parser.add_argument("--graph-arn", help="Behavior graph ARN (auto-detected if only one exists)")
    parser.add_argument("--region", help="AWS region (uses default if not specified)")
    parser.add_argument("--entity-arn", help="Entity ARN to investigate")
    parser.add_argument("--days", type=int, default=7, help="Investigation scope in days (default: 7)")
    parser.add_argument("--investigation-id", help="Existing investigation ID to query")
    parser.add_argument("--collect-indicators", action="store_true", help="Collect IoCs for an existing investigation")
    parser.add_argument("--list-finding-groups", action="store_true", help="List finding groups")
    parser.add_argument("--severity", help="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)")
    parser.add_argument("--list-graphs", action="store_true", help="List all behavior graphs")
    parser.add_argument("--output-dir", default="investigation-output", help="Output directory for results")
    parser.add_argument("--json", action="store_true", help="Output raw JSON to stdout")

    args = parser.parse_args()

    try:
        client = get_detective_client(args.region)
    except NoCredentialsError:
        print("Error: AWS credentials not configured. Run 'aws configure' first.", file=sys.stderr)
        sys.exit(1)

    # List graphs mode
    if args.list_graphs:
        graphs = list_graphs(client)
        if args.json:
            print(json.dumps(graphs, indent=2, default=str))
        else:
            print(f"Found {len(graphs)} behavior graph(s):")
            for g in graphs:
                print(f"  ARN: {g['Arn']}")
                print(f"  Created: {g.get('CreatedTime', 'unknown')}")
                print()
        return

    graph_arn = get_graph_arn(client, args.graph_arn)

    # List finding groups mode
    if args.list_finding_groups:
        groups = list_finding_groups(client, graph_arn, args.severity)
        if args.json:
            print(json.dumps(groups, indent=2, default=str))
        else:
            print(f"Found {len(groups)} finding group(s):")
            for g in groups:
                print(f"  ID: {g.get('Id', 'unknown')}")
                print(f"  Severity: {g.get('Severity', 'unknown')}")
                print()
        return

    # Query existing investigation
    if args.investigation_id:
        inv = get_investigation(client, graph_arn, args.investigation_id)
        if args.collect_indicators:
            indicators = list_indicators(client, graph_arn, args.investigation_id)
            inv["indicators"] = indicators
        if args.json:
            print(json.dumps(inv, indent=2, default=str))
        else:
            print(f"Investigation: {args.investigation_id}")
            print(f"  State: {inv.get('State', 'UNKNOWN')}")
            print(f"  Severity: {inv.get('Severity', 'UNKNOWN')}")
            print(f"  Status: {inv.get('Status', 'UNKNOWN')}")
            if "indicators" in inv:
                print(f"  Indicators: {len(inv['indicators'])}")
        if not args.json:
            export_results(inv, f"{args.output_dir}/investigation-{args.investigation_id}.json")
        return

    # Full investigation mode
    if args.entity_arn:
        results = run_full_investigation(
            client, graph_arn, args.entity_arn, args.days, args.output_dir
        )
        if args.json:
            print(json.dumps(results, indent=2, default=str))
        return

    parser.print_help()


if __name__ == "__main__":
    main()
