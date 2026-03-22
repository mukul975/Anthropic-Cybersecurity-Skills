#!/usr/bin/env python3
"""
AWS Detective Threat Hunting Script

Lists behavior graphs, retrieves investigations, and analyzes entity
indicators for cloud-native threat hunting.
"""

import boto3
import json
import sys
import os
from datetime import datetime, timedelta


def _collect_all_pages(client_method, result_key, **kwargs):
    """Paginate through all pages of an AWS Detective API call."""
    all_items = []
    while True:
        response = client_method(**kwargs)
        all_items.extend(response.get(result_key, []))
        next_token = response.get('NextToken')
        if not next_token:
            break
        kwargs['NextToken'] = next_token
    return all_items


def list_behavior_graphs(session):
    """List all Detective behavior graphs in the account."""
    client = session.client('detective')
    graphs = _collect_all_pages(client.list_graphs, 'GraphList')

    if not graphs:
        print("[!] No behavior graphs found. Enable Detective first.")
        return []

    print(f"[+] Found {len(graphs)} behavior graph(s)\n")
    for graph in graphs:
        print(f"  ARN: {graph['Arn']}")
        created = graph.get('CreatedTime', 'N/A')
        print(f"  Created: {created}")
        print()

    return graphs


def list_investigations(session, graph_arn, severity=None, max_results=20):
    """List investigations filtered by severity."""
    client = session.client('detective')

    filter_criteria = {}
    if severity:
        filter_criteria['Severity'] = {'Value': severity}

    kwargs = {
        'GraphArn': graph_arn,
        'MaxResults': max_results,
    }
    if filter_criteria:
        kwargs['FilterCriteria'] = filter_criteria

    investigations = _collect_all_pages(
        client.list_investigations, 'InvestigationDetails', **kwargs
    )

    if not investigations:
        print("[+] No investigations found matching criteria")
        return []

    print(f"[+] Found {len(investigations)} investigation(s)\n")
    for inv in investigations:
        inv_id = inv.get('InvestigationId', 'N/A')
        severity = inv.get('Severity', 'N/A')
        status = inv.get('Status', 'N/A')
        entity = inv.get('EntityArn', 'N/A')
        created = inv.get('CreatedTime', 'N/A')
        print(f"  Investigation: {inv_id}")
        print(f"    Severity: {severity} | Status: {status}")
        print(f"    Entity: {entity}")
        print(f"    Created: {created}")
        print()

    return investigations


def get_investigation_detail(session, graph_arn, investigation_id):
    """Get detailed information about a specific investigation."""
    client = session.client('detective')

    response = client.get_investigation(
        GraphArn=graph_arn,
        InvestigationId=investigation_id,
    )

    print(f"[+] Investigation: {investigation_id}")
    print(f"  Entity: {response.get('EntityArn', 'N/A')}")
    print(f"  Entity Type: {response.get('EntityType', 'N/A')}")
    print(f"  Severity: {response.get('Severity', 'N/A')}")
    print(f"  Status: {response.get('Status', 'N/A')}")
    print(f"  Created: {response.get('CreatedTime', 'N/A')}")
    print(f"  Scope Start: {response.get('ScopeStartTime', 'N/A')}")
    print(f"  Scope End: {response.get('ScopeEndTime', 'N/A')}")

    return response


def list_indicators(session, graph_arn, investigation_id, max_results=50):
    """List indicators for a specific investigation."""
    client = session.client('detective')

    indicators = _collect_all_pages(
        client.list_indicators, 'Indicators',
        GraphArn=graph_arn,
        InvestigationId=investigation_id,
        MaxResults=max_results,
    )
    if not indicators:
        print("[+] No indicators found for this investigation")
        return []

    print(f"[+] Found {len(indicators)} indicator(s)\n")
    for ind in indicators:
        ind_type = ind.get('IndicatorType', 'N/A')
        detail = ind.get('IndicatorDetail', {})
        print(f"  Type: {ind_type}")
        if detail:
            print(f"    Detail: {json.dumps(detail, default=str)[:200]}")
        print()

    return indicators


def export_results(data, output_dir):
    """Export investigation results to JSON."""
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, "detective_results.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"[+] Results exported to {out_path}")
    return out_path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="AWS Detective Threat Hunting Tool"
    )
    parser.add_argument(
        "--graphs", action="store_true", help="List behavior graphs"
    )
    parser.add_argument(
        "--investigations", action="store_true", help="List investigations"
    )
    parser.add_argument("--graph-arn", type=str, help="Behavior graph ARN")
    parser.add_argument(
        "--investigation-id", type=str, help="Investigation ID for detail view"
    )
    parser.add_argument(
        "--indicators", action="store_true", help="List indicators"
    )
    parser.add_argument(
        "--severity",
        type=str,
        default=None,
        choices=["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Severity filter (e.g. HIGH)",
    )
    parser.add_argument("--max-results", type=int, default=20,
                        help="Max results per API call (1-100)")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--profile", type=str, help="AWS profile name")
    parser.add_argument(
        "--output", type=str, help="Output directory for JSON export"
    )
    args = parser.parse_args()

    if args.max_results < 1 or args.max_results > 100:
        parser.error("--max-results must be between 1 and 100")

    kwargs = {"region_name": args.region}
    if args.profile:
        kwargs["profile_name"] = args.profile
    session = boto3.Session(**kwargs)

    results = {}

    if args.graphs:
        results["graphs"] = list_behavior_graphs(session)

    if args.investigations:
        if not args.graph_arn:
            print("[!] --graph-arn required for --investigations")
            sys.exit(1)
        results["investigations"] = list_investigations(
            session, args.graph_arn, args.severity, args.max_results
        )

    if args.investigation_id:
        if not args.graph_arn:
            print("[!] --graph-arn required for --investigation-id")
            sys.exit(1)
        results["detail"] = get_investigation_detail(
            session, args.graph_arn, args.investigation_id
        )

    if args.indicators:
        if not args.graph_arn or not args.investigation_id:
            print("[!] --graph-arn and --investigation-id required for --indicators")
            sys.exit(1)
        results["indicators"] = list_indicators(
            session, args.graph_arn, args.investigation_id, args.max_results
        )

    if args.output and results:
        export_results(results, args.output)
