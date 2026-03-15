#!/usr/bin/env python3
"""Agent for performing GraphQL introspection attack and schema analysis."""

import json
import argparse
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name kind description
      fields(includeDeprecated: true) {
        name type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
  }
}
"""


def run_introspection(url, headers=None):
    """Execute GraphQL introspection query against target endpoint."""
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    resp = requests.post(url, json={"query": INTROSPECTION_QUERY}, headers=hdrs, timeout=30)
    if resp.status_code != 200:
        return {"url": url, "introspection_enabled": False, "status_code": resp.status_code}
    data = resp.json()
    if "errors" in data and not data.get("data"):
        return {"url": url, "introspection_enabled": False, "errors": data["errors"][:3]}
    schema = data.get("data", {}).get("__schema", {})
    types = schema.get("types", [])
    user_types = [t for t in types if not t["name"].startswith("__")]
    mutations = []
    queries = []
    for t in types:
        if t["name"] == schema.get("queryType", {}).get("name"):
            queries = [f["name"] for f in t.get("fields", [])]
        if t["name"] == (schema.get("mutationType") or {}).get("name"):
            mutations = [f["name"] for f in t.get("fields", [])]
    sensitive_patterns = ["password", "token", "secret", "credential", "ssn", "credit_card", "api_key"]
    sensitive_fields = []
    for t in user_types:
        for f in t.get("fields", []):
            if any(p in f["name"].lower() for p in sensitive_patterns):
                sensitive_fields.append({"type": t["name"], "field": f["name"]})
    return {
        "url": url,
        "introspection_enabled": True,
        "total_types": len(user_types),
        "queries": queries,
        "mutations": mutations,
        "sensitive_fields": sensitive_fields,
        "finding": "CRITICAL: Introspection enabled — full schema exposed" if user_types else "Schema empty",
        "types": [{"name": t["name"], "kind": t["kind"], "field_count": len(t.get("fields", []) or [])} for t in user_types][:50],
    }


def test_depth_limit(url, max_depth=10, headers=None):
    """Test for GraphQL query depth limits."""
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    results = []
    for depth in range(1, max_depth + 1):
        nested = "{ __typename " * depth + "}" * depth
        query = f"query {{ __schema {nested} }}"
        try:
            resp = requests.post(url, json={"query": query}, headers=hdrs, timeout=10)
            results.append({"depth": depth, "status": resp.status_code, "has_errors": "errors" in resp.json()})
        except Exception as e:
            results.append({"depth": depth, "error": str(e)})
            break
    max_allowed = max((r["depth"] for r in results if r.get("status") == 200), default=0)
    return {"url": url, "max_depth_tested": max_depth, "max_allowed_depth": max_allowed, "results": results}


def main():
    if not requests:
        print(json.dumps({"error": "requests not installed"}))
        return
    parser = argparse.ArgumentParser(description="GraphQL Introspection Attack Agent")
    sub = parser.add_subparsers(dest="command")
    i = sub.add_parser("introspect", help="Run introspection query")
    i.add_argument("--url", required=True, help="GraphQL endpoint URL")
    i.add_argument("--auth-header", help="Authorization header value")
    d = sub.add_parser("depth", help="Test query depth limits")
    d.add_argument("--url", required=True)
    d.add_argument("--max-depth", type=int, default=10)
    args = parser.parse_args()
    headers = {"Authorization": args.auth_header} if hasattr(args, "auth_header") and args.auth_header else None
    if args.command == "introspect":
        result = run_introspection(args.url, headers)
    elif args.command == "depth":
        result = test_depth_limit(args.url, args.max_depth, headers)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
