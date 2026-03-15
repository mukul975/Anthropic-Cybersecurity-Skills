#!/usr/bin/env python3
"""Agent for performing GraphQL security assessment.

Tests GraphQL endpoints for introspection leaks, authorization flaws,
query depth/complexity DoS, and injection vulnerabilities.
"""

import requests
import json
import sys
from urllib.parse import urlparse


class GraphQLSecurityAgent:
    """Performs authorized security assessments on GraphQL endpoints."""

    def __init__(self, target_url, auth_token=None):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        if auth_token:
            self.session.headers["Authorization"] = f"Bearer {auth_token}"

    def _query(self, query, variables=None):
        """Send a GraphQL query and return the response."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        try:
            resp = self.session.post(self.target_url, json=payload, timeout=10)
            return {"status": resp.status_code, "body": resp.json()}
        except requests.RequestException as e:
            return {"status": 0, "error": str(e)}

    def test_introspection(self):
        """Test if introspection is enabled in production."""
        query = """{
            __schema {
                queryType { name }
                mutationType { name }
                types { name kind }
            }
        }"""
        result = self._query(query)
        has_schema = "data" in result.get("body", {}) and "__schema" in result.get("body", {}).get("data", {})
        types = []
        if has_schema:
            types = [t["name"] for t in result["body"]["data"]["__schema"].get("types", [])
                     if not t["name"].startswith("__")]
        return {
            "vulnerable": has_schema,
            "severity": "Medium",
            "finding": "Introspection enabled" if has_schema else "Introspection disabled",
            "types_exposed": len(types),
            "type_names": types[:20],
        }

    def test_query_depth(self, max_depth=10):
        """Test for query depth limiting."""
        nested = "{ __typename }"
        for i in range(max_depth):
            nested = f"{{ users {nested} }}"
        query = nested
        result = self._query(query)
        has_error = "errors" in result.get("body", {})
        return {
            "vulnerable": not has_error,
            "severity": "High" if not has_error else "Info",
            "depth_tested": max_depth,
            "finding": "No query depth limit" if not has_error else "Query depth limited",
        }

    def test_batch_queries(self):
        """Test if batch queries are accepted (rate limit bypass risk)."""
        batch = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ]
        try:
            resp = self.session.post(self.target_url, json=batch, timeout=10)
            body = resp.json()
            is_array = isinstance(body, list)
            return {
                "vulnerable": is_array,
                "severity": "High" if is_array else "Info",
                "finding": "Batch queries accepted" if is_array else "Batch queries rejected",
                "response_count": len(body) if is_array else 0,
            }
        except Exception as e:
            return {"vulnerable": False, "error": str(e)}

    def test_field_suggestions(self):
        """Test if field suggestions leak schema information."""
        query = "{ userzzzz }"
        result = self._query(query)
        errors = result.get("body", {}).get("errors", [])
        suggestions = []
        for err in errors:
            msg = err.get("message", "")
            if "did you mean" in msg.lower() or "suggest" in msg.lower():
                suggestions.append(msg)
        return {
            "vulnerable": len(suggestions) > 0,
            "severity": "Low",
            "finding": "Field suggestions enabled" if suggestions else "No field suggestions",
            "suggestions": suggestions,
        }

    def test_unauthorized_access(self):
        """Test queries without authentication token."""
        saved_auth = self.session.headers.pop("Authorization", None)
        queries = [
            ("{ __typename }", "basic_access"),
            ("{ users { id email } }", "user_listing"),
            ('{ user(id: "1") { id email role } }', "user_detail"),
        ]
        results = []
        for query, test_name in queries:
            result = self._query(query)
            has_data = "data" in result.get("body", {})
            has_null_data = has_data and all(
                v is None for v in result["body"]["data"].values()
            ) if has_data else False
            results.append({
                "test": test_name,
                "accessible": has_data and not has_null_data,
                "status": result.get("status"),
            })
        if saved_auth:
            self.session.headers["Authorization"] = saved_auth
        accessible_count = sum(1 for r in results if r["accessible"])
        return {
            "vulnerable": accessible_count > 0,
            "severity": "High" if accessible_count > 0 else "Info",
            "finding": f"{accessible_count} queries accessible without auth",
            "details": results,
        }

    def test_alias_overloading(self, count=50):
        """Test for alias-based resource exhaustion."""
        aliases = " ".join(f'a{i}: __typename' for i in range(count))
        query = f"{{ {aliases} }}"
        result = self._query(query)
        has_error = "errors" in result.get("body", {})
        return {
            "vulnerable": not has_error,
            "severity": "Medium" if not has_error else "Info",
            "aliases_tested": count,
            "finding": f"Accepted {count} aliases" if not has_error else "Alias limit enforced",
        }

    def run_full_assessment(self):
        """Run all security tests and generate a report."""
        report = {
            "target": self.target_url,
            "findings": [],
        }
        tests = [
            ("Introspection", self.test_introspection),
            ("Query Depth", self.test_query_depth),
            ("Batch Queries", self.test_batch_queries),
            ("Field Suggestions", self.test_field_suggestions),
            ("Unauthorized Access", self.test_unauthorized_access),
            ("Alias Overloading", self.test_alias_overloading),
        ]
        for test_name, test_fn in tests:
            result = test_fn()
            result["test_name"] = test_name
            report["findings"].append(result)

        vulnerable_count = sum(1 for f in report["findings"] if f.get("vulnerable"))
        report["summary"] = {
            "total_tests": len(report["findings"]),
            "vulnerabilities_found": vulnerable_count,
            "critical": sum(1 for f in report["findings"] if f.get("severity") == "Critical" and f.get("vulnerable")),
            "high": sum(1 for f in report["findings"] if f.get("severity") == "High" and f.get("vulnerable")),
            "medium": sum(1 for f in report["findings"] if f.get("severity") == "Medium" and f.get("vulnerable")),
            "low": sum(1 for f in report["findings"] if f.get("severity") == "Low" and f.get("vulnerable")),
        }
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <graphql_url> [auth_token]")
        sys.exit(1)

    target_url = sys.argv[1]
    auth_token = sys.argv[2] if len(sys.argv) > 2 else None
    agent = GraphQLSecurityAgent(target_url, auth_token)
    report = agent.run_full_assessment()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
