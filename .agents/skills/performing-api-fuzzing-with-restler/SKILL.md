---
name: performing-api-fuzzing-with-restler
description: >
  Uses Microsoft RESTler to perform stateful REST API fuzzing by automatically generating
  and executing test sequences that exercise API endpoints, discover producer-consumer
  dependencies between requests, and find security and reliability bugs. The tester compiles
  an OpenAPI specification into a RESTler fuzzing grammar, configures authentication, runs
  test/fuzz-lean/fuzz modes, and analyzes results for 500 errors, authentication bypasses,
  resource leaks, and payload injection vulnerabilities. Activates for requests involving
  API fuzzing, RESTler testing, stateful API testing, or automated API security scanning.
domain: cybersecurity
subdomain: api-security
tags: [api-security, fuzzing, restler, automated-testing, openapi, stateful-testing]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Performing API Fuzzing with RESTler

## When to Use

- Performing automated security testing of REST APIs using their OpenAPI/Swagger specifications
- Discovering bugs that only manifest through specific sequences of API calls (stateful testing)
- Finding 500 Internal Server Error responses that indicate unhandled exceptions or crash conditions
- Testing API input validation by fuzzing parameters with malformed, boundary, and injection payloads
- Running continuous security regression testing in CI/CD pipelines for API changes

**Do not use** against production environments without explicit authorization and monitoring. RESTler creates and deletes resources aggressively during fuzzing.

## Prerequisites

- Written authorization specifying the target API and acceptable testing scope
- Python 3.12+ and .NET 8.0 runtime installed
- RESTler downloaded from https://github.com/microsoft/restler-fuzzer
- OpenAPI/Swagger specification (v2 or v3) for the target API
- API authentication credentials (tokens, API keys, or OAuth credentials)
- Isolated test/staging environment (RESTler can create thousands of resources per hour)

## Workflow

### Step 1: RESTler Installation and Setup

```bash
# Clone and build RESTler
git clone https://github.com/microsoft/restler-fuzzer.git
cd restler-fuzzer

# Build RESTler
python3 ./build-restler.py --dest_dir /opt/restler

# Verify installation
/opt/restler/restler/Restler --help

# Alternative: Use pre-built release
# Download from https://github.com/microsoft/restler-fuzzer/releases
```

### Step 2: Compile the API Specification

```bash
# Compile the OpenAPI spec into a RESTler fuzzing grammar
/opt/restler/restler/Restler compile \
    --api_spec /path/to/openapi.yaml

# Output directory structure:
# Compile/
#   grammar.py          - Generated fuzzing grammar
#   grammar.json        - Grammar in JSON format
#   dict.json           - Custom dictionary for fuzzing values
#   engine_settings.json - Engine configuration
#   config.json         - Compilation config
```

**Custom dictionary for targeted fuzzing (dict.json):**
```json
{
    "restler_fuzzable_string": [
        "fuzzstring",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "${7*7}",
        "{{7*7}}",
        "a]UNION SELECT 1,2,3--",
        "\"; cat /etc/passwd; echo \"",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    ],
    "restler_fuzzable_int": [
        "0",
        "-1",
        "999999999",
        "2147483647",
        "-2147483648"
    ],
    "restler_fuzzable_bool": ["true", "false", "null", "1", "0"],
    "restler_fuzzable_datetime": [
        "2024-01-01T00:00:00Z",
        "0000-00-00T00:00:00Z",
        "9999-12-31T23:59:59Z",
        "invalid-date"
    ],
    "restler_fuzzable_uuid4": [
        "00000000-0000-0000-0000-000000000000",
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    ],
    "restler_custom_payload": {
        "/users/{userId}": ["1", "0", "-1", "admin", "' OR 1=1--"],
        "/orders/{orderId}": ["1", "0", "999999999"]
    }
}
```

### Step 3: Configure Authentication

```python
# authentication_token.py - RESTler authentication module
import requests
import json
import time

class AuthenticationProvider:
    def __init__(self):
        self.token = None
        self.token_expiry = 0
        self.auth_url = "https://target-api.example.com/api/v1/auth/login"
        self.credentials = {
            "email": "fuzzer@test.com",
            "password": "FuzzerPass123!"
        }

    def get_token(self):
        """Get or refresh authentication token."""
        current_time = time.time()
        if self.token and current_time < self.token_expiry - 60:
            return self.token

        resp = requests.post(self.auth_url, json=self.credentials)
        if resp.status_code == 200:
            data = resp.json()
            self.token = data["access_token"]
            self.token_expiry = current_time + 3600  # Assume 1-hour TTL
            return self.token
        else:
            raise Exception(f"Authentication failed: {resp.status_code}")

    def get_auth_header(self):
        """Return the authentication header for RESTler."""
        token = self.get_token()
        return f"Authorization: Bearer {token}"

# Export the token refresh command for RESTler
auth = AuthenticationProvider()
print(auth.get_auth_header())
```

**Engine settings for authentication (engine_settings.json):**
```json
{
    "authentication": {
        "token": {
            "token_refresh_interval": 300,
            "token_refresh_cmd": "python3 /path/to/authentication_token.py"
        }
    },
    "max_combinations": 20,
    "max_request_execution_time": 30,
    "global_producer_timing_delay": 2,
    "no_ssl": false,
    "host": "target-api.example.com",
    "target_port": 443,
    "garbage_collection_interval": 300,
    "max_sequence_length": 10
}
```

### Step 4: Run RESTler in Test Mode (Smoke Test)

```bash
# Test mode: Quick validation that all endpoints are reachable
/opt/restler/restler/Restler test \
    --grammar_file Compile/grammar.py \
    --dictionary_file Compile/dict.json \
    --settings Compile/engine_settings.json \
    --no_ssl \
    --target_ip target-api.example.com \
    --target_port 443

# Review test results
cat Test/ResponseBuckets/runSummary.json
```

```python
# Parse test results
import json

with open("Test/ResponseBuckets/runSummary.json") as f:
    summary = json.load(f)

print("Test Mode Summary:")
print(f"  Total requests: {summary.get('total_requests_sent', {}).get('num_requests', 0)}")
print(f"  Successful (2xx): {summary.get('num_fully_valid', 0)}")
print(f"  Client errors (4xx): {summary.get('num_invalid', 0)}")
print(f"  Server errors (5xx): {summary.get('num_server_error', 0)}")

# Identify uncovered endpoints
covered = summary.get('covered_endpoints', [])
total = summary.get('total_endpoints', [])
uncovered = set(total) - set(covered)
if uncovered:
    print(f"\nUncovered endpoints ({len(uncovered)}):")
    for ep in uncovered:
        print(f"  - {ep}")
```

### Step 5: Run Fuzz-Lean Mode

```bash
# Fuzz-lean: One pass through all endpoints with security checkers enabled
/opt/restler/restler/Restler fuzz-lean \
    --grammar_file Compile/grammar.py \
    --dictionary_file Compile/dict.json \
    --settings Compile/engine_settings.json \
    --target_ip target-api.example.com \
    --target_port 443 \
    --time_budget 1  # 1 hour max

# Checkers automatically enabled in fuzz-lean:
# - UseAfterFree: Tests accessing resources after deletion
# - NamespaceRule: Tests accessing resources across namespaces/tenants
# - ResourceHierarchy: Tests child resources with wrong parent IDs
# - LeakageRule: Tests for information disclosure in error responses
# - InvalidDynamicObject: Tests with malformed dynamic object IDs
```

### Step 6: Run Full Fuzzing Mode

```bash
# Full fuzz mode: Extended fuzzing for comprehensive coverage
/opt/restler/restler/Restler fuzz \
    --grammar_file Compile/grammar.py \
    --dictionary_file Compile/dict.json \
    --settings Compile/engine_settings.json \
    --target_ip target-api.example.com \
    --target_port 443 \
    --time_budget 4 \
    --enable_checkers UseAfterFree NamespaceRule ResourceHierarchy LeakageRule InvalidDynamicObject PayloadBody

# Analyze fuzzing results
python3 <<'EOF'
import json
import os

results_dir = "Fuzz/ResponseBuckets"
bugs_dir = "Fuzz/bug_buckets"

# Parse bug buckets
if os.path.exists(bugs_dir):
    for bug_file in os.listdir(bugs_dir):
        if bug_file.endswith(".txt"):
            with open(os.path.join(bugs_dir, bug_file)) as f:
                content = f.read()
            print(f"\n=== Bug: {bug_file} ===")
            print(content[:500])

# Parse response summary
summary_file = os.path.join(results_dir, "runSummary.json")
if os.path.exists(summary_file):
    with open(summary_file) as f:
        summary = json.load(f)
    print(f"\nFuzz Summary:")
    print(f"  Duration: {summary.get('time_budget_hours', 0)} hours")
    print(f"  Total requests: {summary.get('total_requests_sent', {}).get('num_requests', 0)}")
    print(f"  Bugs found: {summary.get('num_bugs', 0)}")
    print(f"  500 errors: {summary.get('num_server_error', 0)}")
EOF
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Stateful Fuzzing** | API fuzzing that maintains state across requests by using responses from earlier requests as inputs to later ones, enabling testing of multi-step workflows |
| **Producer-Consumer Dependencies** | RESTler's inference that a value produced by one API call (e.g., a created resource ID) should be consumed by a subsequent call |
| **Fuzzing Grammar** | Compiled representation of the API specification that defines how to generate valid and invalid requests for each endpoint |
| **Checker** | RESTler security rule that tests for specific vulnerability patterns like use-after-free, namespace isolation, or information leakage |
| **Bug Bucket** | RESTler's categorization of discovered bugs by type and endpoint, grouping similar failures for efficient triage |
| **Garbage Collection** | RESTler's periodic cleanup of resources created during fuzzing to prevent resource exhaustion on the target system |

## Tools & Systems

- **RESTler**: Microsoft Research's stateful REST API fuzzing tool that compiles OpenAPI specs into fuzzing grammars
- **Schemathesis**: Property-based API testing tool that generates test cases from OpenAPI/GraphQL schemas
- **Dredd**: API testing tool that validates API implementations against OpenAPI/API Blueprint documentation
- **Fuzz-lightyear**: Yelp's stateless API fuzzer focused on finding authentication and authorization vulnerabilities
- **API Fuzzer**: OWASP tool for API endpoint fuzzing with customizable payload dictionaries

## Common Scenarios

### Scenario: Microservice API Fuzzing Campaign

**Context**: A fintech company has 12 microservice APIs with OpenAPI specifications. Before a major release, the security team runs RESTler fuzzing against each service in the staging environment to catch bugs.

**Approach**:
1. Collect OpenAPI specs for all 12 services and compile each into a RESTler grammar
2. Configure authentication for each service with service-specific credentials
3. Run test mode on each service to validate endpoint reachability and fix grammar issues
4. Run fuzz-lean mode (1 hour per service) to identify quick wins
5. Find 23 bugs in fuzz-lean mode: 8 unhandled 500 errors, 5 use-after-free patterns, 4 namespace isolation failures, 6 information leakage in error responses
6. Run full fuzz mode (4 hours per service) on the 5 services with the most bugs
7. Discover 47 additional bugs including a critical authentication bypass where deleting a user and reusing their token still allows access
8. Generate bug reports and track remediation through JIRA integration

**Pitfalls**:
- Running RESTler against production without understanding that it creates and deletes thousands of resources
- Not configuring authentication correctly, causing RESTler to only test unauthenticated access
- Using the default dictionary without adding application-specific injection payloads
- Not setting a time budget, allowing RESTler to run indefinitely
- Ignoring the compilation warnings that indicate endpoints RESTler cannot reach due to dependency issues

## Output Format

```
## RESTler API Fuzzing Report

**Target**: User Service API (staging.example.com)
**Specification**: OpenAPI 3.0 (42 endpoints)
**Duration**: 4 hours (full fuzz mode)
**Total Requests**: 145,832

### Bug Summary

| Category | Count | Severity |
|----------|-------|----------|
| 500 Internal Server Error | 12 | High |
| Use After Free | 3 | Critical |
| Namespace Rule Violation | 5 | Critical |
| Information Leakage | 8 | Medium |
| Resource Leak | 4 | Low |

### Critical Findings

**1. Use-After-Free: Deleted user token still valid**
- Sequence: POST /users -> DELETE /users/{id} -> GET /users/{id}
- After deleting user, GET with the deleted user's token returns 200
- Impact: Deleted accounts can still access the API

**2. Namespace Violation: Cross-tenant data access**
- Sequence: POST /users (tenant A) -> GET /users/{id} (tenant B token)
- User created by tenant A is accessible with tenant B's credentials
- Impact: Multi-tenant isolation breach

**3. 500 Error: Unhandled integer overflow**
- Request: POST /orders {"quantity": 2147483648}
- Response: 500 Internal Server Error with stack trace
- Impact: DoS potential, information disclosure via stack trace

### Coverage

- Endpoints covered: 38/42 (90.5%)
- Uncovered: POST /admin/migrate, DELETE /admin/cache,
  PUT /config/advanced, POST /webhooks/test
```
