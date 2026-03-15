---
name: performing-api-security-testing-with-postman
description: >
  Uses Postman to perform structured API security testing by building collections that test
  for OWASP API Security Top 10 vulnerabilities including authentication bypass, authorization
  flaws, injection, and data exposure. The tester creates environments with multiple user
  roles, writes test scripts for automated security validation, and integrates Postman with
  OWASP ZAP and Newman for CI/CD security testing. Activates for requests involving Postman
  security testing, API security collection, automated API testing, or OWASP API testing with Postman.
domain: cybersecurity
subdomain: api-security
tags: [api-security, postman, owasp, automated-testing, security-validation]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Performing API Security Testing with Postman

## When to Use

- Building repeatable API security test suites for OWASP API Security Top 10 coverage
- Creating automated security regression tests that run in CI/CD pipelines via Newman
- Testing API authentication and authorization across multiple user roles systematically
- Integrating Postman with OWASP ZAP proxy for combined manual and automated security testing
- Establishing a baseline security test collection for new API endpoints before deployment

**Do not use** against production APIs without authorization. Postman security testing involves sending potentially malicious payloads.

## Prerequisites

- Postman Desktop or web application with an active workspace
- Target API with OpenAPI/Swagger specification for collection import
- Test accounts for at least three roles: unauthenticated, regular user, admin
- Newman CLI installed for CI/CD integration: `npm install -g newman`
- OWASP ZAP configured as local proxy (localhost:8080) for Postman proxy integration
- API environment variables for base URL, tokens, and test data

## Workflow

### Step 1: Environment and Collection Setup

Create Postman environments for multi-role testing:

```json
// Environment: API Security Test - Regular User
{
    "values": [
        {"key": "base_url", "value": "https://target-api.example.com/api/v1"},
        {"key": "auth_token", "value": ""},
        {"key": "user_email", "value": "regular@test.com"},
        {"key": "user_password", "value": "TestPass123!"},
        {"key": "user_id", "value": ""},
        {"key": "other_user_id", "value": "1002"},
        {"key": "admin_endpoint", "value": "/admin/users"},
        {"key": "test_order_id", "value": ""},
        {"key": "other_user_order_id", "value": "5003"}
    ]
}
```

**Pre-request script for automatic authentication:**
```javascript
// Collection-level pre-request script for auto-login
if (!pm.environment.get("auth_token") || pm.environment.get("token_expired")) {
    const loginRequest = {
        url: pm.environment.get("base_url") + "/auth/login",
        method: "POST",
        header: {"Content-Type": "application/json"},
        body: {
            mode: "raw",
            raw: JSON.stringify({
                email: pm.environment.get("user_email"),
                password: pm.environment.get("user_password")
            })
        }
    };

    pm.sendRequest(loginRequest, (err, res) => {
        if (!err && res.code === 200) {
            const token = res.json().access_token;
            pm.environment.set("auth_token", token);
            pm.environment.set("user_id", res.json().user.id);
        }
    });
}
```

### Step 2: BOLA (API1) Test Collection

```javascript
// Test: Access other user's profile (BOLA)
// Request: GET {{base_url}}/users/{{other_user_id}}
// Auth: Bearer {{auth_token}}

// Test script:
pm.test("BOLA: Cannot access other user profile", function() {
    pm.expect(pm.response.code).to.be.oneOf([401, 403]);
});

pm.test("BOLA: No user data leaked on denial", function() {
    if (pm.response.code === 200) {
        const body = pm.response.json();
        pm.expect(body).to.not.have.property("email");
        pm.expect(body).to.not.have.property("phone");
        pm.expect(body).to.not.have.property("address");
        // Flag as BOLA if full profile returned
        console.error("BOLA VULNERABILITY: Full profile returned for other user");
    }
});

// Test: Access other user's order
// Request: GET {{base_url}}/orders/{{other_user_order_id}}
pm.test("BOLA: Cannot access other user order", function() {
    pm.expect(pm.response.code).to.be.oneOf([401, 403, 404]);
});

// Test: Modify other user's resource
// Request: PATCH {{base_url}}/users/{{other_user_id}}
// Body: {"name": "Hacked"}
pm.test("BOLA: Cannot modify other user profile", function() {
    pm.expect(pm.response.code).to.be.oneOf([401, 403]);
});
```

### Step 3: Authentication (API2) Test Collection

```javascript
// Test: Token validation
// Request: GET {{base_url}}/users/me
// Auth: Bearer invalid_token_value

pm.test("Auth: Invalid token rejected", function() {
    pm.expect(pm.response.code).to.be.oneOf([401, 403]);
});

// Test: Expired token handling
// Request: GET {{base_url}}/users/me
// Auth: Bearer {{expired_token}}

pm.test("Auth: Expired token rejected", function() {
    pm.expect(pm.response.code).to.equal(401);
});

// Test: Missing authentication
// Request: GET {{base_url}}/users/me
// Auth: None

pm.test("Auth: Unauthenticated request rejected", function() {
    pm.expect(pm.response.code).to.equal(401);
});

// Test: SQL injection in login
// Request: POST {{base_url}}/auth/login
// Body: {"email": "' OR 1=1--", "password": "test"}

pm.test("Auth: SQLi in login rejected", function() {
    pm.expect(pm.response.code).to.not.equal(200);
    pm.expect(pm.response.text()).to.not.include("token");
});

// Test: Account enumeration
// Pre-request: Send login with valid email + wrong password, then invalid email + wrong password
pm.test("Auth: No account enumeration", function() {
    // Compare with stored response from valid email attempt
    const validEmailResponse = pm.environment.get("valid_email_response");
    const currentResponse = pm.response.text();
    pm.expect(currentResponse).to.equal(validEmailResponse);
});
```

### Step 4: Data Exposure (API3) and BFLA (API5) Tests

```javascript
// Test: Excessive data exposure check
// Request: GET {{base_url}}/users/me

pm.test("Data Exposure: No sensitive fields in response", function() {
    const sensitiveFields = [
        "password", "password_hash", "passwordHash",
        "ssn", "social_security", "credit_card",
        "api_key", "secret_key", "mfa_secret",
        "refresh_token", "session_id"
    ];
    const responseText = pm.response.text().toLowerCase();
    sensitiveFields.forEach(field => {
        pm.expect(responseText).to.not.include('"' + field + '"');
    });
});

pm.test("Data Exposure: Security headers present", function() {
    pm.expect(pm.response.headers.has("X-Content-Type-Options")).to.be.true;
    pm.expect(pm.response.headers.has("X-Frame-Options")).to.be.true;
    pm.expect(pm.response.headers.get("X-Content-Type-Options")).to.equal("nosniff");
});

pm.test("Data Exposure: No server info leaked", function() {
    pm.expect(pm.response.headers.has("Server")).to.be.false;
    pm.expect(pm.response.headers.has("X-Powered-By")).to.be.false;
});

// Test: BFLA - Admin endpoint access
// Request: GET {{base_url}}{{admin_endpoint}}
// Auth: Bearer {{auth_token}} (regular user)

pm.test("BFLA: Regular user cannot access admin endpoint", function() {
    pm.expect(pm.response.code).to.be.oneOf([401, 403]);
});

// Test: BFLA - Admin function execution
// Request: DELETE {{base_url}}/users/{{other_user_id}}
// Auth: Bearer {{auth_token}} (regular user)

pm.test("BFLA: Regular user cannot delete other users", function() {
    pm.expect(pm.response.code).to.be.oneOf([401, 403]);
});
```

### Step 5: Mass Assignment and Rate Limiting Tests

```javascript
// Test: Mass assignment via profile update
// Request: PUT {{base_url}}/users/me
// Body: {"name": "Test", "role": "admin", "is_admin": true}

pm.test("Mass Assignment: Role field not accepted", function() {
    if (pm.response.code === 200) {
        const user = pm.response.json();
        pm.expect(user.role).to.not.equal("admin");
        pm.expect(user.is_admin).to.not.equal(true);
    }
});

// Test: Rate limiting enforcement
// This test should be run with the Collection Runner at high iteration count

pm.test("Rate Limiting: Returns 429 when limit exceeded", function() {
    // This test expects to be rate-limited after many iterations
    const iterationCount = pm.info.iteration;
    if (iterationCount > 50) {
        // After 50 iterations, we should see rate limiting
        if (pm.response.code === 429) {
            pm.expect(pm.response.headers.has("Retry-After")).to.be.true;
            console.log("Rate limiting enforced at iteration " + iterationCount);
        }
    }
});

// Test: Rate limit headers present
pm.test("Rate Limiting: Rate limit headers present", function() {
    const hasRateHeaders = pm.response.headers.has("X-RateLimit-Limit") ||
                           pm.response.headers.has("X-Rate-Limit-Limit") ||
                           pm.response.headers.has("RateLimit-Limit");
    pm.expect(hasRateHeaders).to.be.true;
});
```

### Step 6: Newman CI/CD Integration

```bash
# Run security test collection via Newman CLI
newman run "API-Security-Tests.postman_collection.json" \
    --environment "Security-Test-Environment.postman_environment.json" \
    --reporters cli,htmlextra,junit \
    --reporter-htmlextra-export ./reports/security-test-report.html \
    --reporter-junit-export ./reports/security-test-results.xml \
    --iteration-count 1 \
    --timeout-request 10000 \
    --delay-request 100 \
    --bail

# Run with different user roles
for role in "regular_user" "admin_user" "unauthenticated"; do
    echo "Testing with role: $role"
    newman run "API-Security-Tests.postman_collection.json" \
        --environment "Security-Test-${role}.postman_environment.json" \
        --reporters cli,junit \
        --reporter-junit-export "./reports/security-${role}.xml"
done
```

**GitHub Actions Integration:**
```yaml
# .github/workflows/api-security-test.yml
name: API Security Tests
on:
  pull_request:
    paths: ['src/api/**', 'openapi.yaml']

jobs:
  security-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install -g newman newman-reporter-htmlextra
      - name: Run API Security Tests
        run: |
          newman run tests/postman/api-security.json \
            --environment tests/postman/env-staging.json \
            --reporters cli,htmlextra,junit \
            --reporter-htmlextra-export reports/security.html \
            --reporter-junit-export reports/security.xml
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-reports
          path: reports/
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Postman Collection** | Organized group of API requests with test scripts that can be shared, version-controlled, and executed automatically |
| **Newman** | Command-line companion for Postman that enables running collections in CI/CD pipelines and generating test reports |
| **Pre-request Script** | JavaScript code that executes before a Postman request, used for dynamic authentication and test data setup |
| **Test Script** | JavaScript code that executes after a Postman response, used to validate security assertions against the response |
| **Collection Runner** | Postman feature that executes all requests in a collection sequentially with configurable iterations and delays |
| **Environment Variables** | Key-value pairs scoped to a Postman environment that parameterize requests for different targets, roles, and configurations |

## Tools & Systems

- **Postman**: API platform for building, testing, and documenting APIs with built-in scripting and collection management
- **Newman**: CLI runner for Postman collections supporting multiple reporters (HTML, JUnit, JSON) for CI/CD integration
- **OWASP ZAP**: Open-source security proxy that can be configured as Postman's proxy to scan all requests passively
- **newman-reporter-htmlextra**: Enhanced HTML reporter for Newman that generates detailed test reports with request/response data
- **Postman Flows**: Visual workflow builder for chaining complex security test sequences with conditional logic

## Common Scenarios

### Scenario: API Security Regression Suite for CI/CD

**Context**: A development team releases API updates bi-weekly. They need an automated security test suite that runs on every pull request to catch authorization and authentication regressions before merge.

**Approach**:
1. Import the OpenAPI spec into Postman to generate a base collection with all endpoints
2. Create three environments: unauthenticated, regular user, admin with appropriate credentials
3. Add security test scripts to each request: BOLA checks, auth validation, data exposure scanning, header security
4. Create a dedicated "Security Tests" folder with injection payloads, mass assignment tests, and rate limit checks
5. Export the collection and environments to the repository
6. Configure Newman in GitHub Actions to run on every PR affecting API code
7. Set the pipeline to fail on any security test failure, blocking the merge

**Pitfalls**:
- Hardcoding authentication tokens in collections instead of using pre-request scripts for dynamic token generation
- Not testing with all user roles - only testing authenticated vs unauthenticated misses role-based authorization issues
- Running security tests against production instead of staging environments
- Not updating the collection when new endpoints are added, leaving gaps in coverage
- Ignoring Newman exit codes in CI/CD, allowing failing security tests to pass silently

## Output Format

```
## API Security Test Report - Postman/Newman

**Collection**: API Security Tests v2.3
**Environment**: Staging - Regular User
**Date**: 2024-12-15
**Total Requests**: 85
**Total Tests**: 234
**Passed**: 219
**Failed**: 15

### Failed Tests Summary

| # | Request | Test Name | Severity |
|---|---------|-----------|----------|
| 1 | GET /users/1002 | BOLA: Cannot access other user profile | Critical |
| 2 | GET /orders/5003 | BOLA: Cannot access other user order | Critical |
| 3 | GET /admin/users | BFLA: Regular user cannot access admin endpoint | Critical |
| 4 | PUT /users/me | Mass Assignment: Role field not accepted | High |
| 5 | GET /users/me | Data Exposure: No sensitive fields in response | High |
| 6 | POST /auth/login | Auth: No account enumeration | Medium |
| ... | ... | ... | ... |

### Recommendations
1. Fix BOLA on /users/{id} and /orders/{id} - add object-level authorization checks
2. Fix BFLA on /admin/users - enforce role-based access control middleware
3. Fix mass assignment on PUT /users/me - implement field allowlist
4. Remove password_hash and mfa_secret from user serialization
5. Standardize login error messages to prevent account enumeration
```
