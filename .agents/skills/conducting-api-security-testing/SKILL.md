---
name: conducting-api-security-testing
description: >
  Conducts security testing of REST, GraphQL, and gRPC APIs to identify vulnerabilities in
  authentication, authorization, rate limiting, input validation, and business logic. The tester
  uses the OWASP API Security Top 10 as the testing framework, combining Burp Suite interception
  with Postman collections and custom scripts to test endpoint security at every privilege level.
  Activates for requests involving API security testing, REST API pentest, GraphQL security
  assessment, or API vulnerability testing.
domain: cybersecurity
subdomain: penetration-testing
tags: [API-security, OWASP-API-Top10, REST, GraphQL, authorization-testing]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Conducting API Security Testing

## When to Use

- Testing API endpoints for authorization flaws, injection vulnerabilities, and business logic bypasses
- Assessing the security of microservices architecture where APIs are the primary communication method
- Validating that API gateway protections (rate limiting, authentication, input validation) are properly enforced
- Testing third-party API integrations for data exposure and insecure configurations
- Evaluating GraphQL APIs for introspection disclosure, query complexity attacks, and authorization bypasses

**Do not use** against APIs without written authorization, for load testing or denial-of-service testing unless explicitly scoped, or for testing production APIs that process real financial transactions without safeguards.

## Prerequisites

- API documentation (OpenAPI/Swagger, GraphQL schema, Postman collection) or application access to reverse-engineer the API
- Burp Suite Professional configured to intercept API traffic with JSON/XML content type handling
- Postman or Insomnia for organizing and replaying API requests across different authentication contexts
- Valid API tokens or credentials at multiple privilege levels (unauthenticated, standard user, admin)
- Target API base URL and version information

## Workflow

### Step 1: API Discovery and Documentation

Map the complete API attack surface:

- **Import API documentation**: Load OpenAPI/Swagger specs into Postman or Burp Suite to catalog all endpoints, methods, parameters, and authentication requirements
- **Reverse-engineer undocumented APIs**: Proxy the mobile app or web frontend through Burp Suite and exercise all features to capture API calls. Export the Burp sitemap as the baseline endpoint inventory.
- **GraphQL introspection**: Send an introspection query to discover the full schema:
  ```json
  {"query": "{__schema{types{name,fields{name,args{name,type{name}}}}}}"}
  ```
- **Endpoint enumeration**: Fuzz for hidden API versions (`/api/v1/`, `/api/v2/`, `/api/internal/`), debug endpoints (`/api/debug`, `/api/health`, `/api/metrics`), and administrative endpoints
- **Document authentication mechanisms**: Identify if the API uses API keys, OAuth 2.0 Bearer tokens, JWT, session cookies, or mutual TLS

### Step 2: Authentication and Token Testing

Test authentication mechanisms for weaknesses:

- **JWT analysis**: Decode the JWT and inspect claims (sub, exp, iss, aud, role). Test:
  - Algorithm confusion: Change `alg` to `none` and remove the signature
  - Key confusion: Change `alg` from RS256 to HS256 and sign with the public key
  - Weak secret: Brute-force the HMAC secret with `hashcat -m 16500 jwt.txt wordlist.txt`
  - Token expiration: Verify tokens expire and cannot be used after expiration
  - Claim tampering: Modify role, userId, or permission claims and re-sign
- **OAuth 2.0 testing**: Check for redirect_uri manipulation, authorization code reuse, token leakage in Referer headers, and missing state parameter (CSRF)
- **API key security**: Test if API keys are validated per-endpoint, if revoked keys are immediately rejected, and if keys in query strings appear in access logs or analytics

### Step 3: Authorization Testing (BOLA/BFLA)

Test for Broken Object Level Authorization (BOLA) and Broken Function Level Authorization (BFLA):

- **BOLA (IDOR) testing**: For every endpoint that returns user-specific data, replace the object identifier with another user's identifier:
  - `GET /api/users/123/orders` -> `GET /api/users/456/orders`
  - Test with numeric IDs, UUIDs, usernames, and email addresses
  - Automate with Burp Autorize extension: configure it with two sessions (attacker and victim) and replay all requests
- **BFLA testing**: Using a low-privilege token, attempt to access administrative endpoints:
  - `DELETE /api/users/456` (admin-only delete)
  - `PUT /api/users/456/role` (role modification)
  - `GET /api/admin/dashboard` (admin panel data)
- **Mass assignment**: Send additional JSON properties not shown in the documentation:
  ```json
  PUT /api/users/123
  {"name": "Test", "role": "admin", "isVerified": true, "balance": 99999}
  ```
- **HTTP method testing**: If GET works on an endpoint, try PUT, PATCH, DELETE, and OPTIONS to discover unprotected methods

### Step 4: Input Validation and Injection Testing

Test API inputs for injection and validation flaws:

- **SQL injection in API parameters**: Test all parameters (path, query, body, headers) with SQL injection payloads. JSON APIs are often overlooked: `{"username": "admin' OR 1=1--", "password": "test"}`
- **NoSQL injection**: For MongoDB backends, test with operator injection: `{"username": {"$gt": ""}, "password": {"$gt": ""}}`
- **SSRF via API**: Test any parameter that accepts URLs (webhook URLs, avatar URLs, import endpoints) with internal addresses and cloud metadata endpoints
- **GraphQL-specific injection**: Test for query depth attacks, alias-based batching for brute force, and field suggestion enumeration
- **XXE in XML APIs**: Submit XML content with external entity declarations to API endpoints that accept XML
- **Rate limiting validation**: Send 100+ rapid requests to authentication endpoints, password reset, and OTP verification to test for brute force protection

### Step 5: Data Exposure and Response Analysis

Check for excessive data exposure in API responses:

- **Verbose responses**: Compare the data returned in API responses with what the UI displays. APIs often return more fields than needed (internal IDs, creation timestamps, email addresses of other users, role information).
- **Error message analysis**: Trigger errors by sending malformed input, invalid tokens, and non-existent resources. Check if error messages reveal stack traces, database queries, internal paths, or technology details.
- **Pagination and enumeration**: Test if enumeration is possible by iterating through paginated responses (`/api/users?page=1`, `page=2`, etc.) to extract all records
- **GraphQL data exposure**: Query for fields not intended for the current user's role. Test nested queries that traverse relationships to access unauthorized data.
- **Debug endpoints**: Check `/api/debug`, `/api/status`, `/metrics`, `/health`, `/.env`, `/api/swagger.json` for exposed internal information

## Key Concepts

| Term | Definition |
|------|------------|
| **BOLA** | Broken Object Level Authorization (OWASP API #1); failure to verify that the requesting user is authorized to access a specific object, enabling IDOR attacks |
| **BFLA** | Broken Function Level Authorization (OWASP API #5); failure to restrict administrative or privileged API functions from being accessed by lower-privilege users |
| **Mass Assignment** | A vulnerability where the API binds client-provided data to internal object properties without filtering, allowing attackers to modify fields they should not have access to |
| **GraphQL Introspection** | A built-in GraphQL feature that exposes the complete API schema including all types, fields, and relationships; should be disabled in production |
| **JWT** | JSON Web Token; a self-contained token format used for API authentication containing claims signed with a secret or key pair |
| **Rate Limiting** | Controls that restrict the number of API requests a client can make within a time window, preventing brute force, enumeration, and abuse |

## Tools & Systems

- **Burp Suite Professional**: HTTP proxy for intercepting, modifying, and replaying API requests with extensions like Autorize for automated authorization testing
- **Postman**: API development platform used for organizing endpoint collections, scripting tests, and comparing responses across authentication contexts
- **GraphQL Voyager**: Visual tool for exploring GraphQL schemas obtained through introspection queries
- **jwt.io / jwt_tool**: Tools for decoding, analyzing, and tampering with JWT tokens to test authentication bypasses
- **Nuclei**: Template-based scanner with API-specific templates for detecting common misconfigurations and known vulnerabilities

## Common Scenarios

### Scenario: API Security Assessment for a Fintech Mobile Application

**Context**: A fintech startup has a mobile banking application with a REST API backend. The API handles account management, fund transfers, bill payments, and transaction history. The tester has Swagger documentation and accounts at user and admin levels.

**Approach**:
1. Import Swagger spec into Postman, generating 87 endpoint collections across 12 controllers
2. Discover BOLA on `/api/v1/accounts/{accountId}/transactions` allowing any authenticated user to view any account's transaction history
3. Find mass assignment on the user update endpoint where adding `"dailyTransferLimit": 999999` bypasses the configured transfer limit
4. Identify that the fund transfer endpoint lacks rate limiting, allowing unlimited transfer attempts without throttling
5. Discover that JWT tokens have a 30-day expiration with no refresh token rotation, enabling long-lived session hijacking
6. Find that the admin endpoint `/api/v1/admin/users` is accessible with a standard user token (BFLA)
7. Report all findings with CVSS scores and specific API code-level remediation guidance

**Pitfalls**:
- Testing only the endpoints documented in Swagger and missing undocumented or deprecated API versions
- Not testing the same endpoint with tokens from every privilege level to detect authorization bypasses
- Ignoring response body analysis for excessive data exposure when the UI only shows a subset of returned fields
- Failing to test for mass assignment by only sending fields shown in the documentation

## Output Format

```
## Finding: Broken Object Level Authorization in Transaction History API

**ID**: API-001
**Severity**: Critical (CVSS 9.1)
**Affected Endpoint**: GET /api/v1/accounts/{accountId}/transactions
**OWASP API Category**: API1:2023 - Broken Object Level Authorization

**Description**:
The transaction history endpoint returns all transactions for the specified
account without verifying that the authenticated user owns the account. Any
authenticated user can view the complete transaction history of any account
by substituting the accountId path parameter.

**Proof of Concept**:
1. Authenticate as User A (account ID: ACC-10045)
2. Request: GET /api/v1/accounts/ACC-10046/transactions
   Authorization: Bearer <User_A_token>
3. Response: 200 OK with User B's full transaction history

**Impact**:
Any authenticated user can view the complete financial transaction history of
all 45,000 customer accounts, including amounts, dates, recipients, and
transaction descriptions.

**Remediation**:
Implement server-side authorization check that verifies the authenticated user
owns the requested account before returning data:
  const account = await Account.findById(accountId);
  if (account.userId !== req.user.id) return res.status(403).json({error: "Forbidden"});
```
