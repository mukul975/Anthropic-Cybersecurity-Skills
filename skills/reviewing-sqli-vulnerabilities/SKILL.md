---
name: reviewing-sqli-vulnerabilities
description: >-
  Comprehensive multi-strategy detection for SQL Injection (SQLi) vulnerabilities.
  Covers Boolean-based blind, Time-based blind, Error-based, and UNION-based injections
  across major DBMS platforms. Activates when parameter manipulation causes response
  mutations, database errors, or controllable time delays.
domain: cybersecurity
subdomain: web-application-security
tags: [sqli, penetration-testing, web-vulnerability, injection, database]
mitre_attack: [T1190]
version: "1.0"
author: Victor
license: Apache-2.0
---

# Reviewing SQL Injection Vulnerabilities

## When to Use

- When observing HTTP response anomalies (status changes, content diffs) triggered by quotes (`'`, `"`) or SQL control characters in query parameters, headers, or JSON bodies.
- When an application responds with verbose database error messages (e.g., `SQL syntax`, `ORA-`, `Unclosed quotation mark`).
- When different logic states (`1=1` vs `1=2`) yield consistently distinguishable responses.
- When you suspect a search, filter, sorting (`ORDER BY`), or data modification endpoint lacks input sanitization.

**Do not use** destructive commands (e.g., `DROP TABLE`, `DELETE`) to verify vulnerabilities in production environments.

## Prerequisites

- Traffic capture tools (e.g., Burp Suite, ZAP, or HAR files) to observe baseline requests.
- Access to the target application endpoints.
- Basic understanding of target backend stack (DBMS and framework) inferred from headers or error signatures.
- Out-of-Band (OOB) testing infrastructure (e.g., Burp Collaborator, interactsh) if testing blind/OOB vectors.

## Workflow

### Step 0: Baseline Collection
1. Send the unmodified request 2-3 times to establish a "Baseline Response Profile" (status code, content length, average response time).
2. Identify dynamic fields (timestamps, CSRF tokens) that change naturally and exclude them from difference analysis.

### Step 1: Context and Closure Fuzzing
Isolate parameters and test them **one at a time**.
Append SQL syntax characters to the parameter to break the query context:
- Quote probing: `'`, `"`, `\'`, `\"`
- Parenthesis probing: `)`, `))`, `')`
- Comment probing: `-- `, `#` (MySQL), `/*`

**Goal**: Look for a syntax error, a 500 Internal Server Error, or a sudden change in response length.

### Step 2: Fingerprint the DBMS
Analyze the response characteristics to tailor your payloads:
- `You have an error in your SQL syntax` / `MySQL` $\rightarrow$ MySQL/MariaDB
- `syntax error at or near` / `PostgreSQL` $\rightarrow$ PostgreSQL
- `Unclosed quotation mark` / `SQL Server` / `ODBC` $\rightarrow$ MSSQL
- `ORA-` $\rightarrow$ Oracle

### Step 3: Injection Strategy Selection
Based on the anomaly observed in Step 1, select the appropriate exploitation strategy:

#### Strategy A: Error-Based Injection
If verbose errors are returned, use functions to extract data within the error message.
- **MySQL**: `AND extractvalue(1,concat(0x7e,(SELECT database())))`
- **MSSQL**: `AND 1=(SELECT @@version)`

#### Strategy B: UNION-Based Injection
If the query results are reflected directly on the page, use `ORDER BY` to find the column count, then inject `UNION SELECT`.
1. `ORDER BY 1`, `ORDER BY 2`... until it errors (determines column count `N`).
2. `UNION SELECT 1,2,3...N` (find which columns echo in the response).
3. `UNION SELECT 1,database(),3...N`.

#### Strategy C: Boolean-Based Blind Injection
If the response contents change consistently based on truth conditions but no errors are shown.
- Test `AND 1=1` (should match baseline).
- Test `AND 1=2` (should show "not found" or missing content).
- Extract data: `AND SUBSTRING(database(),1,1)='a'`

#### Strategy D: Time-Based Blind Injection
If responses are identical regardless of input, test for time delays. **Warning: Slow.**
- **MySQL**: `AND SLEEP(5)`
- **PostgreSQL**: `AND 1=(SELECT 1 FROM pg_sleep(5))`
- **MSSQL**: `WAITFOR DELAY '0:0:5'`
*Verify by ensuring the delay equals the baseline time + 5 seconds consistently across 3 attempts.*

### Step 4: Verification and Proof of Concept
A vulnerability is only **Confirmed** if you have observable evidence:
- Reliable extraction of `database()`, `@@version`, or `user()`.
- A time delay that is statistically significant and exclusively triggered by the payload.
- OOB DNS/HTTP interaction containing a unique token.

### Verification Phase
1. Establish baseline network responses and determine parameter contexts.
2. Inject specialized payloads specifically targeted at evaluating Reviewing SQL Injection Vulnerabilities.
3. Analyze HTTP response headers, status codes, and out-of-band signals.

```bash
# Verify endpoint response behavior under inspection payload
curl -i -s -k -X POST "https://target.example.com/api/v1/inspect" \
     -H "Content-Type: application/json" \
     -d '{"parameter": "test_payload"}'
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Observation Channel** | The specific mechanism through which the SQLi is verified (e.g., `error-echo`, `boolean-diff`, `time-sidechannel`, `oob-dns`). |
| **Second-Order Injection** | A payload that is safely inserted into the database but triggers an injection when read and used in a subsequent query elsewhere in the application. |
| **Stacked Queries** | Using a semicolon (`;`) to terminate the current statement and execute an entirely new one (e.g., `1; DROP TABLE users--`). Common in MSSQL/PostgreSQL, but disabled by default in modern MySQL PHP/Java drivers. |

## Tools & Systems

- Burp Suite Professional / Community Edition
- Standard web browsers and interception proxies.

## Common Scenarios

### Scenario: False Positive - WAF Blocking
**Context**: Appending a single quote (`'`) to a parameter changes the response from HTTP 200 to HTTP 403.
**Analysis**: The change isn't caused by a database syntax error, but by a Web Application Firewall (WAF) matching the quote character.
**Action**: Remove the quote but inject a harmless SQL keyword with mixed casing (e.g., `sElEcT`). If blocked, it's a WAF. Try encoding techniques (e.g., URL encoding, chunked transfer) or confirm as a False Positive for SQLi.

### Scenario: False Negative - `ORDER BY` Clause
**Context**: A `?sort=createdAt` parameter does not respond to `'` or `SLEEP()`.
**Analysis**: `ORDER BY` clauses cannot be parameterized with placeholders (`?`). They must use strict whitelisting. Appending strings directly into `ORDER BY` often causes silent failures if wrapped in quotes.
**Action**: Inject a conditional expression directly: `?sort=(CASE WHEN 1=1 THEN createdAt ELSE id END)`. If the sorting order changes based on the condition, it is vulnerable.

### Scenario: Second-Order Injection
**Context**: An email address containing `'` is registered without error.
**Analysis**: The application uses parameterized queries for `INSERT`, so the registration is safe. However, an internal Admin dashboard might concatenate the stored email into a `SELECT` query.
**Action**: Track data flow. Register a payload and log into the portal where the data is rendered or processed.

## Output Format

Document confirmed vulnerabilities with explicit observation channel evidence:

```json
{
  "id": "sqli-001",
  "title": "Boolean-based Blind SQL Injection in /api/products",
  "severity": "critical",
  "cwe": "CWE-89",
  "parameter": "category_id (Query String)",
  "observation_channel": "boolean-diff",
  "status": "confirmed",
  "evidence": {
    "payload_true": "category_id=5 AND 1=1",
    "response_true": "Returns 12 product JSON objects (Status 200)",
    "payload_false": "category_id=5 AND 1=2",
    "response_false": "Returns 0 product JSON objects (Status 200)"
  },
  "description": "The category_id parameter is vulnerable to boolean-based blind SQL injection, allowing unauthorized data extraction."
}
```
