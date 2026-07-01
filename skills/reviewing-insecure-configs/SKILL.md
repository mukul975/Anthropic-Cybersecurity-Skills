---
name: reviewing-insecure-configs
description: >-
  Static configuration audit for Dangerous Configurations. Compares application configuration 
  files (YAML, JSON, XML, .env) against the Principle of Least Privilege. Detects enabled 
  debug modes, overly permissive CORS, unauthenticated Actuator/Admin endpoints, weak TLS, 
  and unsafe deserialization defaults.
domain: cybersecurity
subdomain: web-application-security
tags: [configuration-management, security-misconfiguration, whitebox, default-passwords]
mitre_attack: [T1588.006, T1580]
version: "1.0"
author: Victor
license: Apache-2.0
---

# Reviewing Insecure Configurations

## When to Use

- When auditing frameworks that rely heavily on configuration files (Spring Boot `application.yml`, Django `settings.py`, Express `config.json`, Laravel `.env`).
- When reviewing server blocks or proxy configurations (e.g., `nginx.conf`, Apache `.htaccess`, `docker-compose.yml`).
- When assessing an application for Security Misconfiguration (OWASP Top 10).

## Prerequisites

- Access to the application's source code and configuration manifests.
- The `grep_search` tool to locate specific configuration keys across the codebase.
- Note: Do NOT use this skill for searching hardcoded passwords or API keys. Route those tasks to `detecting-hardcoded-secrets`. This skill focuses on boolean flags, modes, and behavioral settings.

## Workflow

### Step 1: Locate Configuration Media
Identify where the application stores its settings:
- **Java**: `application.yml`, `bootstrap.yml`, `web.xml`, `server.xml`.
- **Python**: `settings.py`, `config.py`.
- **Node**: `.env`, `config/*.json`.
- **Infrastructure**: `nginx.conf`, `Dockerfile`, Kubernetes `ConfigMap` definitions.

### Step 2: Audit Debug and Verbosity Modes
Search for development modes left active in production profiles.
- **Django**: `DEBUG = True`
- **Spring**: `server.error.include-stacktrace: always`
- **Impact**: Exposes detailed stack traces, internal file paths, or SQL queries on error pages, aiding attackers in further exploitation.

### Step 3: Assess Actuator and Admin Interfaces
If the application uses Spring Boot Actuator or similar management interfaces:
- Check `management.endpoints.web.exposure.include`. If it is set to `*`, are these endpoints protected by Spring Security?
- **Impact**: Unauthenticated access to `/actuator/env` or `/actuator/heapdump` can leak database credentials and full application memory.

### Step 4: Audit CORS and Network Boundaries
Search for Cross-Origin Resource Sharing (CORS) configurations.
- Does the configuration allow `*` (all origins) while simultaneously allowing credentials (`Allow-Credentials: true`)? Note: Browsers block `*` with credentials, but developers often use regexes or dynamic reflection (`addAllowedOriginPattern("*")`) to bypass this browser protection, creating a severe vulnerability.
- **Impact**: Allows malicious websites to read authenticated data from the user's session.

### Step 5: Check Dangerous Framework Defaults
Evaluate framework-specific features that are known to be dangerous if left in their default state:
- **Jackson (Java)**: Is `enableDefaultTyping()` activated? This allows polymorphic deserialization, leading to RCE.
- **XML Parsers**: Is the `DocumentBuilderFactory` explicitly configured to disallow DOCTYPE declarations (`setFeature("...disallow-doctype-decl", true)`)? If not, it defaults to allowing XXE.

### Verification Phase
1. Establish baseline network responses and determine parameter contexts.
2. Inject specialized payloads specifically targeted at evaluating Reviewing Insecure Configurations.
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
| **Security Misconfiguration** | Insecure default settings, incomplete configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information. |
| **Profile-Specific Configurations** | Frameworks like Spring use profiles (e.g., `dev`, `staging`, `prod`) to load different configurations. Always audit the configuration files intended for the production environment. |

## Tools & Systems

- Burp Suite Professional / Community Edition
- Standard web browsers and interception proxies.

## Common Scenarios

### Scenario: The Hidden Override
**Context**: You audit `application.yml` and see `server.error.include-stacktrace: never`.
**Analysis**: You assume the application is secure from stack trace leaks.
**Action**: You must search the rest of the codebase. A developer might have added an `application-prod.yml` file, or a Kubernetes `deployment.yaml` might inject an environment variable (`SERVER_ERROR_INCLUDE_STACKTRACE=always`) that overrides the safe base configuration in production. Always determine the final precedence order.

### Scenario: Permissive File Uploads
**Context**: You are auditing `nginx.conf`.
**Analysis**: You check `client_max_body_size`. It is missing or set to an extremely large value (e.g., `500m`).
**Action**: While the application might have its own upload limits, the infrastructure layer is not enforcing a reasonable boundary. This misconfiguration can lead to resource exhaustion (Denial of Service) if attackers upload massive files.

## Output Format

Document dangerous configurations, specifying the file, the insecure value, and the recommended secure baseline:

```json
{
  "id": "config-001",
  "title": "Spring Boot Actuator Endpoints Exposed Unauthenticated",
  "severity": "high",
  "cwe": "CWE-1188",
  "file": "src/main/resources/application-prod.yml",
  "line": 24,
  "status": "confirmed",
  "evidence": {
    "source_code": "management:\\n  endpoints:\\n    web:\\n      exposure:\\n        include: '*'",
    "analysis": "The production configuration file exposes all Actuator endpoints to the web. Cross-referencing this with the Spring Security configuration reveals no authentication requirements for the /actuator/** path. This exposes sensitive endpoints like /env and /heapdump to the public internet."
  },
  "description": "A dangerous configuration setting exposes internal management endpoints without authentication, allowing attackers to extract environment variables, credentials, and memory dumps."
}
```
