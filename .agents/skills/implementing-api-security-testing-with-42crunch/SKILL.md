---
name: implementing-api-security-testing-with-42crunch
description: Implement comprehensive API security testing using the 42Crunch platform to perform static audit and dynamic conformance scanning of OpenAPI specifications.
domain: cybersecurity
subdomain: api-security
tags: [api-security, 42crunch, openapi, api-audit, api-scan, conformance-testing, shift-left, ci-cd-security, owasp-api-top-10]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing API Security Testing with 42Crunch

## Overview

42Crunch is an API security platform that combines Shift-Left security testing with Shield-Right runtime protection. It provides API Audit for static security analysis of OpenAPI definitions, API Conformance Scan for dynamic vulnerability detection, and API Protect for real-time threat prevention. The platform integrates into CI/CD pipelines and IDEs to identify OWASP API Security Top 10 vulnerabilities before and after deployment.

## Prerequisites

- 42Crunch platform account (free tier available for evaluation)
- OpenAPI Specification (OAS) v2.0, v3.0, or v3.1 definitions for target APIs
- IDE with 42Crunch extension (VS Code, IntelliJ, or Eclipse)
- CI/CD pipeline (Jenkins, GitHub Actions, Azure DevOps, or GitLab CI)
- Running API instance for dynamic scanning (conformance scan)
- Node.js or Python environment for CLI tooling

## Core Concepts

### API Audit (Static Analysis)

API Audit performs static security analysis of OpenAPI definitions without requiring a running API. It evaluates the specification against 300+ security checks organized into categories:

**Security Score Categories:**
- **Data Validation**: Schema definitions, parameter constraints, response validation
- **Authentication**: Security scheme definitions, scope requirements
- **Transport Security**: Server URL schemes, TLS requirements
- **Error Handling**: Error response definitions, information leakage prevention

**Running API Audit via VS Code Extension:**

1. Install the 42Crunch extension from the VS Code marketplace
2. Open an OpenAPI specification file (YAML or JSON)
3. Click the security audit icon in the editor toolbar
4. Review the security score (0-100) and individual findings
5. Address issues using the inline remediation guidance

**Example OpenAPI Definition with Security Controls:**

```yaml
openapi: 3.0.3
info:
  title: Secure User API
  version: 1.0.0
servers:
  - url: https://api.example.com/v1
    description: Production server (HTTPS only)
security:
  - BearerAuth: []
paths:
  /users/{userId}:
    get:
      operationId: getUserById
      summary: Retrieve user by ID
      parameters:
        - name: userId
          in: path
          required: true
          schema:
            type: string
            format: uuid
            pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            maxLength: 36
      responses:
        '200':
          description: User details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
        '400':
          description: Invalid request
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        '401':
          description: Unauthorized
        '404':
          description: User not found
components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
  schemas:
    User:
      type: object
      required:
        - id
        - email
      properties:
        id:
          type: string
          format: uuid
          readOnly: true
        email:
          type: string
          format: email
          maxLength: 254
        name:
          type: string
          maxLength: 100
          pattern: '^[a-zA-Z\s\-]+$'
      additionalProperties: false
    Error:
      type: object
      required:
        - code
        - message
      properties:
        code:
          type: integer
          format: int32
        message:
          type: string
          maxLength: 256
      additionalProperties: false
```

### API Conformance Scan (Dynamic Testing)

The conformance scan dynamically tests a running API against its OpenAPI contract to detect runtime vulnerabilities including OWASP API Security Top 10 issues:

**Scan v2 Configuration:**

```yaml
# 42c-conf.yaml
version: "2.0"
scan:
  target:
    url: https://api.example.com/v1
  authentication:
    - type: bearer
      token: "${API_TOKEN}"
      in: header
      name: Authorization
  settings:
    maxScanTime: 3600
    requestsPerSecond: 10
    followRedirects: false
  tests:
    owasp:
      - bola
      - bfla
      - injection
      - ssrf
      - massAssignment
      - excessiveDataExposure
```

**Running Conformance Scan via CLI:**

```bash
# Install the 42Crunch CLI
npm install -g @42crunch/cicd-cli

# Run conformance scan
42crunch-cli scan \
  --api-definition ./openapi.yaml \
  --target-url https://api.example.com/v1 \
  --token $CRUNCH_TOKEN \
  --min-score 70 \
  --report-format sarif \
  --output scan-report.sarif
```

### CI/CD Pipeline Integration

**GitHub Actions Integration:**

```yaml
name: API Security Testing
on:
  push:
    paths:
      - 'api/**'
      - 'openapi/**'
jobs:
  api-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: 42Crunch API Audit
        uses: 42Crunch/api-security-audit-action@v3
        with:
          api-token: ${{ secrets.CRUNCH_API_TOKEN }}
          collection-name: "my-api-collection"
          min-score: 75
          upload-to-code-scanning: true

      - name: 42Crunch Conformance Scan
        if: github.ref == 'refs/heads/main'
        uses: 42Crunch/api-conformance-scan@v1
        with:
          api-token: ${{ secrets.CRUNCH_API_TOKEN }}
          target-url: ${{ secrets.STAGING_API_URL }}
          scan-config: ./42c-conf.yaml
```

**Jenkins Pipeline Integration:**

```groovy
pipeline {
    agent any
    stages {
        stage('API Security Audit') {
            steps {
                script {
                    def auditResult = sh(
                        script: '''
                            42crunch-cli audit \
                              --api-definition openapi.yaml \
                              --token ${CRUNCH_TOKEN} \
                              --min-score 75 \
                              --report-format json \
                              --output audit-report.json
                        ''',
                        returnStatus: true
                    )
                    if (auditResult != 0) {
                        error("API Security Audit failed - score below threshold")
                    }
                }
            }
        }
        stage('Conformance Scan') {
            when { branch 'main' }
            steps {
                sh '''
                    42crunch-cli scan \
                      --api-definition openapi.yaml \
                      --target-url ${STAGING_URL} \
                      --token ${CRUNCH_TOKEN} \
                      --scan-config 42c-conf.yaml
                '''
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: '*-report.*'
            publishHTML([
                reportDir: '.',
                reportFiles: 'audit-report.html',
                reportName: 'API Security Report'
            ])
        }
    }
}
```

### API Protect (Runtime Protection)

API Protect deploys as a micro-gateway in front of API endpoints to enforce the OpenAPI contract at runtime:

```yaml
# api-protect-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: api-protect-config
data:
  protection-config.json: |
    {
      "apiDefinition": "/config/openapi.yaml",
      "enforcement": {
        "validateRequests": true,
        "validateResponses": true,
        "blockOnFailure": true,
        "logLevel": "warn"
      },
      "rateLimit": {
        "enabled": true,
        "requestsPerMinute": 100,
        "burstSize": 20
      },
      "allowlist": {
        "contentTypes": ["application/json"],
        "methods": ["GET", "POST", "PUT", "DELETE"]
      }
    }
```

## Remediation Workflow

When 42Crunch identifies issues, follow this remediation process:

1. **Triage**: Review findings sorted by severity (Critical, High, Medium, Low)
2. **Analyze**: Understand the specific security control missing from the OpenAPI definition
3. **Fix**: Apply the recommended changes to the specification
4. **Validate**: Re-run audit to confirm the score improvement
5. **Deploy**: Push the updated specification through the CI/CD pipeline

**Common Audit Findings and Fixes:**

| Finding | Severity | Fix |
|---------|----------|-----|
| No authentication defined | Critical | Add securitySchemes and security requirements |
| Missing input validation | High | Add type, format, pattern, maxLength constraints |
| Server URL uses HTTP | High | Change server URLs to HTTPS |
| No error responses defined | Medium | Add 4xx and 5xx response definitions |
| additionalProperties not restricted | Medium | Set additionalProperties: false on object schemas |
| Missing rate limiting | Medium | Add x-rateLimit extension or use API Protect |

## Key Security Checks

42Crunch evaluates APIs against these critical security areas:

- **BOLA Prevention**: Validates that object-level authorization patterns are defined
- **BFLA Prevention**: Checks for function-level access control definitions
- **Injection Prevention**: Ensures input parameters have proper type/format/pattern constraints
- **Data Exposure**: Verifies response schemas limit returned properties
- **Security Misconfiguration**: Checks authentication schemes, transport security, CORS settings
- **Mass Assignment**: Validates that request bodies use explicit property allowlists

## References

- 42Crunch API Security Platform: https://42crunch.com/api-security-platform/
- 42Crunch Documentation: https://docs.42crunch.com/
- Microsoft Defender for Cloud 42Crunch Integration: https://learn.microsoft.com/en-us/azure/defender-for-cloud/onboarding-guide-42crunch
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x00-header/
- Jenkins Plugin for 42Crunch: https://plugins.jenkins.io/42crunch-security-audit/
