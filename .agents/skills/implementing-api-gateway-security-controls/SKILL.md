---
name: implementing-api-gateway-security-controls
description: >
  Implements security controls at the API gateway layer including authentication enforcement,
  rate limiting, request validation, IP allowlisting, TLS termination, and threat protection.
  The engineer configures API gateways (Kong, AWS API Gateway, Azure APIM, Apigee) to act
  as a centralized security enforcement point that validates, throttles, and monitors all
  API traffic before it reaches backend services. Activates for requests involving API gateway
  security, API management security, gateway authentication, or centralized API protection.
domain: cybersecurity
subdomain: api-security
tags: [api-security, api-gateway, kong, aws-api-gateway, rate-limiting, waf]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Implementing API Gateway Security Controls

## When to Use

- Deploying a centralized authentication and authorization layer for microservice APIs
- Implementing rate limiting, throttling, and quota management across all API endpoints
- Configuring request/response validation against OpenAPI specifications at the gateway level
- Setting up TLS termination, mutual TLS, and certificate management for API traffic
- Integrating WAF rules with the API gateway to block injection, XSS, and known attack patterns

**Do not use** as the sole security layer. API gateways provide defense in depth but backend services must also validate authorization and input.

## Prerequisites

- API gateway platform selected and deployed (Kong, AWS API Gateway, Azure APIM, or Apigee)
- OpenAPI/Swagger specifications for all backend APIs
- TLS certificates for the gateway domain
- Identity provider (IdP) configured for OAuth2/OIDC (Okta, Auth0, Azure AD)
- Monitoring and logging infrastructure (CloudWatch, Datadog, ELK)
- Backend service endpoints registered and reachable from the gateway

## Workflow

### Step 1: Kong Gateway Security Configuration

```yaml
# kong.yml - Declarative Kong configuration with security plugins
_format_version: "3.0"

services:
  - name: user-service
    url: http://user-service:8080
    routes:
      - name: user-api
        paths:
          - /api/v1/users
        methods:
          - GET
          - POST
          - PUT
          - PATCH
          - DELETE
        strip_path: false

plugins:
  # 1. Authentication: JWT validation
  - name: jwt
    config:
      uri_param_names:
        - jwt
      header_names:
        - Authorization
      claims_to_verify:
        - exp
      maximum_expiration: 3600  # Max 1 hour token TTL

  # 2. Rate Limiting
  - name: rate-limiting
    config:
      minute: 60
      hour: 1000
      policy: redis
      redis_host: redis
      redis_port: 6379
      fault_tolerant: true
      hide_client_headers: false
      limit_by: credential  # Per-user, not per-IP

  # 3. Request Size Limiting
  - name: request-size-limiting
    config:
      allowed_payload_size: 1  # 1 MB max
      size_unit: megabytes

  # 4. IP Restriction (admin endpoints)
  - name: ip-restriction
    service: admin-service
    config:
      allow:
        - 10.0.0.0/8
        - 172.16.0.0/12

  # 5. Bot Detection
  - name: bot-detection
    config:
      deny:
        - "sqlmap"
        - "nikto"
        - "nmap"
        - "masscan"

  # 6. CORS Configuration
  - name: cors
    config:
      origins:
        - "https://app.example.com"
      methods:
        - GET
        - POST
        - PUT
        - PATCH
        - DELETE
      headers:
        - Authorization
        - Content-Type
      credentials: true
      max_age: 3600

  # 7. Response Transformer - Remove sensitive headers
  - name: response-transformer
    config:
      remove:
        headers:
          - X-Powered-By
          - Server
      add:
        headers:
          - "X-Content-Type-Options: nosniff"
          - "X-Frame-Options: DENY"
          - "Strict-Transport-Security: max-age=31536000; includeSubDomains"
          - "Content-Security-Policy: default-src 'none'"
```

### Step 2: AWS API Gateway Security Configuration

```python
import boto3
import json

apigw = boto3.client('apigatewayv2')

# Create API with mutual TLS
api_response = apigw.create_api(
    Name='secure-api',
    ProtocolType='HTTP',
    DisableExecuteApiEndpoint=True,  # Force custom domain
)
api_id = api_response['ApiId']

# Configure authorizer (JWT with Cognito)
authorizer = apigw.create_authorizer(
    ApiId=api_id,
    AuthorizerType='JWT',
    IdentitySource='$request.header.Authorization',
    Name='cognito-jwt-authorizer',
    JwtConfiguration={
        'Audience': ['your-app-client-id'],
        'Issuer': 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_xxxxx'
    }
)

# Create route with authorizer
apigw.create_route(
    ApiId=api_id,
    RouteKey='GET /api/v1/users',
    AuthorizerId=authorizer['AuthorizerId'],
    AuthorizationType='JWT',
)

# Configure throttling
apigw.create_stage(
    ApiId=api_id,
    StageName='prod',
    DefaultRouteSettings={
        'ThrottlingBurstLimit': 100,
        'ThrottlingRateLimit': 50.0,  # 50 requests per second
    },
    AccessLogSettings={
        'DestinationArn': 'arn:aws:logs:us-east-1:123456789:log-group:api-access-logs',
        'Format': json.dumps({
            'requestId': '$context.requestId',
            'ip': '$context.identity.sourceIp',
            'caller': '$context.identity.caller',
            'user': '$context.identity.user',
            'requestTime': '$context.requestTime',
            'httpMethod': '$context.httpMethod',
            'resourcePath': '$context.resourcePath',
            'status': '$context.status',
            'protocol': '$context.protocol',
            'responseLength': '$context.responseLength'
        })
    }
)

# WAF association
waf = boto3.client('wafv2')
web_acl = waf.create_web_acl(
    Name='api-security-acl',
    Scope='REGIONAL',
    DefaultAction={'Allow': {}},
    Rules=[
        {
            'Name': 'AWS-AWSManagedRulesSQLiRuleSet',
            'Priority': 1,
            'Statement': {
                'ManagedRuleGroupStatement': {
                    'VendorName': 'AWS',
                    'Name': 'AWSManagedRulesSQLiRuleSet'
                }
            },
            'OverrideAction': {'None': {}},
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': 'SQLiRuleSet'
            }
        },
        {
            'Name': 'RateLimit',
            'Priority': 2,
            'Statement': {
                'RateBasedStatement': {
                    'Limit': 2000,
                    'AggregateKeyType': 'IP'
                }
            },
            'Action': {'Block': {}},
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': 'RateLimitRule'
            }
        },
    ],
    VisibilityConfig={
        'SampledRequestsEnabled': True,
        'CloudWatchMetricsEnabled': True,
        'MetricName': 'ApiSecurityACL'
    }
)
```

### Step 3: Request Validation with OpenAPI Schema

```yaml
# Kong OAS Validation Plugin configuration
plugins:
  - name: oas-validation
    config:
      api_spec: |
        openapi: "3.0.3"
        info:
          title: Secure API
          version: "1.0"
        paths:
          /api/v1/users:
            post:
              requestBody:
                required: true
                content:
                  application/json:
                    schema:
                      type: object
                      required: [name, email]
                      properties:
                        name:
                          type: string
                          maxLength: 100
                          pattern: "^[a-zA-Z ]+$"
                        email:
                          type: string
                          format: email
                          maxLength: 255
                      additionalProperties: false  # Block mass assignment
              responses:
                '201':
                  description: User created
      validate_request_body: true
      validate_request_header_params: true
      validate_request_query_params: true
      validate_request_uri_params: true
      verbose_response: false  # Do not expose schema details in errors
```

### Step 4: Mutual TLS Configuration

```bash
# Generate CA and client certificates for mTLS
# 1. Create CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -out ca.crt -days 365 \
    -subj "/CN=API Gateway CA/O=Example Corp"

# 2. Create client certificate
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
    -subj "/CN=api-client/O=Example Corp"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt -days 365

# Kong mTLS configuration
# Upload CA certificate to Kong
curl -X POST http://kong-admin:8001/ca_certificates \
    -F "cert=@ca.crt"

# Enable mTLS plugin
curl -X POST http://kong-admin:8001/services/user-service/plugins \
    --data "name=mtls-auth" \
    --data "config.ca_certificates[]=$(cat ca_cert_id)" \
    --data "config.revocation_check_mode=SKIP" \
    --data "config.authenticated_group_by=CN"
```

### Step 5: Logging and Monitoring Configuration

```python
# CloudWatch monitoring for API security events
import boto3

cloudwatch = boto3.client('cloudwatch')
logs = boto3.client('logs')

# Create metric filters for security events
security_filters = [
    {
        'name': 'UnauthorizedAccess',
        'pattern': '{ $.status = 401 || $.status = 403 }',
        'metric': 'UnauthorizedAccessCount'
    },
    {
        'name': 'RateLimitHits',
        'pattern': '{ $.status = 429 }',
        'metric': 'RateLimitHitCount'
    },
    {
        'name': 'ServerErrors',
        'pattern': '{ $.status >= 500 }',
        'metric': 'ServerErrorCount'
    },
    {
        'name': 'LargeResponses',
        'pattern': '{ $.responseLength > 1000000 }',
        'metric': 'LargeResponseCount'
    },
]

for sf in security_filters:
    logs.put_metric_filter(
        logGroupName='api-access-logs',
        filterName=sf['name'],
        filterPattern=sf['pattern'],
        metricTransformations=[{
            'metricName': sf['metric'],
            'metricNamespace': 'APISecurityMetrics',
            'metricValue': '1',
            'defaultValue': 0
        }]
    )

# Create alarm for unusual 401/403 spike
cloudwatch.put_metric_alarm(
    AlarmName='API-UnauthorizedAccessSpike',
    MetricName='UnauthorizedAccessCount',
    Namespace='APISecurityMetrics',
    Statistic='Sum',
    Period=300,  # 5 minutes
    EvaluationPeriods=1,
    Threshold=100,
    ComparisonOperator='GreaterThanThreshold',
    AlarmActions=['arn:aws:sns:us-east-1:123456789:security-alerts'],
    AlarmDescription='More than 100 unauthorized access attempts in 5 minutes'
)
```

## Key Concepts

| Term | Definition |
|------|------------|
| **API Gateway** | Centralized entry point for all API traffic that enforces authentication, authorization, rate limiting, and request validation before routing to backend services |
| **Rate Limiting** | Controlling the number of API requests per client within a time window to prevent abuse and ensure fair resource allocation |
| **Request Validation** | Verifying that incoming API requests conform to the expected schema (data types, required fields, value ranges) before forwarding to backend services |
| **Mutual TLS (mTLS)** | Two-way TLS authentication where both the client and server present certificates, providing strong identity verification for API-to-API communication |
| **WAF Integration** | Web Application Firewall rules applied at the API gateway to block common attack patterns (SQLi, XSS, path traversal) |
| **OAuth2/OIDC** | Token-based authentication protocols where the gateway validates JWT tokens against an identity provider before allowing access |

## Tools & Systems

- **Kong Gateway**: Open-source API gateway with extensive plugin ecosystem for security, rate limiting, and authentication
- **AWS API Gateway**: Managed API gateway service with built-in throttling, WAF integration, and Lambda authorizers
- **Azure API Management**: Enterprise API gateway with policy-based security, developer portal, and Azure AD integration
- **Apigee (Google Cloud)**: API management platform with threat protection, quota management, and API analytics
- **Envoy Proxy**: High-performance proxy used as API gateway in service mesh architectures with extensive filter chain

## Common Scenarios

### Scenario: Securing a Microservice API with Kong Gateway

**Context**: A company is migrating from a monolithic API to microservices. Each microservice has its own REST API. The security team needs to implement centralized authentication, rate limiting, and request validation without modifying each service.

**Approach**:
1. Deploy Kong Gateway as the single entry point, routing traffic to 8 backend microservices
2. Configure JWT validation plugin to verify tokens against the company's Keycloak IdP
3. Apply rate limiting: 60 requests/minute for regular users, 300/minute for premium users, identified by JWT claims
4. Enable OAS validation plugin to reject requests that do not match the OpenAPI spec (blocks mass assignment and injection)
5. Configure mTLS for service-to-service communication behind the gateway
6. Set up response transformer to remove Server and X-Powered-By headers and add security headers
7. Integrate with AWS WAF for SQL injection and XSS protection rules
8. Configure access logging to CloudWatch with security metric filters and alerting

**Pitfalls**:
- Relying solely on the gateway for authorization when backend services also need to verify permissions
- Not configuring rate limiting per authenticated user (per-IP only allows attackers to bypass with IP rotation)
- Using verbose error responses from the gateway that reveal internal service architecture
- Not testing the gateway configuration with security tools after deployment
- Missing mutual TLS between the gateway and backend services, allowing direct backend access

## Output Format

```
## API Gateway Security Configuration Report

**Gateway**: Kong 3.5 (Kubernetes deployment)
**Backend Services**: 8 microservices
**Date**: 2024-12-15

### Security Controls Implemented

| Control | Plugin/Feature | Configuration |
|---------|---------------|---------------|
| Authentication | JWT Plugin | Cognito IdP, 1-hour max TTL |
| Rate Limiting | Rate Limiting Plugin | 60 req/min (user), Redis-backed |
| Request Validation | OAS Validation | Strict mode, no additional properties |
| TLS | Kong TLS | TLS 1.3 only, HSTS enabled |
| mTLS | mTLS Auth Plugin | Client cert required for admin APIs |
| WAF | AWS WAF | SQLi, XSS, rate-based rules |
| Headers | Response Transformer | Server header removed, security headers added |
| Logging | HTTP Log Plugin | CloudWatch, security metric filters |

### Verification Results

- JWT validation: Expired/invalid tokens correctly rejected (tested 50 payloads)
- Rate limiting: Enforced at 60 req/min, 429 returned with Retry-After header
- Request validation: Malformed requests rejected with 400 (tested 30 invalid payloads)
- mTLS: Requests without client certificate rejected with 401
- WAF: SQL injection payloads blocked (tested top 100 SQLi patterns)
```
