---
name: securing-serverless-functions
description: >
  This skill covers security hardening for serverless compute platforms including AWS
  Lambda, Azure Functions, and Google Cloud Functions. It addresses least privilege IAM
  roles, dependency vulnerability scanning, secrets management integration, input
  validation, function URL authentication, and runtime monitoring to protect against
  injection attacks, credential theft, and supply chain compromises.
domain: cybersecurity
subdomain: cloud-security
tags: [serverless-security, aws-lambda, azure-functions, function-hardening, supply-chain]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Securing Serverless Functions

## When to Use

- When deploying Lambda functions or Azure Functions with access to sensitive data or cloud APIs
- When auditing existing serverless workloads for overly permissive IAM roles
- When integrating serverless functions into a DevSecOps pipeline with automated security scanning
- When hardcoded secrets or vulnerable dependencies are discovered in function code
- When establishing runtime monitoring for serverless workloads to detect injection or credential theft

**Do not use** for container-based compute security (see securing-kubernetes-on-cloud), for API Gateway configuration (see implementing-cloud-waf-rules), or for serverless architecture design decisions.

## Prerequisites

- AWS Lambda, Azure Functions, or GCP Cloud Functions with deployment access
- CI/CD pipeline with dependency scanning tools (npm audit, Snyk, Dependabot)
- AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault for secrets management
- CloudWatch, Application Insights, or Cloud Logging for function monitoring

## Workflow

### Step 1: Enforce Least Privilege IAM Roles

Assign each Lambda function a dedicated IAM role with permissions scoped to only the specific resources it accesses. Never share IAM roles across functions.

```bash
# Create a least-privilege role for a specific Lambda function
aws iam create-role \
  --role-name order-processor-lambda-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach a scoped policy (not AmazonDynamoDBFullAccess)
aws iam put-role-policy \
  --role-name order-processor-lambda-role \
  --policy-name order-processor-policy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
        "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/Orders"
      },
      {
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/order-processor:*"
      },
      {
        "Effect": "Allow",
        "Action": ["secretsmanager:GetSecretValue"],
        "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:order-api-key-*"
      }
    ]
  }'
```

### Step 2: Eliminate Hardcoded Secrets

Replace plaintext credentials in environment variables with references to secrets management services. Use Lambda extensions or SDK calls to retrieve secrets at runtime.

```python
# INSECURE: Hardcoded credentials in environment variable
# DB_PASSWORD = os.environ['DB_PASSWORD']  # Stored as plaintext in Lambda config

# SECURE: Retrieve from AWS Secrets Manager with caching
import boto3
from botocore.exceptions import ClientError
import json

_secret_cache = {}

def get_secret(secret_name):
    if secret_name in _secret_cache:
        return _secret_cache[secret_name]

    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId=secret_name)
    secret = json.loads(response['SecretString'])
    _secret_cache[secret_name] = secret
    return secret

def lambda_handler(event, context):
    db_creds = get_secret('production/database/credentials')
    db_host = db_creds['host']
    db_password = db_creds['password']
    # Use credentials securely
```

```bash
# Enable encryption at rest for Lambda environment variables
aws lambda update-function-configuration \
  --function-name order-processor \
  --kms-key-arn arn:aws:kms:us-east-1:123456789012:key/key-id
```

### Step 3: Scan Dependencies for Vulnerabilities

Integrate automated dependency scanning into the CI/CD pipeline to catch vulnerable packages before deployment.

```bash
# npm audit for Node.js Lambda functions
cd lambda-function/
npm audit --audit-level=high
npm audit fix

# Snyk scanning in CI/CD pipeline
snyk test --severity-threshold=high
snyk monitor --project-name=order-processor-lambda

# pip-audit for Python Lambda functions
pip-audit -r requirements.txt --desc on --fix

# Scan Lambda deployment package with Trivy
trivy fs --severity HIGH,CRITICAL ./lambda-package/
```

```yaml
# GitHub Actions CI/CD security scanning
name: Lambda Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install dependencies
        run: npm ci
      - name: Run npm audit
        run: npm audit --audit-level=high
      - name: Snyk vulnerability scan
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      - name: Scan with Semgrep for code vulnerabilities
        uses: returntocorp/semgrep-action@v1
        with:
          config: p/owasp-top-ten
```

### Step 4: Implement Input Validation

Validate and sanitize all event input data to prevent injection attacks including SQL injection, command injection, and NoSQL injection through Lambda event sources.

```python
import re
import json
from jsonschema import validate, ValidationError

# Define expected input schema
ORDER_SCHEMA = {
    "type": "object",
    "properties": {
        "orderId": {"type": "string", "pattern": "^[a-zA-Z0-9-]{1,36}$"},
        "customerId": {"type": "string", "pattern": "^[a-zA-Z0-9]{1,20}$"},
        "amount": {"type": "number", "minimum": 0.01, "maximum": 999999.99},
        "currency": {"type": "string", "enum": ["USD", "EUR", "GBP"]}
    },
    "required": ["orderId", "customerId", "amount", "currency"],
    "additionalProperties": False
}

def lambda_handler(event, context):
    # Validate API Gateway event body
    try:
        body = json.loads(event.get('body', '{}'))
        validate(instance=body, schema=ORDER_SCHEMA)
    except (json.JSONDecodeError, ValidationError) as e:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Invalid input', 'details': str(e)})
        }

    # Safe to proceed with validated input
    order_id = body['orderId']
    # Use parameterized queries for database operations
```

### Step 5: Configure Function URL and API Gateway Authentication

Secure function invocation endpoints with proper authentication. Never expose Lambda function URLs without IAM or Cognito authentication.

```bash
# Secure Lambda function URL with IAM auth (not NONE)
aws lambda create-function-url-config \
  --function-name order-processor \
  --auth-type AWS_IAM \
  --cors '{
    "AllowOrigins": ["https://app.company.com"],
    "AllowMethods": ["POST"],
    "AllowHeaders": ["Content-Type", "Authorization"],
    "MaxAge": 3600
  }'

# API Gateway with Cognito authorizer
aws apigateway create-authorizer \
  --rest-api-id abc123 \
  --name CognitoAuth \
  --type COGNITO_USER_POOLS \
  --provider-arns "arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_EXAMPLE"
```

### Step 6: Enable Runtime Monitoring and Logging

Configure GuardDuty Lambda Network Activity Monitoring and CloudWatch structured logging to detect anomalous function behavior.

```bash
# Enable GuardDuty Lambda protection
aws guardduty update-detector \
  --detector-id <detector-id> \
  --features '[{"Name": "LAMBDA_NETWORK_ACTIVITY_LOGS", "Status": "ENABLED"}]'

# Configure Lambda to use structured logging
aws lambda update-function-configuration \
  --function-name order-processor \
  --logging-config '{"LogFormat": "JSON", "ApplicationLogLevel": "INFO", "SystemLogLevel": "WARN"}'
```

## Key Concepts

| Term | Definition |
|------|------------|
| Cold Start | Initial function invocation that includes container provisioning, increasing latency and creating a window where cached secrets may not be available |
| Event Injection | Attack where malicious input is embedded in Lambda event data from API Gateway, S3, SQS, or other event sources to exploit the function |
| Execution Role | IAM role assumed by Lambda during execution, defining all cloud API permissions the function can use |
| Function URL | Direct HTTPS endpoint for Lambda functions that can be configured with IAM or no authentication (NONE is insecure) |
| Layer | Lambda deployment package containing shared code or dependencies that should be scanned for vulnerabilities independently |
| Reserved Concurrency | Maximum number of concurrent executions for a function, useful for preventing resource exhaustion attacks |
| Provisioned Concurrency | Pre-initialized function instances that reduce cold start latency and ensure secrets are cached |

## Tools & Systems

- **AWS Lambda Power Tuning**: Open-source tool for optimizing Lambda memory and timeout settings to balance security with performance
- **Snyk**: SCA tool scanning Lambda dependencies for known vulnerabilities with automatic fix suggestions
- **Semgrep**: SAST tool with serverless-specific rules detecting injection vulnerabilities, hardcoded secrets, and insecure configurations
- **GuardDuty Lambda Protection**: AWS service monitoring Lambda network activity for connections to malicious endpoints
- **AWS X-Ray**: Distributed tracing service for detecting suspicious external connections and latency anomalies in Lambda invocations

## Common Scenarios

### Scenario: SQL Injection via API Gateway to Lambda to RDS

**Context**: A Lambda function receives user input from API Gateway and constructs SQL queries by string concatenation against an RDS PostgreSQL database. An attacker injects SQL payloads through the API.

**Approach**:
1. Audit the Lambda function code for string concatenation in SQL queries
2. Replace all string-formatted queries with parameterized queries using the database driver
3. Implement input validation using JSON Schema before any database operation
4. Add a WAF rule on API Gateway to block common SQL injection patterns
5. Deploy Semgrep in the CI/CD pipeline with the `python.django.security.injection.sql` rule set
6. Enable GuardDuty Lambda protection to detect anomalous database connection patterns

**Pitfalls**: Relying solely on WAF rules without fixing the underlying code vulnerability allows attackers to bypass with encoding tricks. Using ORM methods incorrectly (raw queries) still allows injection.

## Output Format

```
Serverless Security Assessment Report
=======================================
Account: 123456789012
Functions Assessed: 47
Assessment Date: 2025-02-23

CRITICAL FINDINGS:
  [SLS-001] order-processor: SQL injection via string concatenation
    Language: Python 3.12 | Runtime: Lambda
    Vulnerable Code: f"SELECT * FROM orders WHERE id = '{order_id}'"
    Remediation: Use parameterized queries with psycopg2

  [SLS-002] payment-handler: Hardcoded Stripe API key in environment variable
    Key: sk_live_XXXX... (unencrypted)
    Remediation: Migrate to AWS Secrets Manager with KMS encryption

HIGH FINDINGS:
  [SLS-003] 12 functions share the same IAM execution role with s3:*
  [SLS-004] 8 functions have function URLs with AuthType: NONE
  [SLS-005] 23 functions have dependencies with known HIGH CVEs

DEPENDENCY VULNERABILITIES:
  axios@0.21.1:         CVE-2023-45857 (HIGH) - 5 functions affected
  jsonwebtoken@8.5.1:   CVE-2022-23529 (CRITICAL) - 3 functions affected
  lodash@4.17.15:       CVE-2021-23337 (HIGH) - 11 functions affected

SUMMARY:
  Critical: 2 | High: 5 | Medium: 12 | Low: 8
  Functions with Least Privilege: 14/47 (30%)
  Functions with Secrets Manager: 19/47 (40%)
  Functions with Input Validation: 22/47 (47%)
```
