# API Reference: Serverless Function Security Review

## Overview

Agent automates Lambda security reviews using boto3 to audit execution roles, environment variable secrets, deprecated runtimes, and public access configurations.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| boto3 | >= 1.28 | AWS SDK for Lambda and IAM API calls |
| botocore | >= 1.31 | Exception handling for AWS API errors |

## Core Functions

### `list_all_functions(client)`
Paginates through all Lambda functions in the region.
- **Parameters**: `client` - boto3 Lambda client
- **Returns**: `list[dict]` - full function configuration objects

### `check_deprecated_runtime(runtime)`
Checks if a Lambda runtime is end-of-life.
- **Parameters**: `runtime` (str) - Lambda runtime identifier
- **Returns**: `bool` - True if deprecated

### `audit_execution_role(iam, role_arn)`
Inspects attached IAM policies for wildcard actions and AdministratorAccess.
- **Parameters**: `iam` - boto3 IAM client, `role_arn` (str)
- **Returns**: `list[str]` - finding descriptions

### `check_env_secrets(env_vars)`
Scans environment variables for sensitive patterns (passwords, API keys, AWS credentials).
- **Parameters**: `env_vars` (dict) - Lambda environment variables
- **Returns**: `list[str]` - masked sensitive variable findings

### `check_public_access(client, function_name)`
Checks resource-based policies and function URLs for unauthenticated access.
- **Parameters**: `client` - boto3 Lambda client, `function_name` (str)
- **Returns**: `list[str]` - public access findings

### `run_review(region="us-east-1")`
Orchestrates the full review across all functions. Returns structured report dict.

## AWS API Calls Used

| API Call | Service | Purpose |
|----------|---------|---------|
| `list_functions` | Lambda | Enumerate all Lambda functions |
| `get_policy` | Lambda | Retrieve resource-based policy |
| `list_function_url_configs` | Lambda | Check function URL auth type |
| `list_attached_role_policies` | IAM | Get policies on execution role |
| `get_policy_version` | IAM | Read policy document for wildcards |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AWS_ACCESS_KEY_ID` | Yes | AWS credential (or use IAM role) |
| `AWS_SECRET_ACCESS_KEY` | Yes | AWS credential (or use IAM role) |
| `AWS_DEFAULT_REGION` | No | Defaults to us-east-1 |

## Output Schema

```json
{
  "total_functions": 34,
  "deprecated_runtimes": [{"function": "name", "runtime": "python3.7"}],
  "role_findings": ["CRITICAL: Role X has AdministratorAccess"],
  "secret_findings": [{"function": "name", "finding": "SENSITIVE: DB_PASSWORD = prod****word"}],
  "public_access_findings": ["PUBLIC ACCESS: func allows public invocation"]
}
```
