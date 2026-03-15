# API Reference: Securing Serverless Functions

## boto3 Lambda Client

### Installation
```bash
pip install boto3
```

### Key Methods
| Method | Description |
|--------|-------------|
| `list_functions()` | List all functions with configuration details |
| `get_function_configuration()` | Get function config (role, env vars, KMS) |
| `get_function_url_config()` | Get function URL and auth type |
| `get_function_concurrency()` | Get reserved concurrency settings |
| `update_function_configuration()` | Update KMS key, logging, VPC config |
| `create_function_url_config()` | Create function URL with auth type |

### Function Configuration Fields
| Field | Security Relevance |
|-------|-------------------|
| `Role` | Execution role ARN (check for least privilege) |
| `Environment.Variables` | May contain hardcoded secrets |
| `KMSKeyArn` | Customer-managed KMS key for env encryption |
| `VpcConfig` | VPC subnet and security group configuration |
| `Timeout` | Max execution time (1-900 seconds) |
| `Runtime` | Language runtime (check for EOL versions) |
| `Layers` | Shared code layers (scan independently) |

### Function URL Auth Types
| Value | Description |
|-------|-------------|
| `AWS_IAM` | Requires IAM authentication (secure) |
| `NONE` | No authentication required (insecure for sensitive functions) |

## boto3 IAM Client (Role Checks)
| Method | Description |
|--------|-------------|
| `list_attached_role_policies()` | Check for overly broad managed policies |
| `get_role_policy()` | Inspect inline policy for wildcards |
| `get_role()` | Check trust policy and permission boundary |

## GuardDuty Lambda Protection
```python
gd = boto3.client("guardduty")
gd.update_detector(
    DetectorId="<id>",
    Features=[{"Name": "LAMBDA_NETWORK_ACTIVITY_LOGS", "Status": "ENABLED"}]
)
```

## References
- Lambda security best practices: https://docs.aws.amazon.com/lambda/latest/dg/lambda-security.html
- Lambda function URLs: https://docs.aws.amazon.com/lambda/latest/dg/lambda-urls.html
- GuardDuty Lambda protection: https://docs.aws.amazon.com/guardduty/latest/ug/lambda-protection.html
