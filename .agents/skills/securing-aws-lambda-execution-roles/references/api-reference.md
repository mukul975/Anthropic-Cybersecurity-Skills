# API Reference: Securing AWS Lambda Execution Roles

## boto3 Lambda Client

### Key Methods
| Method | Description |
|--------|-------------|
| `list_functions()` | List all Lambda functions with role ARNs and runtime info |
| `get_function_configuration()` | Get function config including execution role |
| `update_function_configuration()` | Update function settings (role, KMS key, logging) |
| `create_function_url_config()` | Configure function URL with auth type |

## boto3 IAM Client (Role Analysis)

| Method | Description |
|--------|-------------|
| `get_role()` | Get role details including trust policy and permission boundary |
| `list_attached_role_policies()` | List managed policies on a role |
| `list_role_policies()` | List inline policy names |
| `get_role_policy()` | Get inline policy document |
| `put_role_permissions_boundary()` | Apply permission boundary |
| `simulate_principal_policy()` | Test effective permissions |
| `create_role()` | Create new role with trust policy |
| `attach_role_policy()` | Attach a managed policy to a role |

## boto3 Access Analyzer Client

| Method | Description |
|--------|-------------|
| `validate_policy()` | Validate policy against security best practices |
| `start_policy_generation()` | Generate least-privilege policy from CloudTrail |
| `get_generated_policy()` | Retrieve generated policy result |
| `check_no_new_access()` | Verify policy does not grant new access |

### Trust Policy Structure
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {"aws:SourceAccount": "ACCOUNT_ID"}
    }
  }]
}
```

### Permission Boundary Effect
The effective permissions are the intersection of:
1. Identity-based policy (attached to role)
2. Permission boundary (maximum allowed permissions)
3. Service Control Policies (organizational guardrails)

## References
- Lambda execution role docs: https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html
- Permission boundaries: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
- Access Analyzer policy validation: https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html
