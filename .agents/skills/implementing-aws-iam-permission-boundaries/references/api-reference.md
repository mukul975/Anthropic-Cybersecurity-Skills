# API Reference: AWS IAM Permission Boundary Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| boto3 | >=1.28 | AWS SDK for IAM permission boundary management |

## CLI Usage

```bash
python scripts/agent.py \
  --profile security-admin \
  --region us-east-1 \
  --audit \
  --output-dir /reports/ \
  --output iam_boundary_report.json
```

## Functions

### `get_iam_client(profile, region)`
Creates boto3 IAM client with optional named profile.

### `create_permission_boundary(client, policy_name, allowed_services, allowed_regions) -> dict`
Creates an IAM policy for use as a permission boundary. Includes a DenyBoundaryChanges statement to prevent boundary removal. Uses `client.create_policy()`.

### `attach_boundary_to_role(client, role_name, boundary_arn) -> dict`
Calls `client.put_role_permissions_boundary()` to attach a boundary to a role.

### `audit_roles_without_boundary(client) -> list`
Paginates `client.list_roles()` and identifies roles missing `PermissionsBoundary`.

### `audit_boundary_effectiveness(client, role_name) -> dict`
Calls `client.get_role()`, `list_attached_role_policies()`, `list_role_policies()` to show effective policy stack.

### `generate_report(client) -> dict`
Orchestrates audit and generates compliance report.

## boto3 IAM Methods Used

| Method | Purpose |
|--------|---------|
| `create_policy(PolicyName, PolicyDocument)` | Create boundary policy |
| `put_role_permissions_boundary(RoleName, PermissionsBoundary)` | Attach boundary |
| `list_roles()` | Enumerate all roles |
| `get_role(RoleName)` | Get role details including boundary |

## Output Schema

```json
{
  "roles_without_boundary_count": 12,
  "roles_without_boundary": [{"role_name": "dev-role", "arn": "arn:aws:iam::..."}],
  "recommendations": ["Attach permission boundaries to 12 roles"]
}
```
