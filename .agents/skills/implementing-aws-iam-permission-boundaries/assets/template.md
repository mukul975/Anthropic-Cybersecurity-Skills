# AWS IAM Permission Boundary Implementation Template

## Boundary Policy Details

| Field | Value |
|-------|-------|
| Policy Name | |
| AWS Account ID | |
| Target Roles | (prefix pattern, e.g., app-*) |
| Allowed Services | |
| Created By | |
| Date | |

## Allowed Service Actions

| Service | Actions Allowed | Justification |
|---------|----------------|---------------|
| S3 | s3:* | Application data storage |
| DynamoDB | dynamodb:* | Application database |
| Lambda | lambda:* | Serverless compute |
| CloudWatch | cloudwatch:*, logs:* | Monitoring and logging |
| | | |

## Denied Actions (Escalation Prevention)

| Action | Reason |
|--------|--------|
| iam:DeleteRolePermissionsBoundary | Prevent boundary removal |
| iam:DeleteUserPermissionsBoundary | Prevent boundary removal |
| iam:CreatePolicyVersion (on boundary) | Prevent boundary modification |
| iam:SetDefaultPolicyVersion (on boundary) | Prevent boundary modification |

## Testing Results

| Test Case | Expected Result | Actual Result | Pass/Fail |
|-----------|----------------|---------------|-----------|
| Create role with boundary | Success | | |
| Create role without boundary | AccessDenied | | |
| Use allowed service (e.g., S3) | Success | | |
| Use blocked service (e.g., IAM admin) | AccessDenied | | |
| Remove own boundary | AccessDenied | | |
| Modify boundary policy | AccessDenied | | |

## Sign-Off

| Role | Name | Date |
|------|------|------|
| Security Engineer | | |
| Cloud Architect | | |
| DevOps Lead | | |
