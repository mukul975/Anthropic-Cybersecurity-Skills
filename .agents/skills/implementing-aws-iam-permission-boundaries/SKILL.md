---
name: implementing-aws-iam-permission-boundaries
description: Configure IAM permission boundaries in AWS to delegate role creation to developers while enforcing maximum privilege limits set by the security team.
domain: cybersecurity
subdomain: identity-access-management
tags: [aws, iam, permission-boundaries, least-privilege, delegation, cloud-security]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing AWS IAM Permission Boundaries

## Overview

IAM permission boundaries are an advanced AWS feature that sets the maximum permissions an identity-based policy can grant to an IAM entity (user or role). They enable centralized security teams to safely delegate IAM role and policy creation to application developers without risking privilege escalation. The effective permissions of an entity are the intersection of its identity-based policies and its permission boundary -- even if an identity policy grants `AdministratorAccess`, the permission boundary restricts it to only the allowed actions.

## Prerequisites

- AWS account with IAM administrative access
- Understanding of AWS IAM policy language (JSON)
- AWS CLI v2 configured with appropriate credentials
- Terraform or CloudFormation for infrastructure-as-code deployment

## Core Concepts

### How Permission Boundaries Work

```
Identity-Based Policy          Permission Boundary
(What the role CAN do)    ∩    (What the role MAY do)
        │                              │
        └──────────┬───────────────────┘
                   │
          Effective Permissions
    (Only actions in BOTH policies)
```

### Policy Evaluation Logic

AWS evaluates permissions in this order:
1. **Explicit Deny** in any policy - always wins
2. **Organizations SCP** - sets org-wide maximum
3. **Permission Boundary** - sets entity-level maximum
4. **Identity-Based Policy** - grants actual permissions
5. **Resource-Based Policy** - cross-account access (evaluated separately)

The entity can only perform an action if ALL applicable policy types allow it.

### Key Use Cases

| Use Case | Description |
|----------|-------------|
| Developer Delegation | Allow devs to create IAM roles without escalating beyond their boundary |
| Sandbox Isolation | Limit what roles can do in sandbox/dev accounts |
| Multi-Tenant Workloads | Ensure tenant-specific roles cannot access other tenants' resources |
| CI/CD Pipeline Roles | Restrict automation roles to specific services |

## Implementation Steps

### Step 1: Define the Permission Boundary Policy

Create a managed policy that defines the maximum allowed permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowedServices",
            "Effect": "Allow",
            "Action": [
                "s3:*",
                "dynamodb:*",
                "lambda:*",
                "logs:*",
                "cloudwatch:*",
                "sqs:*",
                "sns:*",
                "events:*",
                "states:*",
                "xray:*",
                "ec2:Describe*",
                "ec2:CreateTags",
                "sts:AssumeRole",
                "kms:Decrypt",
                "kms:GenerateDataKey",
                "kms:DescribeKey",
                "secretsmanager:GetSecretValue"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowIAMPassRole",
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "arn:aws:iam::*:role/app-*",
            "Condition": {
                "StringEquals": {
                    "iam:PassedToService": [
                        "lambda.amazonaws.com",
                        "states.amazonaws.com"
                    ]
                }
            }
        },
        {
            "Sid": "DenyBoundaryDeletion",
            "Effect": "Deny",
            "Action": [
                "iam:DeletePolicy",
                "iam:DeletePolicyVersion",
                "iam:CreatePolicyVersion"
            ],
            "Resource": "arn:aws:iam::*:policy/DeveloperBoundary"
        },
        {
            "Sid": "DenyBoundaryRemoval",
            "Effect": "Deny",
            "Action": [
                "iam:DeleteUserPermissionsBoundary",
                "iam:DeleteRolePermissionsBoundary"
            ],
            "Resource": "*"
        }
    ]
}
```

### Step 2: Create the Developer Delegation Policy

Grant developers the ability to create IAM roles, but only with the boundary attached:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowCreateRoleWithBoundary",
            "Effect": "Allow",
            "Action": [
                "iam:CreateRole",
                "iam:AttachRolePolicy",
                "iam:DetachRolePolicy",
                "iam:PutRolePolicy",
                "iam:DeleteRolePolicy"
            ],
            "Resource": "arn:aws:iam::*:role/app-*",
            "Condition": {
                "StringEquals": {
                    "iam:PermissionsBoundary": "arn:aws:iam::*:policy/DeveloperBoundary"
                }
            }
        },
        {
            "Sid": "AllowCreatePolicyScoped",
            "Effect": "Allow",
            "Action": [
                "iam:CreatePolicy",
                "iam:DeletePolicy",
                "iam:CreatePolicyVersion",
                "iam:DeletePolicyVersion"
            ],
            "Resource": "arn:aws:iam::*:policy/app-*"
        },
        {
            "Sid": "AllowViewIAM",
            "Effect": "Allow",
            "Action": [
                "iam:Get*",
                "iam:List*"
            ],
            "Resource": "*"
        }
    ]
}
```

### Step 3: Attach the Boundary

```bash
# Create the boundary policy
aws iam create-policy \
    --policy-name DeveloperBoundary \
    --policy-document file://developer-boundary.json

# Attach boundary to an existing role
aws iam put-role-permissions-boundary \
    --role-name developer-role \
    --permissions-boundary arn:aws:iam::123456789012:policy/DeveloperBoundary

# Create a new role with boundary
aws iam create-role \
    --role-name app-lambda-executor \
    --assume-role-policy-document file://trust-policy.json \
    --permissions-boundary arn:aws:iam::123456789012:policy/DeveloperBoundary
```

### Step 4: Prevent Privilege Escalation

The boundary must include deny statements to prevent developers from:
- Removing the boundary from their own roles
- Modifying the boundary policy itself
- Creating roles without the boundary attached
- Accessing IAM services to escalate privileges

### Step 5: Deploy with Terraform

```hcl
resource "aws_iam_policy" "developer_boundary" {
  name   = "DeveloperBoundary"
  path   = "/"
  policy = file("${path.module}/policies/developer-boundary.json")
}

resource "aws_iam_role" "app_role" {
  name                 = "app-lambda-executor"
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
  permissions_boundary = aws_iam_policy.developer_boundary.arn
}
```

## Validation Checklist

- [ ] Permission boundary policy created and reviewed by security team
- [ ] Boundary includes deny statements preventing self-modification
- [ ] Developer delegation policy requires boundary on all new roles
- [ ] Role naming convention enforced (e.g., `app-*` prefix)
- [ ] Developers tested creating roles with and without boundary (should fail without)
- [ ] Privilege escalation paths tested and blocked
- [ ] CloudTrail logging enabled for IAM API calls
- [ ] Boundary policy versioned in source control
- [ ] Automated tests validate boundary effectiveness
- [ ] Documentation provided to development teams

## References

- [AWS IAM Permission Boundaries Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
- [When and Where to Use Permission Boundaries - AWS Security Blog](https://aws.amazon.com/blogs/security/when-and-where-to-use-iam-permissions-boundaries/)
- [AWS Example Permission Boundary - GitHub](https://github.com/aws-samples/example-permissions-boundary)
- [AWS Prescriptive Guidance - Creating Permission Boundaries](https://docs.aws.amazon.com/prescriptive-guidance/latest/transitioning-to-multiple-aws-accounts/creating-a-permissions-boundary.html)
