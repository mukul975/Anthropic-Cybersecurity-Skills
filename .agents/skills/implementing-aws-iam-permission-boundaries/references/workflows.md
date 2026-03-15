# AWS IAM Permission Boundaries - Workflows

## Boundary Policy Creation Workflow

```
1. Security team identifies allowed services for developer workloads
       │
2. Draft permission boundary policy (JSON)
       │
3. Peer review by second security engineer
       │
4. Test in sandbox account:
       ├── Create test role with boundary
       ├── Verify allowed actions succeed
       ├── Verify blocked actions are denied
       └── Verify boundary cannot be self-modified
       │
5. Commit policy to version control (IaC repository)
       │
6. Deploy via CI/CD pipeline (Terraform/CloudFormation)
       │
7. Attach boundary to all developer-created roles
```

## Developer Role Creation Workflow (with Boundary)

```
Developer wants to create a new IAM role
       │
├── Developer writes role policy (only app-* prefixed)
│
├── Developer creates role with --permissions-boundary flag
│       │
│       └── If boundary not attached → API returns AccessDenied
│
├── AWS IAM validates:
│   ├── Role name matches required prefix (app-*)
│   ├── Permission boundary ARN matches required boundary
│   └── Developer has iam:CreateRole with boundary condition
│
├── Role created successfully with boundary attached
│
└── Effective permissions = identity policy ∩ boundary policy
```

## Privilege Escalation Prevention Workflow

```
Attacker attempts to escalate privileges:

Attempt 1: Create role without boundary
    → Denied by developer policy (condition requires boundary)

Attempt 2: Modify the boundary policy itself
    → Denied by boundary's own deny statements

Attempt 3: Remove boundary from existing role
    → Denied by boundary deny on DeleteRolePermissionsBoundary

Attempt 4: Create policy granting iam:* access
    → Policy can only grant actions within boundary intersection

Attempt 5: Assume a role without boundary
    → Developer can only create roles with boundary condition

All escalation paths blocked ✓
```

## Boundary Audit Workflow

```
Monthly audit:
    │
    ├── List all IAM roles in account
    │
    ├── Check each role for boundary attachment:
    │   ├── Has boundary → Verify correct boundary ARN
    │   └── No boundary → Flag for remediation
    │
    ├── Review boundary policy changes (CloudTrail)
    │
    ├── Check for new IAM actions added to AWS services
    │   └── Update boundary if new actions should be restricted
    │
    └── Generate compliance report
```
