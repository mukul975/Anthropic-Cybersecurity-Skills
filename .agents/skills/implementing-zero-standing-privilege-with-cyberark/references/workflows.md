# Zero Standing Privilege with CyberArk - Workflows

## JIT Access Request Workflow

```
Developer needs to access AWS production environment
    │
    ├── Opens CyberArk Secure Cloud Access portal
    │
    ├── Selects target: AWS Account "Production" (123456789012)
    │
    ├── Selects policy: "Developer Production Read Access"
    │
    ├── Specifies duration: 2 hours
    │
    ├── Provides justification: "Investigating PROD-1234 latency issue"
    │
    ├── Submits request
    │
    ├── CyberArk evaluates TEA policy:
    │   ├── Time: 2 hours within allowed range
    │   ├── Entitlements: Read-only production access
    │   └── Approval: Manager approval required
    │
    ├── Approval request sent to manager (Slack/email)
    │
    ├── Manager approves
    │
    ├── CyberArk provisions ephemeral IAM role:
    │   ├── Creates role with ReadOnlyAccess + resource restrictions
    │   ├── Sets session duration to 2 hours
    │   └── Generates temporary STS credentials
    │
    ├── Developer accesses AWS console/CLI with temp credentials
    │   └── All actions recorded in session log
    │
    └── After 2 hours: role deleted, credentials revoked
```

## Standing Privilege Migration Workflow

```
Phase 1: DISCOVERY AND ANALYSIS
    ├── Export all IAM users/roles with standing admin access
    ├── Analyze CloudTrail logs for actual permission usage
    ├── Identify which permissions are actually used vs. assigned
    ├── Calculate right-sized policy for each use case
    └── Map standing privileges to CyberArk ZSP policies

Phase 2: POLICY CREATION
    ├── Create CyberArk SCA policies for each access pattern
    ├── Define TEA parameters:
    │   ├── Maximum session duration per policy
    │   ├── Entitlement scope (AWS managed policies + custom)
    │   └── Approval requirements (auto vs. manual)
    ├── Configure approval workflows
    └── Test policies with pilot group

Phase 3: PILOT MIGRATION (2-4 weeks)
    ├── Assign ZSP policies to pilot users
    ├── Remove standing privileges from pilot users
    ├── Monitor for access denied errors
    ├── Adjust policies based on feedback
    └── Measure: request volume, approval time, session duration

Phase 4: FULL MIGRATION (4-8 weeks)
    ├── Migrate teams in waves (1 team per week)
    ├── Remove standing privileges after ZSP confirmed working
    ├── Configure auto-detect for new standing privilege creation
    └── Report metrics to security leadership

Phase 5: CONTINUOUS GOVERNANCE
    ├── Weekly: Review and right-size ZSP policies
    ├── Monthly: Audit for any standing privilege re-creation
    ├── Quarterly: Entitlement optimization report
    └── Alert on: New standing admin roles created outside CyberArk
```

## Emergency Break-Glass Workflow

```
CyberArk SCA unavailable or network issue
    │
    ├── Retrieve break-glass credentials from:
    │   ├── Physical safe (sealed envelope)
    │   ├── Or secondary vault (Azure Key Vault / AWS Secrets Manager)
    │
    ├── Authenticate with break-glass credentials
    │
    ├── Perform emergency actions
    │
    ├── Document all actions taken
    │
    └── Post-incident:
        ├── Rotate break-glass credentials
        ├── Review session logs for the emergency access
        ├── File incident report
        └── Verify no unauthorized changes made
```
