# Azure AD PIM - Workflows

## PIM Deployment Workflow

```
Phase 1: DISCOVERY
    ├── Export all permanent role assignments via Microsoft Graph
    ├── Identify users with multiple admin roles
    ├── Flag accounts without MFA enabled
    └── Document break-glass account strategy

Phase 2: PLANNING
    ├── Define activation settings per role (duration, MFA, approval)
    ├── Identify approvers for each critical role
    ├── Create communication plan for affected admins
    └── Schedule pilot group for initial rollout

Phase 3: CONFIGURATION
    ├── Configure PIM role settings (activation, assignment, notification)
    ├── Convert permanent assignments to eligible (except break-glass)
    ├── Configure conditional access policies for admin activation
    └── Enable audit logging and SIEM integration

Phase 4: TESTING
    ├── Test role activation with pilot users
    ├── Test approval workflow end-to-end
    ├── Test MFA enforcement during activation
    ├── Test auto-deactivation after duration expires
    └── Validate audit logs capture all PIM events

Phase 5: ROLLOUT
    ├── Convert remaining permanent assignments to eligible
    ├── Notify all affected users with activation instructions
    ├── Monitor for activation failures and help desk tickets
    └── Configure access reviews on quarterly schedule
```

## Role Activation Workflow

```
Admin needs to perform privileged task
    │
    ├── Navigate to PIM portal (Entra Admin Center > PIM > My Roles)
    │
    ├── Click "Activate" on the needed role
    │
    ├── Select activation duration (up to configured max)
    │
    ├── Enter justification and optional ticket number
    │
    ├── Complete MFA challenge
    │
    ├── [If approval required]
    │   ├── Request submitted to approvers
    │   ├── Approvers receive email notification
    │   ├── Approver reviews justification and approves/denies
    │   └── Admin receives approval notification
    │
    ├── Role becomes active
    │
    ├── Admin performs required task
    │
    └── Role automatically deactivates when duration expires
        (or admin manually deactivates early)
```

## Access Review Workflow

```
Quarterly Access Review Triggered
    │
    ├── PIM sends review notifications to designated reviewers
    │
    ├── For each eligible assignment:
    │   ├── Reviewer checks: Is this role still needed?
    │   ├── Reviewer checks: When was role last activated?
    │   ├── Decision: Approve (maintain), Deny (remove), or Don't know
    │   └── Provide justification for decision
    │
    ├── Review period expires (14 days default)
    │
    ├── Auto-apply results:
    │   ├── Approved assignments maintained
    │   ├── Denied assignments removed
    │   └── No-response: configurable (remove or maintain)
    │
    └── Review summary report generated for compliance
```

## Break-Glass Account Workflow

```
Normal Operations:
    └── Break-glass accounts exist as ACTIVE Global Admin
        ├── Stored in secure physical safe (password printout)
        ├── Excluded from conditional access policies
        ├── Monitored by Azure Monitor alert rule
        └── Monthly verification: confirm no unauthorized sign-ins

Emergency Use:
    ├── Primary admin methods unavailable (MFA outage, PIM issue)
    ├── Retrieve break-glass credentials from safe
    ├── Sign in and resolve the emergency
    ├── Document all actions taken
    ├── Reset break-glass credentials after use
    └── Review and document in incident log
```
