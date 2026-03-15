# Privileged Account Access Review - Workflows

## Quarterly Review Cycle

```
Week 1: PREPARATION
    ├── Extract privileged account inventory from PAM/AD/Cloud
    ├── Identify new accounts since last review
    ├── Assign reviewers based on account ownership
    └── Send review campaign notifications

Week 2-3: REVIEW EXECUTION
    ├── Reviewers evaluate each account against criteria
    ├── Approve, revoke, or flag for investigation
    ├── Escalate unresponsive reviewers after 7 days
    └── Security team reviews flagged accounts

Week 4: REMEDIATION
    ├── Disable/remove revoked accounts
    ├── Rotate credentials for all reviewed accounts
    ├── Create tickets for privilege reduction
    └── Generate review completion report
```

## Account Discovery Workflow

```
1. Active Directory Enumeration
   ├── Query AdminCount=1 accounts
   ├── Enumerate privileged group memberships
   ├── Identify accounts with SPN (service accounts)
   └── Check for accounts with delegation rights

2. Cloud Platform Enumeration
   ├── AWS: List IAM users/roles with admin policies
   ├── Azure: Export Entra ID directory role assignments
   ├── GCP: List IAM bindings with Owner/Editor roles
   └── Cross-reference with known approved accounts

3. Database and Application Enumeration
   ├── Query database system role memberships
   ├── Export application admin role assignments
   └── Identify shared/generic admin accounts

4. Consolidation
   ├── Merge all discovered accounts into single inventory
   ├── Deduplicate accounts across platforms
   ├── Assign risk classification
   └── Identify accounts missing from PAM vault
```

## Reviewer Decision Workflow

```
Reviewer receives account for certification
    │
    ├── Is the account owner still employed?
    │   ├── NO → Revoke immediately, disable account
    │   └── YES → Continue
    │
    ├── Has the account been used in last 90 days?
    │   ├── NO → Recommend disable, notify owner
    │   └── YES → Continue
    │
    ├── Does the user's current role require this privilege?
    │   ├── NO → Revoke, provide lower-privilege alternative
    │   └── YES → Continue
    │
    ├── Can the privilege be reduced (least privilege)?
    │   ├── YES → Approve with remediation to reduce
    │   └── NO → Continue
    │
    ├── Are there SoD conflicts?
    │   ├── YES → Flag for risk acceptance or remediation
    │   └── NO → Continue
    │
    └── CERTIFY the access with documented justification
```

## Emergency Account Review Workflow

```
Break-glass account used
    │
    ├── Alert generated to security team
    │
    ├── Within 24 hours:
    │   ├── Verify incident ticket exists for the usage
    │   ├── Confirm authorized personnel used the account
    │   ├── Review session recording (if available)
    │   └── Validate actions taken were appropriate
    │
    ├── Within 48 hours:
    │   ├── Reset break-glass account credentials
    │   ├── Store new credentials in sealed envelope/vault
    │   └── Document usage in access review log
    │
    └── Monthly: Verify break-glass accounts have not been used
        without corresponding incident documentation
```
