# Service Account Credential Rotation - Workflows

## Automated Rotation Workflow

```
Rotation Scheduler (cron/secrets manager)
    │
    ├── Pre-Rotation Checks:
    │   ├── Verify service account exists and is active
    │   ├── Verify all dependent services are healthy
    │   ├── Confirm change window (maintenance window)
    │   └── Notify operations team of pending rotation
    │
    ├── Generate New Credential:
    │   ├── Create new password/key with required complexity
    │   ├── Store new credential in secrets vault
    │   └── Maintain old credential as backup
    │
    ├── Update Source System:
    │   ├── AD: Set-ADAccountPassword
    │   ├── AWS: CreateAccessKey
    │   ├── Azure: Add client secret to service principal
    │   ├── GCP: Create new service account key
    │   └── DB: ALTER USER ... PASSWORD ...
    │
    ├── Propagate to Consumers:
    │   ├── Update application config (env vars, config files)
    │   ├── Update Kubernetes secrets
    │   ├── Update CI/CD pipeline secrets
    │   ├── Restart dependent services if required
    │   └── Wait for propagation
    │
    ├── Post-Rotation Verification:
    │   ├── Health check all dependent services
    │   ├── Test authentication with new credentials
    │   ├── Verify old credential no longer works
    │   └── Log rotation success/failure
    │
    └── Cleanup:
        ├── Deactivate old credential after grace period
        ├── Delete old credential after confirmation
        └── Update rotation audit log
```

## Emergency Rotation Workflow (Credential Compromise)

```
Credential compromise detected
    │
    ├── IMMEDIATE (within 15 minutes):
    │   ├── Disable compromised credential
    │   ├── Generate new credential
    │   ├── Update source system
    │   └── Notify incident response team
    │
    ├── SHORT-TERM (within 1 hour):
    │   ├── Propagate new credential to all consumers
    │   ├── Verify service health
    │   ├── Review audit logs for unauthorized use
    │   └── Assess blast radius of compromise
    │
    └── FOLLOW-UP (within 24 hours):
        ├── Complete incident report
        ├── Review rotation procedures
        ├── Update dependent service configurations
        └── Rotate any related credentials
```

## gMSA Migration Workflow

```
Identify service accounts eligible for gMSA migration
    │
    ├── For each eligible service account:
    │   ├── Create gMSA in Active Directory
    │   ├── Add target servers to PrincipalsAllowedToRetrieve
    │   ├── Install gMSA on each target server
    │   ├── Test gMSA retrieval (Test-ADServiceAccount)
    │   │
    │   ├── During maintenance window:
    │   │   ├── Stop the service
    │   │   ├── Change service logon account to gMSA
    │   │   ├── Update file/folder permissions if needed
    │   │   ├── Start the service
    │   │   └── Verify service functionality
    │   │
    │   └── Post-migration:
    │       ├── Disable old service account
    │       ├── Monitor service for 2 weeks
    │       └── Delete old account after confirmation
    │
    └── Update service account inventory
```
