# Workflows - Authenticated Vulnerability Scanning

## Workflow 1: Credential Preparation and Validation

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Create Service   │────>│ Configure Least  │────>│ Test Credentials │
│ Accounts         │     │ Privilege Access  │     │ on Sample Hosts  │
└──────────────────┘     └──────────────────┘     └──────────────────┘
                                                          │
        ┌────────────────────────────────────────────────┘
        v
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Store in Secrets │────>│ Configure Scanner│────>│ Validate Auth    │
│ Vault            │     │ Credentials      │     │ Success Rate     │
└──────────────────┘     └──────────────────┘     └──────────────────┘
```

## Workflow 2: Authenticated Scan Execution

1. **Pre-scan**: Verify credentials, check network connectivity, confirm scan window
2. **Discovery**: Host enumeration to identify live targets
3. **Authentication**: Scanner authenticates to each target host
4. **Local Enumeration**: Query installed packages, patches, configurations
5. **Vulnerability Assessment**: Match local data against vulnerability database
6. **Report Generation**: Compile findings with credential success metrics
7. **Post-scan**: Verify no service disruption, archive results

## Workflow 3: Credential Success Monitoring

```
Scan Completion
    │
    ├──> Check Plugin 117887 (Local Security Checks)
    │        │
    │        ├──> SUCCESS: Proceed to analyze findings
    │        └──> FAILURE: Investigate cause
    │                 │
    │                 ├──> Network connectivity issue
    │                 ├──> Credential expired or changed
    │                 ├──> Firewall blocking management ports
    │                 ├──> Account locked out
    │                 └──> Insufficient privileges
    │
    └──> Calculate Credential Success Rate
             │
             ├──> Target: >95% authenticated hosts
             ├──> Alert if <90% success rate
             └──> Document exceptions for failed hosts
```

## Workflow 4: Credential Lifecycle Management

| Phase | Action | Frequency |
|-------|--------|-----------|
| Provisioning | Create accounts with least privilege | One-time |
| Distribution | Deploy keys/passwords to scanner | One-time |
| Validation | Test connectivity before scans | Per scan |
| Rotation | Change passwords, rotate keys | 90 days |
| Monitoring | Audit login events in SIEM | Continuous |
| Deprovisioning | Remove accounts when scanner retired | As needed |
