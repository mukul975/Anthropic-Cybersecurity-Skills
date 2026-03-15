# ZTNA Implementation Workflows

## Workflow 1: Initial ZPA Deployment

```
┌─────────────────┐
│ Pre-Assessment   │
│ - Inventory apps │
│ - Map user groups│
│ - Classify data  │
└───────┬─────────┘
        v
┌─────────────────────┐
│ IdP Integration      │
│ - SAML/OIDC config   │
│ - SCIM provisioning  │
│ - MFA enrollment     │
│ - Test SSO flow      │
└───────┬─────────────┘
        v
┌─────────────────────┐
│ App Connector Deploy │
│ - Provision VMs      │
│ - Generate enroll key│
│ - Install + enroll   │
│ - Health validation  │
└───────┬─────────────┘
        v
┌─────────────────────┐
│ Application Segments │
│ - Define apps by     │
│   FQDN/IP + ports   │
│ - Create seg groups  │
│ - Map to server grps │
└───────┬─────────────┘
        v
┌─────────────────────┐
│ Access Policies      │
│ - User->App mapping  │
│ - Posture conditions │
│ - Deny rules         │
│ - Priority ordering  │
└───────┬─────────────┘
        v
┌─────────────────────┐
│ Client Deployment    │
│ - Package connector  │
│ - MDM distribution   │
│ - Forwarding profile │
│ - User acceptance    │
└───────┬─────────────┘
        v
┌─────────────────────┐
│ Validation & Monitor │
│ - Access testing     │
│ - SIEM integration   │
│ - Dashboard setup    │
│ - Incident playbooks │
└─────────────────────┘
```

## Workflow 2: Access Request Evaluation (Runtime)

```
User Request
    │
    v
┌──────────────────┐    ┌──────────────────┐
│ Client Connector  │───>│ ZPA Service Edge  │
│ - Capture request │    │ - Receive tunnel  │
│ - Forward to edge │    │ - Identify user   │
└──────────────────┘    └────────┬─────────┘
                                 │
                    ┌────────────v────────────┐
                    │ Authentication          │
                    │ - Redirect to IdP       │
                    │ - Validate SAML/OIDC    │
                    │ - Check MFA completion  │
                    └────────────┬────────────┘
                                 │
                    ┌────────────v────────────┐
                    │ Authorization            │
                    │ - Match access policies  │
                    │ - Evaluate posture       │
                    │ - Check context signals  │
                    │ - Apply least privilege  │
                    └────────────┬────────────┘
                                 │
                    ┌────YES─────┴─────NO────┐
                    v                         v
           ┌──────────────┐         ┌──────────────┐
           │ Grant Access  │         │ Deny Access   │
           │ - Select App  │         │ - Log denial  │
           │   Connector   │         │ - Alert SIEM  │
           │ - Stitch tunnel│        │ - User notify │
           │ - Monitor     │         └──────────────┘
           └──────────────┘
```

## Workflow 3: VPN-to-ZTNA Migration

```
Phase 1: Assessment (Weeks 1-2)
├── Catalog all VPN-accessed applications
├── Map user groups to applications
├── Identify application dependencies
├── Baseline VPN performance metrics
└── Document compliance requirements

Phase 2: Parallel Deployment (Weeks 3-6)
├── Deploy ZPA alongside existing VPN
├── Configure App Connectors for pilot apps
├── Create policies mirroring VPN ACLs
├── Deploy Client Connector to pilot users
└── Validate access and performance

Phase 3: Migration Waves (Weeks 7-16)
├── Wave 1: Low-risk web applications
├── Wave 2: Business-critical web apps
├── Wave 3: Non-web TCP/UDP applications
├── Wave 4: Legacy applications
└── Each wave: test → validate → migrate → monitor

Phase 4: VPN Decommission (Weeks 17-20)
├── Verify all applications accessible via ZPA
├── Disable VPN for migrated user groups
├── Monitor for access issues (2-week soak)
├── Decommission VPN concentrators
└── Update disaster recovery documentation
```

## Workflow 4: Device Posture Enforcement

```
┌───────────────────┐
│ Device Connects    │
└───────┬───────────┘
        v
┌───────────────────┐
│ Posture Assessment │
│ - OS version       │
│ - Patch level      │
│ - Disk encryption  │
│ - AV/EDR status    │
│ - Firewall enabled │
│ - Domain joined    │
└───────┬───────────┘
        v
┌───────────────────┐
│ Posture Evaluation │
│ Compare against    │
│ posture profiles   │
└───┬──────────┬────┘
    │          │
  PASS       FAIL
    │          │
    v          v
┌────────┐ ┌──────────────────┐
│ Full   │ │ Restricted Access │
│ Access │ │ - Browser only    │
└────────┘ │ - Limited apps    │
           │ - Remediation msg │
           └──────────────────┘
```

## Workflow 5: Incident Response with ZPA

```
Alert Triggered (SIEM/SOAR)
    │
    v
┌──────────────────┐
│ 1. Triage         │
│ - Review ZPA logs │
│ - Identify user   │
│ - Identify app    │
│ - Classify event  │
└───────┬──────────┘
        v
┌──────────────────┐
│ 2. Containment    │
│ - Revoke user     │
│   access in ZPA   │
│ - Isolate app     │
│   segment         │
│ - Block device    │
│   via posture     │
└───────┬──────────┘
        v
┌──────────────────┐
│ 3. Investigation  │
│ - Pull session    │
│   logs from ZPA   │
│ - Correlate with  │
│   IdP/EDR/SIEM    │
│ - Map lateral     │
│   movement        │
└───────┬──────────┘
        v
┌──────────────────┐
│ 4. Recovery       │
│ - Update policies │
│ - Re-enable access│
│ - Post-incident   │
│   review          │
└──────────────────┘
```
