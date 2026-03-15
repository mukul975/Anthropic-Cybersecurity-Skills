# Azure AD PIM Implementation Template

## Tenant Details

| Field | Value |
|-------|-------|
| Tenant ID | |
| Tenant Name | |
| License | Entra ID P2 / Entra ID Governance |
| Implementation Date | |
| Project Lead | |

## Role Configuration Matrix

| Role | Assignment Type | Max Activation | MFA Required | Approval Required | Approver |
|------|----------------|---------------|--------------|-------------------|----------|
| Global Administrator | Eligible | 1 hour | Yes | Yes | |
| Security Administrator | Eligible | 4 hours | Yes | Yes | |
| Exchange Administrator | Eligible | 8 hours | Yes | No | |
| User Administrator | Eligible | 8 hours | Yes | No | |
| Application Administrator | Eligible | 8 hours | Yes | No | |

## Break-Glass Accounts

| Account | UPN | Assignment | MFA | Storage Location |
|---------|-----|-----------|-----|-----------------|
| Break-Glass 1 | | Active Global Admin | FIDO2 key | |
| Break-Glass 2 | | Active Global Admin | FIDO2 key | |

## Migration Checklist

- [ ] All permanent role assignments inventoried
- [ ] Break-glass accounts identified and documented
- [ ] PIM role settings configured for each role
- [ ] Approval workflows configured with designated approvers
- [ ] MFA enforced for all role activations
- [ ] Permanent assignments converted to eligible (except break-glass)
- [ ] Notification settings configured (admin, security team)
- [ ] Access reviews scheduled (quarterly)
- [ ] PIM alerts enabled and monitored
- [ ] Audit logs forwarded to SIEM
- [ ] User communication sent with activation instructions
- [ ] Help desk trained on PIM troubleshooting

## Access Review Schedule

| Role | Frequency | Reviewer | Auto-Apply | Duration |
|------|-----------|----------|------------|----------|
| Global Administrator | Monthly | Security Lead | Yes - Remove | 7 days |
| Security Administrator | Quarterly | CISO | Yes - Remove | 14 days |
| All Other Admin Roles | Quarterly | Manager | Yes - Remove | 14 days |
