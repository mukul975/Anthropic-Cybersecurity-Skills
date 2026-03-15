# API Reference: Service Account Abuse Detection

## Active Directory PowerShell Module

### Get Service Accounts (SPN-based)
```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties `
    ServicePrincipalName, LastLogonDate, Enabled, PasswordLastSet, `
    PasswordNeverExpires, AdminCount, MemberOf
```

### Get Managed Service Accounts
```powershell
Get-ADServiceAccount -Filter * -Properties `
    PrincipalsAllowedToRetrieveManagedPassword, LastLogonDate
```

### Check Kerberos Delegation
```powershell
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties `
    TrustedForDelegation, TrustedToAuthForDelegation, `
    msDS-AllowedToDelegateTo
```

## Windows Event Log Queries

### Logon Type Values
| Type | Description | Concern for Service Accounts |
|------|-------------|------------------------------|
| 2 | Interactive | HIGH — should not happen |
| 3 | Network | Normal for services |
| 5 | Service | Normal |
| 10 | RemoteInteractive (RDP) | HIGH — should not happen |

### Event IDs
| ID | Log | Description |
|----|-----|-------------|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4648 | Security | Explicit credential use |
| 4672 | Security | Special privilege logon |
| 4720 | Security | Account created |
| 4738 | Security | Account modified |

## Microsoft Graph API — Service Principal Audit

### List Service Principals
```http
GET https://graph.microsoft.com/v1.0/servicePrincipals
Authorization: Bearer {token}
```

### List App Role Assignments
```http
GET https://graph.microsoft.com/v1.0/servicePrincipals/{id}/appRoleAssignments
```

### Audit Sign-In Logs
```http
GET https://graph.microsoft.com/v1.0/auditLogs/signIns
    ?$filter=appId eq '{service-principal-app-id}'
```

## AWS IAM — Service Role Audit

### List service-linked roles
```bash
aws iam list-roles --query "Roles[?starts_with(Path, '/aws-service-role/')]"
```

### Get role last used
```bash
aws iam get-role --role-name MyServiceRole \
    --query "Role.RoleLastUsed"
```

### Access Analyzer findings
```bash
aws accessanalyzer list-findings --analyzer-arn {arn} \
    --filter '{"resourceType":{"eq":["AWS::IAM::Role"]}}'
```
