# Compromised Cloud Credentials Detection API Reference

## GuardDuty Credential Findings

| Finding Type | Description |
|-------------|-------------|
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | EC2 instance creds used outside AWS |
| `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` | Console login from unusual location |
| `UnauthorizedAccess:IAMUser/MaliciousIPCaller` | API calls from known malicious IP |
| `Discovery:IAMUser/AnomalousBehavior` | Unusual reconnaissance API patterns |
| `Persistence:IAMUser/AnomalousBehavior` | Unusual persistence API calls |
| `InitialAccess:IAMUser/AnomalousBehavior` | Unusual initial access patterns |

## CloudTrail - Credential Abuse Investigation

```bash
# Lookup events by access key
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAXXXXXXXXXXXXXXXX \
  --start-time 2024-01-01T00:00:00Z --end-time 2024-01-02T00:00:00Z

# Lookup by username
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=compromised-user

# Athena query for deep investigation
SELECT eventtime, eventsource, eventname, sourceipaddress,
       useridentity.arn, errorcode
FROM cloudtrail_logs
WHERE useridentity.accesskeyid = 'AKIAXXXXXXXXXXXXXXXX'
  AND eventtime > '2024-01-01'
ORDER BY eventtime DESC
```

## IAM Credential Remediation

```bash
# Deactivate access key
aws iam update-access-key --access-key-id AKIAXXXX --user-name user --status Inactive

# Delete access key
aws iam delete-access-key --access-key-id AKIAXXXX --user-name user

# Revoke all sessions (inline deny policy with token age condition)
aws iam put-user-policy --user-name user --policy-name RevokeOldSessions \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"2024-01-15T00:00:00Z"}}}]}'

# List all access keys for user
aws iam list-access-keys --user-name user
```

## Reconnaissance API Calls to Monitor

```
GetCallerIdentity, ListBuckets, DescribeInstances,
ListUsers, ListRoles, ListAccessKeys, DescribeRegions,
GetAccountAuthorizationDetails, ListFunctions,
DescribeDBInstances, ListSecrets
```

## Azure - Compromised Credential Detection

```bash
# Query risky sign-ins
az rest --method GET --url "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers"

# Revoke user sessions
az rest --method POST --url "https://graph.microsoft.com/v1.0/users/{id}/revokeSignInSessions"
```
