# AWS Credential Exposure Detection API Reference

## TruffleHog CLI

```bash
# Scan local git repo
trufflehog git file:///path/to/repo --json

# Scan GitHub organization
trufflehog github --org my-org --token $GITHUB_TOKEN --json

# Scan GitHub repo
trufflehog git https://github.com/org/repo.git --json

# Scan filesystem (non-git)
trufflehog filesystem /path/to/dir --json

# Scan S3 bucket
trufflehog s3 --bucket my-bucket --json

# Only show verified credentials
trufflehog git file:///repo --only-verified --json
```

## git-secrets CLI

```bash
# Install hooks in repo
git secrets --install
git secrets --register-aws

# Scan repo history
git secrets --scan-history

# Scan specific file
git secrets --scan /path/to/file

# Add custom pattern
git secrets --add 'PRIVATE KEY'
git secrets --add-provider -- cat /path/to/patterns.txt
```

## AWS IAM CLI - Key Management

```bash
# Check key last used
aws iam get-access-key-last-used --access-key-id AKIAXXXXXXXXXXXXXXXX

# List access keys for user
aws iam list-access-keys --user-name jsmith

# Deactivate exposed key
aws iam update-access-key --access-key-id AKIAXXXXXXXXXXXXXXXX \
  --user-name jsmith --status Inactive

# Delete key
aws iam delete-access-key --access-key-id AKIAXXXXXXXXXXXXXXXX \
  --user-name jsmith

# Create new key (after rotation)
aws iam create-access-key --user-name jsmith
```

## AWS Access Key Regex Patterns

```
Access Key ID:  AKIA[A-Z0-9]{16}
Temp Key ID:    ASIA[A-Z0-9]{16}
Secret Key:     [A-Za-z0-9/+=]{40}
```

## GuardDuty Credential Findings

| Finding Type | Description |
|-------------|-------------|
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | Instance creds used outside AWS |
| `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` | Console login from unusual IP |
| `Recon:IAMUser/MaliciousIPCaller.Custom` | API calls from threat intel IPs |

## AWS CloudTrail - Credential Abuse Queries (Athena)

```sql
SELECT eventtime, useridentity.accesskeyid, sourceipaddress, eventname
FROM cloudtrail_logs
WHERE useridentity.accesskeyid = 'AKIAXXXXXXXXXXXXXXXX'
ORDER BY eventtime DESC
LIMIT 100;
```
