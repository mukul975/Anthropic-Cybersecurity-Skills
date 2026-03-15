# API Reference: Service Account Credential Rotation

## AWS IAM CLI Key Rotation

| Command | Description |
|---------|-------------|
| `aws iam create-access-key --user-name <user>` | Create new access key |
| `aws iam list-access-keys --user-name <user>` | List existing keys |
| `aws iam update-access-key --access-key-id <id> --status Inactive` | Deactivate old key |
| `aws iam delete-access-key --access-key-id <id> --user-name <user>` | Delete old key |

## Azure AD CLI Credential Rotation

| Command | Description |
|---------|-------------|
| `az ad app credential reset --id <app-id> --years 1` | Generate new client secret |
| `az ad app credential list --id <app-id>` | List current credentials |
| `az ad app credential delete --id <app-id> --key-id <key-id>` | Remove old credential |

## HashiCorp Vault Database Secrets Engine

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/database/creds/{role}` | GET | Generate dynamic database credentials |
| `/v1/database/config/{name}` | POST | Configure database connection |
| `/v1/database/roles/{name}` | POST | Create dynamic credential role |
| `/v1/sys/leases/revoke` | PUT | Revoke a dynamic credential lease |

### Vault Request Headers

| Header | Value |
|--------|-------|
| `X-Vault-Token` | Vault authentication token |
| `Content-Type` | `application/json` |

## GCP Service Account Key Rotation

| Command | Description |
|---------|-------------|
| `gcloud iam service-accounts keys create` | Create new key |
| `gcloud iam service-accounts keys list --iam-account <sa>` | List keys |
| `gcloud iam service-accounts keys delete <key-id>` | Delete old key |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute AWS/Azure/GCP CLI commands |
| `requests` | >=2.28 | HashiCorp Vault HTTP API calls |
| `hvac` | >=2.1 | HashiCorp Vault Python client |
| `boto3` | >=1.26 | AWS IAM programmatic key rotation |

## References

- AWS Secrets Manager Rotation: https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html
- HashiCorp Vault Database Engine: https://developer.hashicorp.com/vault/docs/secrets/databases
- Azure Key Vault Rotation: https://learn.microsoft.com/en-us/azure/key-vault/secrets/tutorial-rotation
- GCP Key Rotation: https://cloud.google.com/iam/docs/key-rotation
