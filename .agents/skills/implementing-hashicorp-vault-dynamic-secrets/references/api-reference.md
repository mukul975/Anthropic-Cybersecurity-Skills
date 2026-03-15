# API Reference: Implementing HashiCorp Vault Dynamic Secrets

## Libraries

### hvac (HashiCorp Vault Client)
- **Install**: `pip install hvac`
- **Docs**: https://hvac.readthedocs.io/en/stable/

## Database Secrets Engine

| Method | Description |
|--------|-------------|
| `secrets.database.configure()` | Set up database connection |
| `secrets.database.create_role()` | Define dynamic credential role |
| `secrets.database.generate_credentials()` | Generate ephemeral DB credentials |
| `secrets.database.rotate_root_credentials()` | Rotate root DB password |
| Plugins: `postgresql-database-plugin`, `mysql-database-plugin`, `mongodb-database-plugin` |

## AWS Secrets Engine

| Method | Description |
|--------|-------------|
| `secrets.aws.configure_root_iam_credentials()` | Set AWS root creds |
| `secrets.aws.create_or_update_role()` | Define IAM role template |
| `secrets.aws.generate_credentials()` | Generate dynamic IAM keys |
| Credential types: `iam_user`, `assumed_role`, `federation_token` |

## PKI Secrets Engine

| Method | Description |
|--------|-------------|
| `sys.enable_secrets_engine(backend_type="pki")` | Enable PKI |
| `secrets.pki.generate_root()` | Create CA root certificate |
| `secrets.pki.create_or_update_role()` | Define cert issuance role |
| `secrets.pki.generate_certificate()` | Issue dynamic certificate |

## Lease Management

| Method | Description |
|--------|-------------|
| `sys.list_leases(prefix)` | List active leases |
| `sys.revoke_lease(lease_id)` | Revoke specific credential |
| `sys.revoke_prefix(prefix)` | Revoke all under prefix |
| `sys.renew_lease(lease_id, increment)` | Extend lease TTL |

## Authentication Methods

| Method | Description |
|--------|-------------|
| `auth.token` | Token-based auth |
| `auth.approle.login()` | AppRole for applications |
| `auth.kubernetes.login()` | Kubernetes service account |
| `auth.aws.iam_login()` | AWS IAM-based auth |

## System Operations

| Method | Description |
|--------|-------------|
| `sys.read_health_status()` | Vault health check |
| `sys.list_mounted_secrets_engines()` | List secrets engines |
| `sys.list_auth_methods()` | List auth backends |
| `sys.enable_audit_device()` | Enable audit logging |

## External References
- Vault Documentation: https://developer.hashicorp.com/vault/docs
- hvac Python Client: https://hvac.readthedocs.io/
- Database Secrets: https://developer.hashicorp.com/vault/docs/secrets/databases
- AWS Secrets: https://developer.hashicorp.com/vault/docs/secrets/aws
- PKI Secrets: https://developer.hashicorp.com/vault/docs/secrets/pki
