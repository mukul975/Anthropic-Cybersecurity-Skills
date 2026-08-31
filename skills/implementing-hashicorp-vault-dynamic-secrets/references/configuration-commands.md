# HashiCorp Vault Dynamic Secrets - Configuration and Commands

Full configuration files, CLI commands, and integration code for each workflow step in the main SKILL.md.

## Step 1: Deploy and Configure Vault Server

Initialize Vault with production-grade configuration:

```hcl
# vault-config.hcl - Production Vault server configuration
storage "raft" {
  path    = "/opt/vault/data"
  node_id = "vault-1"

  retry_join {
    leader_api_addr = "https://vault-2.corp.local:8200"
  }
  retry_join {
    leader_api_addr = "https://vault-3.corp.local:8200"
  }
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/opt/vault/tls/vault-cert.pem"
  tls_key_file  = "/opt/vault/tls/vault-key.pem"
}

seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "alias/vault-unseal-key"
}

api_addr      = "https://vault-1.corp.local:8200"
cluster_addr  = "https://vault-1.corp.local:8201"

telemetry {
  prometheus_retention_time = "24h"
  disable_hostname          = true
}

ui = true
```

```bash
# Initialize Vault cluster
vault operator init -key-shares=5 -key-threshold=3

# Enable audit logging
vault audit enable file file_path=/var/log/vault/audit.log

# Enable AppRole authentication for applications
vault auth enable approle

# Create policy for database secret consumers
vault policy write db-consumer - <<EOF
# Allow reading dynamic database credentials
path "database/creds/app-readonly" {
  capabilities = ["read"]
}
path "database/creds/app-readwrite" {
  capabilities = ["read"]
}

# Allow renewing and revoking own leases
path "sys/leases/renew" {
  capabilities = ["update"]
}
path "sys/leases/revoke" {
  capabilities = ["update"]
}

# Allow reading own token info
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
EOF

# Create AppRole for application
vault write auth/approle/role/webapp \
    token_policies="db-consumer" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=720h \
    secret_id_num_uses=0
```

## Step 2: Configure Database Secrets Engine

Set up dynamic credential generation for PostgreSQL and MySQL:

```bash
# Enable the database secrets engine
vault secrets enable database

# Configure PostgreSQL connection
vault write database/config/production-postgres \
    plugin_name=postgresql-database-plugin \
    allowed_roles="app-readonly,app-readwrite,app-admin" \
    connection_url="postgresql://{{username}}:{{password}}@db-primary.corp.local:5432/appdb?sslmode=verify-full" \
    username="vault_admin" \
    password="$VAULT_DB_PASSWORD" \
    password_authentication="scram-sha-256"

# Rotate the root credentials so Vault manages them exclusively
vault write -force database/rotate-root/production-postgres

# Create read-only role (TTL: 1 hour, max 24 hours)
vault write database/roles/app-readonly \
    db_name=production-postgres \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; \
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO \"{{name}}\";" \
    revocation_statements="REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\"; \
        DROP ROLE IF EXISTS \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"

# Create read-write role (TTL: 30 minutes, max 8 hours)
vault write database/roles/app-readwrite \
    db_name=production-postgres \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; \
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO \"{{name}}\";" \
    revocation_statements="REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\"; \
        DROP ROLE IF EXISTS \"{{name}}\";" \
    default_ttl="30m" \
    max_ttl="8h"

# Configure MySQL connection
vault write database/config/production-mysql \
    plugin_name=mysql-database-plugin \
    allowed_roles="mysql-readonly,mysql-readwrite" \
    connection_url="{{username}}:{{password}}@tcp(mysql-primary.corp.local:3306)/" \
    username="vault_admin" \
    password="$VAULT_MYSQL_PASSWORD"

vault write database/roles/mysql-readonly \
    db_name=production-mysql \
    creation_statements="CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'; \
        GRANT SELECT ON appdb.* TO '{{name}}'@'%';" \
    revocation_statements="DROP USER IF EXISTS '{{name}}'@'%';" \
    default_ttl="1h" \
    max_ttl="24h"

# Test dynamic credential generation
echo "Testing PostgreSQL dynamic credentials:"
vault read database/creds/app-readonly
# Returns: username=v-approle-app-read-xxxxx, password=<random>, lease_id=database/creds/app-readonly/xxxxx
```

## Step 3: Configure AWS Secrets Engine

Generate ephemeral AWS IAM credentials:

```bash
# Enable the AWS secrets engine
vault secrets enable aws

# Configure the AWS secrets engine with root credentials
vault write aws/config/root \
    access_key="$AWS_ACCESS_KEY_ID" \
    secret_key="$AWS_SECRET_ACCESS_KEY" \
    region="us-east-1"

# Configure lease settings
vault write aws/config/lease \
    lease="30m" \
    lease_max="1h"

# Create IAM User role for S3 read-only access
vault write aws/roles/s3-readonly \
    credential_type=iam_user \
    policy_document=-<<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:GetBucketLocation"
      ],
      "Resource": [
        "arn:aws:s3:::app-data-bucket",
        "arn:aws:s3:::app-data-bucket/*"
      ]
    }
  ]
}
EOF

# Create Assumed Role for EC2 management (preferred over IAM users)
vault write aws/roles/ec2-admin \
    credential_type=assumed_role \
    role_arns="arn:aws:iam::123456789012:role/VaultEC2AdminRole" \
    default_sts_ttl="30m" \
    max_sts_ttl="1h"

# Create Federation Token role for cross-account access
vault write aws/roles/cross-account-readonly \
    credential_type=federation_token \
    policy_document=-<<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole"
      ],
      "Resource": "arn:aws:iam::987654321098:role/CrossAccountReadOnly"
    }
  ]
}
EOF

# Test AWS dynamic credentials
echo "Testing AWS STS credentials:"
vault read aws/creds/ec2-admin
# Returns: access_key, secret_key, security_token with 30-minute TTL
```

## Step 4: Configure PKI Secrets Engine for Dynamic Certificates

Generate short-lived TLS certificates on demand:

```bash
# Enable PKI secrets engine for root CA
vault secrets enable -path=pki pki
vault secrets tune -max-lease-ttl=87600h pki

# Generate root CA certificate
vault write pki/root/generate/internal \
    common_name="Corp Internal Root CA" \
    ttl=87600h \
    key_type=ec \
    key_bits=384

# Enable PKI for intermediate CA
vault secrets enable -path=pki_int pki
vault secrets tune -max-lease-ttl=43800h pki_int

# Generate intermediate CA CSR
vault write pki_int/intermediate/generate/internal \
    common_name="Corp Intermediate CA" \
    key_type=ec \
    key_bits=256

# Sign intermediate CA with root CA
vault write pki/root/sign-intermediate \
    csr=@intermediate.csr \
    format=pem_bundle \
    ttl=43800h

# Configure issuing URLs
vault write pki_int/config/urls \
    issuing_certificates="https://vault.corp.local:8200/v1/pki_int/ca" \
    crl_distribution_points="https://vault.corp.local:8200/v1/pki_int/crl"

# Create role for web server certificates (TTL: 30 days)
vault write pki_int/roles/web-server \
    allowed_domains="corp.local,internal.corp.com" \
    allow_subdomains=true \
    max_ttl=720h \
    key_type=ec \
    key_bits=256 \
    require_cn=true \
    enforce_hostnames=true

# Create role for service mesh certificates (TTL: 24 hours)
vault write pki_int/roles/service-mesh \
    allowed_domains="service.consul" \
    allow_subdomains=true \
    max_ttl=24h \
    key_type=ec \
    key_bits=256 \
    allow_ip_sans=true \
    server_flag=true \
    client_flag=true

# Issue a certificate
vault write pki_int/issue/web-server \
    common_name="api.corp.local" \
    alt_names="api.internal.corp.com" \
    ttl=720h
```

## Step 5: Integrate Applications with Vault

Configure applications to consume dynamic secrets:

```python
"""
Application integration with HashiCorp Vault for dynamic database credentials.
Uses the hvac Python client with automatic lease renewal.
"""
import hvac
import threading
import time
import logging

class VaultDynamicCredentialManager:
    def __init__(self, vault_addr, role_id, secret_id):
        self.client = hvac.Client(url=vault_addr)
        self.role_id = role_id
        self.secret_id = secret_id
        self.logger = logging.getLogger("vault_credentials")
        self._current_creds = None
        self._lease_id = None
        self._renewal_thread = None
        self._stop_event = threading.Event()

    def authenticate(self):
        """Authenticate to Vault using AppRole."""
        response = self.client.auth.approle.login(
            role_id=self.role_id,
            secret_id=self.secret_id
        )
        self.client.token = response["auth"]["client_token"]
        self.logger.info("Authenticated to Vault via AppRole")

    def get_database_credentials(self, role="app-readonly"):
        """Request dynamic database credentials from Vault."""
        self.authenticate()

        response = self.client.secrets.database.generate_credentials(
            name=role
        )

        self._current_creds = {
            "username": response["data"]["username"],
            "password": response["data"]["password"],
        }
        self._lease_id = response["lease_id"]
        lease_duration = response["lease_duration"]

        self.logger.info(
            f"Obtained dynamic credentials: user={self._current_creds['username']}, "
            f"lease={self._lease_id}, ttl={lease_duration}s"
        )

        # Start background lease renewal
        self._start_renewal(lease_duration)

        return self._current_creds

    def _start_renewal(self, lease_duration):
        """Start background thread to renew lease before expiration."""
        if self._renewal_thread and self._renewal_thread.is_alive():
            self._stop_event.set()
            self._renewal_thread.join()

        self._stop_event.clear()
        renewal_interval = lease_duration * 0.7  # Renew at 70% of TTL

        def renew_loop():
            while not self._stop_event.wait(renewal_interval):
                try:
                    self.client.sys.renew_lease(
                        lease_id=self._lease_id,
                        increment=lease_duration
                    )
                    self.logger.info(f"Renewed lease: {self._lease_id}")
                except hvac.exceptions.InvalidRequest:
                    self.logger.warning("Lease expired, obtaining new credentials")
                    self.get_database_credentials()
                    break
                except Exception as e:
                    self.logger.error(f"Lease renewal failed: {e}")

        self._renewal_thread = threading.Thread(target=renew_loop, daemon=True)
        self._renewal_thread.start()

    def revoke_credentials(self):
        """Explicitly revoke current dynamic credentials."""
        if self._lease_id:
            self._stop_event.set()
            self.client.sys.revoke_lease(self._lease_id)
            self.logger.info(f"Revoked lease: {self._lease_id}")
            self._current_creds = None
            self._lease_id = None

    def get_aws_credentials(self, role="s3-readonly"):
        """Request dynamic AWS credentials from Vault."""
        self.authenticate()

        response = self.client.secrets.aws.generate_credentials(
            name=role
        )

        return {
            "access_key": response["data"]["access_key"],
            "secret_key": response["data"]["secret_key"],
            "security_token": response["data"].get("security_token"),
            "lease_id": response["lease_id"],
            "ttl": response["lease_duration"]
        }

# Usage example
vault_mgr = VaultDynamicCredentialManager(
    vault_addr="https://vault.corp.local:8200",
    role_id="<approle-role-id>",
    secret_id="<approle-secret-id>"
)

db_creds = vault_mgr.get_database_credentials("app-readonly")
# Use db_creds["username"] and db_creds["password"] for database connection
```

## Step 6: Monitor Vault Operations and Lease Management

Track dynamic secret usage and lease lifecycle:

```bash
# Monitor active leases
vault list sys/leases/lookup/database/creds/app-readonly
vault list sys/leases/lookup/aws/creds/s3-readonly

# Check lease details
vault write sys/leases/lookup lease_id="database/creds/app-readonly/abcd1234"

# Revoke all leases for a specific path (emergency credential rotation)
vault lease revoke -prefix database/creds/app-readonly

# Vault metrics for monitoring (Prometheus format)
# Key metrics to monitor:
# vault.expire.num_leases - Total active leases
# vault.expire.revoke - Lease revocations per second
# vault.secret.kv.count - Total stored secrets
# vault.runtime.alloc_bytes - Memory allocation

# Configure Vault audit log analysis
cat > vault_audit_monitor.sh << 'SCRIPT'
#!/bin/bash
# Monitor Vault audit logs for suspicious activity

AUDIT_LOG="/var/log/vault/audit.log"

# Count credential requests per hour
echo "=== Dynamic Credential Requests (Last Hour) ==="
jq -r 'select(.type == "response" and .request.path | startswith("database/creds/")) |
    "\(.time) \(.request.path) \(.auth.display_name)"' \
    "$AUDIT_LOG" | tail -100

# Detect unusual credential request patterns
echo ""
echo "=== High-Volume Credential Consumers ==="
jq -r 'select(.type == "request" and .request.path | startswith("database/creds/")) |
    .auth.display_name' \
    "$AUDIT_LOG" | sort | uniq -c | sort -rn | head -10

# Check for failed authentication attempts
echo ""
echo "=== Failed Auth Attempts ==="
jq -r 'select(.type == "response" and .error != null and
    .request.path | startswith("auth/")) |
    "\(.time) \(.request.path) \(.error)"' \
    "$AUDIT_LOG" | tail -20
SCRIPT
chmod +x vault_audit_monitor.sh
```
