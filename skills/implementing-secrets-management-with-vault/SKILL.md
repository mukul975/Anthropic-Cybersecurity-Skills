---
name: implementing-secrets-management-with-vault
description: >
  This skill covers deploying HashiCorp Vault for centralized secrets management across
  cloud environments, including dynamic secret generation for databases and cloud providers,
  transit encryption, PKI certificate management, and Kubernetes integration. It addresses
  eliminating hardcoded credentials from application code and CI/CD pipelines by implementing
  short-lived, automatically rotated secrets.
domain: cybersecurity
subdomain: cloud-security
tags: [hashicorp-vault, secrets-management, dynamic-secrets, credential-rotation, zero-trust]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Implementing Secrets Management with Vault

## When to Use

- When applications store database passwords, API keys, or certificates in environment variables or config files
- When migrating from static long-lived credentials to dynamic short-lived secrets
- When Kubernetes workloads need secure access to database credentials or cloud provider APIs
- When compliance requirements mandate centralized credential management with audit logging
- When CI/CD pipelines contain hardcoded secrets that represent supply chain risk

**Do not use** for AWS-only environments where AWS Secrets Manager suffices without multi-cloud requirements, for application-level encryption logic (though Vault Transit can help), or for identity federation (see managing-cloud-identity-with-okta).

## Prerequisites

- HashiCorp Vault server deployed in HA mode (Consul or Raft storage backend)
- TLS certificates for Vault listener endpoints
- Vault Enterprise license for namespaces, Sentinel policies, and replication (optional)
- Kubernetes cluster with Vault Agent Injector or CSI provider for workload integration

## Workflow

### Step 1: Deploy Vault in High Availability Mode

Deploy Vault using Integrated Storage (Raft) for HA without external dependencies. Configure TLS, audit logging, and auto-unseal using a cloud KMS.

```hcl
# vault-config.hcl
storage "raft" {
  path    = "/opt/vault/data"
  node_id = "vault-node-1"

  retry_join {
    leader_api_addr = "https://vault-node-2.internal:8200"
  }
  retry_join {
    leader_api_addr = "https://vault-node-3.internal:8200"
  }
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_cert_file = "/opt/vault/tls/vault.crt"
  tls_key_file  = "/opt/vault/tls/vault.key"
}

seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "alias/vault-unseal-key"
}

api_addr      = "https://vault-node-1.internal:8200"
cluster_addr  = "https://vault-node-1.internal:8201"

telemetry {
  prometheus_retention_time = "30s"
  disable_hostname         = true
}
```

```bash
# Initialize Vault
vault operator init -key-shares=5 -key-threshold=3

# Enable audit logging
vault audit enable file file_path=/var/log/vault/audit.log

# Enable syslog audit for SIEM integration
vault audit enable syslog tag="vault" facility="AUTH"
```

### Step 2: Configure Authentication Methods

Enable authentication backends for human operators, applications, and CI/CD pipelines. Use AppRole for machine authentication and OIDC for human access.

```bash
# Enable OIDC auth for human users via Okta
vault auth enable oidc
vault write auth/oidc/config \
  oidc_discovery_url="https://company.okta.com/oauth2/default" \
  oidc_client_id="vault-client-id" \
  oidc_client_secret="vault-client-secret" \
  default_role="default"

# Enable AppRole for application authentication
vault auth enable approle
vault write auth/approle/role/web-app \
  secret_id_ttl=10m \
  token_num_uses=10 \
  token_ttl=20m \
  token_max_ttl=30m \
  secret_id_num_uses=1 \
  token_policies="web-app-policy"

# Enable Kubernetes auth for pod-based access
vault auth enable kubernetes
vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc:443" \
  token_reviewer_jwt=@/var/run/secrets/kubernetes.io/serviceaccount/token \
  kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

### Step 3: Enable Dynamic Secret Engines

Configure database secret engines to generate short-lived credentials on demand. Each credential set has a TTL and is automatically revoked when it expires.

```bash
# Enable database secrets engine for PostgreSQL
vault secrets enable database
vault write database/config/production-db \
  plugin_name=postgresql-database-plugin \
  allowed_roles="readonly,readwrite" \
  connection_url="postgresql://{{username}}:{{password}}@db.internal:5432/production?sslmode=require" \
  username="vault_admin" \
  password="initial-password"

# Rotate the root credentials so Vault manages them exclusively
vault write -force database/rotate-root/production-db

# Create a readonly role with 1-hour TTL
vault write database/roles/readonly \
  db_name=production-db \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  revocation_statements="REVOKE ALL ON ALL TABLES IN SCHEMA public FROM \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="24h"

# Enable AWS secrets engine for dynamic IAM credentials
vault secrets enable aws
vault write aws/config/root \
  access_key=AKIAEXAMPLE \
  secret_key=secretkey \
  region=us-east-1

vault write aws/roles/deploy-role \
  credential_type=iam_user \
  policy_document=@deploy-policy.json \
  default_sts_ttl=3600
```

### Step 4: Integrate with Kubernetes Workloads

Use the Vault Agent Injector or CSI Provider to deliver secrets to pods without application code changes. Secrets are rendered as files in a shared volume.

```yaml
# Kubernetes deployment with Vault Agent Injector annotations
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "web-app"
        vault.hashicorp.com/agent-inject-secret-db-creds: "database/creds/readonly"
        vault.hashicorp.com/agent-inject-template-db-creds: |
          {{- with secret "database/creds/readonly" -}}
          export DB_USERNAME="{{ .Data.username }}"
          export DB_PASSWORD="{{ .Data.password }}"
          {{- end }}
    spec:
      serviceAccountName: web-app
      containers:
        - name: web-app
          image: company/web-app:v2.1
          command: ["/bin/sh", "-c", "source /vault/secrets/db-creds && ./start.sh"]
```

### Step 5: Implement Transit Encryption and PKI

Use the Transit secrets engine for application-level encryption without managing keys in application code. Deploy the PKI engine for automatic TLS certificate management.

```bash
# Enable Transit engine for encryption as a service
vault secrets enable transit
vault write -f transit/keys/payment-data type=aes256-gcm96

# Encrypt sensitive data
vault write transit/encrypt/payment-data \
  plaintext=$(echo "card-number-4111-1111-1111-1111" | base64)

# Enable PKI for internal certificate management
vault secrets enable pki
vault secrets tune -max-lease-ttl=87600h pki

# Generate root CA
vault write pki/root/generate/internal \
  common_name="Internal Root CA" \
  ttl=87600h

# Configure intermediate CA for issuing certificates
vault secrets enable -path=pki_int pki
vault write pki_int/intermediate/generate/internal \
  common_name="Internal Intermediate CA" \
  ttl=43800h

# Create a role for issuing certificates
vault write pki_int/roles/internal-services \
  allowed_domains="internal.company.com" \
  allow_subdomains=true \
  max_ttl=720h
```

### Step 6: Establish Policies and Audit Trail

Define fine-grained ACL policies following least privilege. Enable comprehensive audit logging for all secret access and administrative operations.

```hcl
# web-app-policy.hcl
path "database/creds/readonly" {
  capabilities = ["read"]
}

path "transit/encrypt/payment-data" {
  capabilities = ["update"]
}

path "transit/decrypt/payment-data" {
  capabilities = ["update"]
}

path "secret/data/web-app/*" {
  capabilities = ["read", "list"]
}

# Deny access to admin paths
path "sys/*" {
  capabilities = ["deny"]
}
```

```bash
# Apply the policy
vault policy write web-app-policy web-app-policy.hcl

# Verify audit log captures all operations
vault audit list -detailed
```

## Key Concepts

| Term | Definition |
|------|------------|
| Dynamic Secrets | Credentials generated on-demand with automatic expiration and revocation, eliminating long-lived static credentials |
| Secret Engine | Vault component that stores, generates, or encrypts data; includes KV, database, AWS, PKI, and Transit engines |
| Auto-Unseal | Cloud KMS-based mechanism that automatically unseals Vault nodes on restart without manual key entry |
| AppRole | Machine-oriented authentication method using Role ID and Secret ID for application and CI/CD pipeline access |
| Transit Engine | Encryption-as-a-service engine that handles cryptographic operations without exposing encryption keys to applications |
| Lease | Time-bound credential with a TTL that Vault automatically revokes on expiration unless renewed |
| Namespace | Vault Enterprise feature providing tenant isolation with separate auth, secrets, and policy management |
| Response Wrapping | Technique that wraps secret responses in a single-use token to prevent man-in-the-middle exposure during delivery |

## Tools & Systems

- **HashiCorp Vault**: Core secrets management platform providing dynamic secrets, encryption, and identity-based access
- **Vault Agent Injector**: Kubernetes mutating webhook that automatically injects Vault secrets into pod volumes via sidecar containers
- **Vault CSI Provider**: Kubernetes CSI driver that mounts Vault secrets directly into pod volumes without sidecar containers
- **consul-template**: Template rendering daemon that watches Vault secrets and re-renders configuration files when secrets change
- **Vault Radar**: Secret scanning tool that detects hardcoded credentials in source code, CI/CD pipelines, and cloud configurations

## Common Scenarios

### Scenario: Eliminating Hardcoded Database Credentials from CI/CD Pipeline

**Context**: A DevOps team stores PostgreSQL credentials in GitHub Actions secrets and Jenkins credential stores. The same credentials are shared across staging and production environments with no rotation for 18 months.

**Approach**:
1. Deploy Vault with AppRole auth enabled for CI/CD systems
2. Configure the database secrets engine with separate roles for staging (readwrite, 2h TTL) and production (readonly, 1h TTL)
3. Create separate Vault policies for each pipeline stage restricting access to the appropriate database role
4. Update GitHub Actions workflows to authenticate via AppRole and request dynamic credentials at the start of each job
5. Rotate the static PostgreSQL credentials and hand root access to Vault exclusively
6. Enable audit logging to track every credential request with pipeline job metadata

**Pitfalls**: Failing to rotate the original static credentials after Vault migration leaves the old credentials valid. Setting TTLs too short causes credential expiry mid-deployment for long-running jobs.

## Output Format

```
Vault Secrets Management Audit Report
=======================================
Vault Cluster: vault.internal.company.com
Version: 1.18.1 Enterprise
HA Mode: Raft (3 nodes)
Seal Type: AWS KMS Auto-Unseal
Report Date: 2025-02-23

SECRET ENGINES:
  database/         PostgreSQL dynamic creds   Leases Active: 47
  aws/              Dynamic IAM credentials    Leases Active: 12
  transit/          Encryption as a service    Keys: 8
  pki/              Root CA                    Certs Issued: 0
  pki_int/          Intermediate CA            Certs Issued: 234
  secret/           KV v2 static secrets       Versions: 1,892

AUTH METHODS:
  oidc/             Okta SSO for humans        Active Tokens: 23
  approle/          CI/CD pipelines            Active Tokens: 156
  kubernetes/       Pod-based auth             Active Tokens: 89

AUDIT FINDINGS:
  [WARN] 3 AppRole secret_id_num_uses set to 0 (unlimited)
  [WARN] 12 KV secrets not accessed in 90+ days (potential orphans)
  [PASS] All dynamic secret TTLs under 24 hours
  [PASS] Audit logging enabled on all nodes
  [PASS] Root token revoked after initial setup

CREDENTIAL HYGIENE:
  Static Secrets (KV): 234
  Dynamic Secrets Active: 59
  Average Lease TTL: 2.3 hours
  Secrets Rotated This Month: 12,456
```
