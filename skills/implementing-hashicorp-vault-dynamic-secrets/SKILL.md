---
name: implementing-hashicorp-vault-dynamic-secrets
description: Configures HashiCorp Vault dynamic secrets engines for database credentials, AWS IAM keys, and PKI certificates, with automatic generation, lease management, and rotation to eliminate static secrets in application configuration. Use when eliminating long-lived static credentials, configuring a Vault secrets engine, generating ephemeral database or cloud credentials, or automating credential rotation for compliance (PCI-DSS, NIST 800-53 IA-5). Do not use for general Vault static secrets storage and management setup - use implementing-secrets-management-with-vault.
domain: cybersecurity
subdomain: identity-access-management
tags:
- HashiCorp-Vault
- dynamic-secrets
- secrets-management
- database-credentials
- AWS-secrets
- PKI
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
- PR.AA-06
mitre_attack:
- T1078
- T1110
- T1556
- T1098
- T1003
mitre_f3:
  version: '1.1'
  tactics:
  - initial-access
  - positioning
  - stealth
  - resource-development
  techniques:
  - id: F1006.001
    name: 'Account Takeover: Exposed API Key'
    tactic: initial-access
    source: f3
  - id: F1006.002
    name: 'Account Takeover: Exposed Login Credential'
    tactic: initial-access
    source: f3
  - id: T1586
    name: Compromise Accounts
    tactic: resource-development
    source: attack
  - id: T1555
    name: Credentials from Password Stores
    tactic: reconnaissance
    source: attack
  - id: F1005.004
    name: 'Account Manipulation: Change Account Details'
    tactic: positioning
    source: f3
  - id: F1033
    name: Insider Access Abuse
    tactic: initial-access
    source: f3
---

# Implementing HashiCorp Vault Dynamic Secrets

## When to Use

- Applications use static database credentials stored in configuration files or environment variables
- AWS IAM access keys are long-lived and shared across services
- Need to eliminate credential sprawl by generating short-lived, per-request secrets
- Compliance requirements mandate credential rotation (PCI-DSS Requirement 8, NIST 800-53 IA-5)
- Implementing zero-trust secret management where credentials are never stored at rest
- Migrating from manual credential management to automated secrets lifecycle

**Do not use** for storing static secrets that cannot be dynamically generated (use Vault's KV secrets engine instead); dynamic secrets are for credentials that can be programmatically created and revoked on target systems.

## Prerequisites

- HashiCorp Vault 1.15+ (Community or Enterprise edition)
- Vault server initialized and unsealed with auto-unseal configured (AWS KMS, Azure Key Vault, or Transit)
- Target database systems with admin credentials for Vault to create/revoke dynamic accounts
- AWS IAM account with permissions to create/delete IAM users and access keys
- Network connectivity from Vault to all target systems
- Vault policies and authentication methods configured for consuming applications

## Workflow

### Step 1: Deploy and Configure Vault Server

Initialize Vault with production-grade configuration: Raft integrated storage across a 3-node HA cluster, a TLS listener, AWS KMS auto-unseal, telemetry, and the UI. Then bootstrap operationally - `vault operator init` (5 shares / 3 threshold), enable file audit logging, enable AppRole auth, write the `db-consumer` policy (read dynamic creds, renew/revoke own leases), and create the `webapp` AppRole.

See the full `vault-config.hcl` and bootstrap commands in [references/configuration-commands.md](references/configuration-commands.md#step-1-deploy-and-configure-vault-server).

### Step 2: Configure Database Secrets Engine

Set up dynamic credential generation for PostgreSQL and MySQL. Enable the database engine, configure each connection with the `vault_admin` account, rotate the root credential so Vault owns it exclusively, then define roles with creation/revocation SQL statements and TTLs (read-only 1h/24h, read-write 30m/8h). Test with `vault read database/creds/app-readonly`.

See the full database engine commands in [references/configuration-commands.md](references/configuration-commands.md#step-2-configure-database-secrets-engine).

### Step 3: Configure AWS Secrets Engine

Generate ephemeral AWS IAM credentials. Enable the aws engine, configure root credentials and lease settings, then create roles for each credential type: `iam_user` (S3 read-only with an inline policy), `assumed_role` (EC2 admin via STS, preferred over IAM users), and `federation_token` (cross-account read-only). Test with `vault read aws/creds/ec2-admin`.

See the full AWS engine commands and policy documents in [references/configuration-commands.md](references/configuration-commands.md#step-3-configure-aws-secrets-engine).

### Step 4: Configure PKI Secrets Engine for Dynamic Certificates

Generate short-lived TLS certificates on demand. Stand up a root CA (EC P-384) and an intermediate CA, sign the intermediate with the root, configure issuing/CRL URLs, and define roles for web-server certs (30-day max TTL) and service-mesh certs (24h max TTL) with domain and hostname constraints. Issue with `vault write pki_int/issue/web-server`.

See the full PKI engine commands in [references/configuration-commands.md](references/configuration-commands.md#step-4-configure-pki-secrets-engine-for-dynamic-certificates).

### Step 5: Integrate Applications with Vault

Configure applications to consume dynamic secrets. The `VaultDynamicCredentialManager` (hvac client) authenticates via AppRole, requests dynamic database credentials, runs a background thread that renews the lease at 70% of TTL (falling back to re-issuing on expiry), supports explicit revocation, and can likewise fetch dynamic AWS credentials.

See the full Python integration class in [references/configuration-commands.md](references/configuration-commands.md#step-5-integrate-applications-with-vault).

### Step 6: Monitor Vault Operations and Lease Management

Track dynamic secret usage and lease lifecycle. Enumerate and look up active leases, revoke all leases under a path for emergency rotation, watch the key Prometheus metrics (`vault.expire.num_leases`, `vault.expire.revoke`, etc.), and run an audit-log analysis script that surfaces credential-request volume, high-volume consumers, and failed auth attempts via `jq`.

See the full monitoring commands and audit script in [references/configuration-commands.md](references/configuration-commands.md#step-6-monitor-vault-operations-and-lease-management).

## Key Concepts

| Term | Definition |
|------|------------|
| **Dynamic Secrets** | Credentials generated on-demand by Vault with automatic expiration, ensuring each consumer receives unique short-lived credentials |
| **Lease** | Time-bound agreement where Vault guarantees the credential is valid; consumers must renew before expiration or request new credentials |
| **Secrets Engine** | Vault plugin that generates, stores, or encrypts data; database, AWS, PKI, and KV are common engines |
| **AppRole** | Vault authentication method designed for machine-to-machine authentication using role ID and secret ID pairs |
| **Root Credential Rotation** | Process of having Vault take exclusive ownership of the admin credential used to create dynamic secrets, eliminating human knowledge of the root password |
| **Lease Revocation** | Immediate invalidation of dynamic credentials, used during incident response to revoke all credentials for compromised paths |

## Tools & Systems

- **HashiCorp Vault**: Secrets management platform providing dynamic secrets, encryption as a service, and identity-based access control
- **Vault Agent**: Sidecar process that handles Vault authentication, token renewal, and secret caching for applications
- **Vault Secrets Operator**: Kubernetes operator that syncs Vault secrets into Kubernetes Secrets for pod consumption
- **hvac**: Python client library for HashiCorp Vault API operations

## Common Scenarios

### Scenario: Eliminating Static Database Credentials in Microservices

**Context**: 50 microservices share 3 static PostgreSQL credentials stored in environment variables across Kubernetes deployments. A credential leak requires rotating all 50 services simultaneously.

**Approach**:
1. Deploy Vault with Raft storage in a 3-node HA cluster within Kubernetes
2. Configure database secrets engine with PostgreSQL connection using admin credentials
3. Create per-service Vault roles with least-privilege SQL grants
4. Deploy Vault Secrets Operator to inject dynamic credentials into pod environment variables
5. Update application connection logic to handle credential rotation via lease renewal
6. Rotate the Vault root credential to remove human knowledge of the admin password
7. Monitor lease lifecycle and set alerts for renewal failures

**Pitfalls**:
- Not handling credential rotation in application connection pools (connections using expired credentials fail)
- Setting TTLs too short causes excessive credential generation load on the database
- Not configuring proper revocation statements leaves orphaned database users after lease expiration
- Running Vault without HA causes single point of failure for all application authentication

## Output Format

```
HASHICORP VAULT DYNAMIC SECRETS REPORT
=========================================
Vault Version:     1.16.2 Enterprise
Cluster Status:    HA Active (3 nodes)
Seal Type:         AWS KMS (auto-unseal)

SECRETS ENGINES
database/:         PostgreSQL, MySQL (2 connections)
aws/:              IAM User, Assumed Role, Federation Token
pki_int/:          Internal CA (EC P-256)

DYNAMIC CREDENTIAL METRICS (Last 24 Hours)
Total Credentials Generated:    4,287
  Database (PostgreSQL):        2,891
  Database (MySQL):             543
  AWS STS:                      612
  PKI Certificates:             241

ACTIVE LEASES
Total Active:                   387
  database/creds/app-readonly:  198
  database/creds/app-readwrite: 89
  aws/creds/s3-readonly:        67
  pki_int/issue/web-server:     33

LEASE LIFECYCLE
Average TTL:                    45 minutes
Renewals (24h):                 12,847
Revocations (24h):              3,901
Expired (not renewed):          12

SECURITY
Failed Auth Attempts (24h):     3
Root Credential Rotated:        YES (all databases)
Audit Logging:                  ENABLED (file + syslog)
Policy Violations (24h):        7 (permission denied)
```
