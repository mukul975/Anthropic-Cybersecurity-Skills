---
name: implementing-zero-trust-with-hashicorp-boundary
description: Implement HashiCorp Boundary for identity-aware zero trust infrastructure access management with dynamic credential brokering, session recording, and Vault integration.
domain: cybersecurity
subdomain: zero-trust-architecture
tags: [zero-trust, hashicorp, boundary, privileged-access, vault, identity-aware-proxy, session-recording, just-in-time-access]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Zero Trust with HashiCorp Boundary

## Overview

HashiCorp Boundary is an identity-aware proxy that provides secure, zero trust access to infrastructure resources without traditional VPNs or direct network access. Boundary operates on a default-deny model -- users start with no access and must be explicitly granted permissions for specific resources. When integrated with HashiCorp Vault, Boundary can dynamically broker credentials, ensuring users never see or manage underlying secrets. This eliminates credential sprawl and enables just-in-time access with automatic credential revocation when sessions end. Boundary supports session recording for audit compliance, OIDC/LDAP authentication, and manages access through a hierarchical scope model of organizations and projects.

## Prerequisites

- HashiCorp Boundary server (self-hosted or HCP Boundary)
- HashiCorp Vault (for credential brokering)
- Identity provider supporting OIDC (Okta, Azure AD, Auth0)
- PostgreSQL database for Boundary's backend
- TLS certificates for secure communication
- Understanding of PKI and X.509 certificate management

## Architecture

```
                    Identity Provider (OIDC)
                           |
                    Authentication
                           |
                  +--------+--------+
                  |   Boundary      |
                  |   Controller    |
                  |  (Control Plane)|
                  +--------+--------+
                           |
              +------------+------------+
              |                         |
     +--------+--------+      +--------+--------+
     | Boundary Worker |      | Boundary Worker |
     | (Data Plane)    |      | (Data Plane)    |
     +--------+--------+      +--------+--------+
              |                         |
     +--------+--------+      +--------+--------+
     |  Target Hosts   |      |  Target Hosts   |
     |  (SSH, RDP,     |      |  (Databases,    |
     |   K8s, HTTP)    |      |   APIs)         |
     +-----------------+      +-----------------+

     Vault (Credential Brokering)
     - Dynamic database credentials
     - SSH certificate signing
     - Credential libraries
```

## Installation and Configuration

### Boundary Server Setup

```bash
# Install Boundary
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install boundary

# Initialize the database
boundary database init \
  -config=/etc/boundary/controller.hcl

# Start the controller
boundary server -config=/etc/boundary/controller.hcl
```

### Controller Configuration

```hcl
# /etc/boundary/controller.hcl
controller {
  name = "boundary-controller-1"
  description = "Primary Boundary Controller"
  database {
    url = "postgresql://boundary:password@localhost:5432/boundary?sslmode=require"
  }
  public_cluster_addr = "boundary.example.com"
}

listener "tcp" {
  address = "0.0.0.0:9200"
  purpose = "api"
  tls_cert_file = "/etc/boundary/tls/cert.pem"
  tls_key_file  = "/etc/boundary/tls/key.pem"
}

listener "tcp" {
  address = "0.0.0.0:9201"
  purpose = "cluster"
  tls_cert_file = "/etc/boundary/tls/cert.pem"
  tls_key_file  = "/etc/boundary/tls/key.pem"
}

kms "aead" {
  purpose = "root"
  aead_type = "aes-gcm"
  key = "sP1fnF5Xz85RrXM..."  # Use Vault Transit in production
  key_id = "global_root"
}

kms "aead" {
  purpose = "worker-auth"
  aead_type = "aes-gcm"
  key = "8fZBjCUfN0TzjEG..."
  key_id = "global_worker-auth"
}

kms "aead" {
  purpose = "recovery"
  aead_type = "aes-gcm"
  key = "8fZBjCUfN0TzjEG..."
  key_id = "global_recovery"
}
```

### Worker Configuration

```hcl
# /etc/boundary/worker.hcl
worker {
  name = "boundary-worker-1"
  description = "Worker in production VPC"
  public_addr = "worker1.example.com"

  controllers = [
    "boundary.example.com:9201"
  ]

  tags {
    type = ["production"]
    region = ["us-east-1"]
  }
}

listener "tcp" {
  address = "0.0.0.0:9202"
  purpose = "proxy"
}

kms "aead" {
  purpose = "worker-auth"
  aead_type = "aes-gcm"
  key = "8fZBjCUfN0TzjEG..."
  key_id = "global_worker-auth"
}
```

## Terraform Configuration

### Scope and Auth Configuration

```hcl
# main.tf - Boundary resources via Terraform
terraform {
  required_providers {
    boundary = {
      source  = "hashicorp/boundary"
      version = "~> 1.1"
    }
  }
}

provider "boundary" {
  addr             = "https://boundary.example.com:9200"
  recovery_kms_hcl = file("recovery_kms.hcl")
}

# Organization scope
resource "boundary_scope" "org" {
  scope_id                 = "global"
  name                     = "production-org"
  description              = "Production organization scope"
  auto_create_admin_role   = true
  auto_create_default_role = true
}

# Project scope
resource "boundary_scope" "production" {
  name                     = "production"
  description              = "Production infrastructure project"
  scope_id                 = boundary_scope.org.id
  auto_create_admin_role   = true
  auto_create_default_role = true
}

# OIDC Auth Method (Okta example)
resource "boundary_auth_method_oidc" "okta" {
  scope_id               = boundary_scope.org.id
  name                   = "okta"
  description            = "Okta OIDC authentication"
  issuer                 = "https://company.okta.com/oauth2/default"
  client_id              = var.okta_client_id
  client_secret          = var.okta_client_secret
  signing_algorithms     = ["RS256"]
  api_url_prefix         = "https://boundary.example.com:9200"
  claims_scopes          = ["groups"]
  account_claim_maps     = ["oid=sub"]
  is_primary_for_scope   = true
}

# Managed group for auto-assignment
resource "boundary_managed_group" "sre_team" {
  auth_method_id = boundary_auth_method_oidc.okta.id
  name           = "sre-team"
  description    = "SRE team members from Okta"
  filter         = "\"sre-team\" in \"/token/groups\""
}

resource "boundary_managed_group" "dev_team" {
  auth_method_id = boundary_auth_method_oidc.okta.id
  name           = "dev-team"
  description    = "Development team from Okta"
  filter         = "\"dev-team\" in \"/token/groups\""
}
```

### Host Catalogs and Targets

```hcl
# Static host catalog for known infrastructure
resource "boundary_host_catalog_static" "production_servers" {
  name     = "production-servers"
  scope_id = boundary_scope.production.id
}

resource "boundary_host_static" "web_server" {
  name            = "web-server-1"
  host_catalog_id = boundary_host_catalog_static.production_servers.id
  address         = "10.0.1.10"
}

resource "boundary_host_static" "db_server" {
  name            = "db-server-1"
  host_catalog_id = boundary_host_catalog_static.production_servers.id
  address         = "10.0.2.20"
}

# Host set grouping
resource "boundary_host_set_static" "web_servers" {
  name            = "web-servers"
  host_catalog_id = boundary_host_catalog_static.production_servers.id
  host_ids        = [boundary_host_static.web_server.id]
}

resource "boundary_host_set_static" "db_servers" {
  name            = "database-servers"
  host_catalog_id = boundary_host_catalog_static.production_servers.id
  host_ids        = [boundary_host_static.db_server.id]
}

# SSH target
resource "boundary_target" "ssh_production" {
  name         = "ssh-production-servers"
  description  = "SSH access to production servers"
  type         = "ssh"
  scope_id     = boundary_scope.production.id
  default_port = 22

  host_source_ids = [
    boundary_host_set_static.web_servers.id
  ]

  session_max_seconds          = 3600  # 1 hour max session
  session_connection_limit     = 1
  enable_session_recording     = true
  storage_bucket_id            = boundary_storage_bucket.sessions.id

  injected_application_credential_source_ids = [
    boundary_credential_library_vault_ssh_certificate.ssh_cert.id
  ]
}

# Database target with Vault credential brokering
resource "boundary_target" "postgres_production" {
  name         = "postgres-production"
  description  = "PostgreSQL production database"
  type         = "tcp"
  scope_id     = boundary_scope.production.id
  default_port = 5432

  host_source_ids = [
    boundary_host_set_static.db_servers.id
  ]

  session_max_seconds      = 1800  # 30 min max
  session_connection_limit = 5

  brokered_credential_source_ids = [
    boundary_credential_library_vault.postgres_creds.id
  ]
}
```

### Vault Integration for Credential Brokering

```hcl
# Vault credential store
resource "boundary_credential_store_vault" "vault" {
  name        = "vault-store"
  scope_id    = boundary_scope.production.id
  address     = "https://vault.example.com:8200"
  token       = var.vault_token
  namespace   = "production"
}

# Dynamic database credentials from Vault
resource "boundary_credential_library_vault" "postgres_creds" {
  name                = "postgres-dynamic-creds"
  credential_store_id = boundary_credential_store_vault.vault.id
  path                = "database/creds/readonly"
  http_method         = "GET"
  credential_type     = "username_password"
}

# SSH certificate signing via Vault
resource "boundary_credential_library_vault_ssh_certificate" "ssh_cert" {
  name                = "ssh-certificate"
  credential_store_id = boundary_credential_store_vault.vault.id
  path                = "ssh-client-signer/sign/production"
  username            = "admin"
  key_type            = "ed25519"
  key_bits            = 256
  extensions = {
    "permit-pty" = ""
  }
}

# Session recording storage
resource "boundary_storage_bucket" "sessions" {
  name        = "session-recordings"
  scope_id    = "global"
  plugin_name = "aws"
  bucket_name = "boundary-session-recordings"
  attributes_json = jsonencode({
    "region"                      = "us-east-1"
    "disable_credential_rotation" = true
  })
  secrets_json = jsonencode({
    "access_key_id"     = var.aws_access_key
    "secret_access_key" = var.aws_secret_key
  })
}
```

### Role-Based Access Control

```hcl
# SRE team role - full production access
resource "boundary_role" "sre_production" {
  name          = "sre-production-access"
  scope_id      = boundary_scope.production.id
  grant_strings = [
    "ids=*;type=target;actions=list,read,authorize-session",
    "ids=*;type=session;actions=list,read,cancel",
    "ids=*;type=host;actions=list,read",
  ]
  principal_ids = [
    boundary_managed_group.sre_team.id
  ]
}

# Dev team role - limited access
resource "boundary_role" "dev_staging" {
  name          = "dev-staging-access"
  scope_id      = boundary_scope.production.id
  grant_strings = [
    "ids=${boundary_target.ssh_production.id};type=target;actions=read,authorize-session",
  ]
  principal_ids = [
    boundary_managed_group.dev_team.id
  ]
}
```

## Connecting to Targets

```bash
# Authenticate via OIDC
boundary authenticate oidc \
  -auth-method-id amoidc_xxxxx

# List available targets
boundary targets list -scope-id p_xxxxx

# Connect to SSH target (credentials injected by Vault)
boundary connect ssh \
  -target-id ttcp_xxxxx

# Connect to database (credentials brokered by Vault)
boundary connect postgres \
  -target-id ttcp_xxxxx \
  -dbname production

# Use Boundary Desktop client for GUI access
# Download from: https://developer.hashicorp.com/boundary/install
```

## Session Recording and Auditing

```bash
# List session recordings
boundary session-recordings list \
  -scope-id p_xxxxx

# Download session recording for review
boundary session-recordings download \
  -id sr_xxxxx \
  -output recording.cast

# Play back with asciinema
asciinema play recording.cast
```

## Dynamic Host Catalogs

```hcl
# AWS dynamic host catalog - auto-discovers EC2 instances
resource "boundary_host_catalog_plugin" "aws_catalog" {
  scope_id    = boundary_scope.production.id
  name        = "aws-production"
  plugin_name = "aws"

  attributes_json = jsonencode({
    "region"                      = "us-east-1"
    "disable_credential_rotation" = true
  })

  secrets_json = jsonencode({
    "access_key_id"     = var.aws_access_key
    "secret_access_key" = var.aws_secret_key
  })
}

resource "boundary_host_set_plugin" "web_tier" {
  host_catalog_id = boundary_host_catalog_plugin.aws_catalog.id
  name            = "web-tier"
  attributes_json = jsonencode({
    "filters" = [
      "tag:Environment=production",
      "tag:Tier=web"
    ]
  })
}
```

## Security Best Practices

1. **Use Vault KMS for key management** instead of static AEAD keys in production
2. **Enable session recording** for all privileged access targets
3. **Set session time limits** appropriate to the resource sensitivity
4. **Use OIDC managed groups** for automatic role assignment from IdP
5. **Deploy multi-hop workers** for accessing resources across network boundaries
6. **Rotate Vault tokens** used by credential stores regularly
7. **Enable audit logging** on both controllers and workers
8. **Use credential injection** (SSH certificates) over brokering when possible
9. **Implement least-privilege grants** -- avoid wildcard permissions
10. **Review session recordings** regularly for compliance and incident response

## References

- [HashiCorp Boundary Documentation](https://developer.hashicorp.com/boundary/docs)
- [Boundary and Vault Integration](https://developer.hashicorp.com/boundary/docs/concepts/credential-management)
- [From Zero to Hero with Boundary](https://www.hashicorp.com/en/blog/from-zero-to-hero-hashicorp-boundary)
- [Boundary Terraform Provider](https://registry.terraform.io/providers/hashicorp/boundary/latest/docs)
- [Zero Trust with Vault, Consul, and Boundary](https://www.hashicorp.com/en/resources/zero-trust-security-with-hashicorp-vault-consul-and-boundary)
