---
name: implementing-zero-trust-with-hashicorp-boundary
description: Installs and configures HashiCorp Boundary as a default-deny, identity-aware proxy for infrastructure access, including controller/worker setup, Vault-backed credential brokering, session recording, and OIDC/LDAP auth across an org/project scope hierarchy. Use when replacing VPN or direct network access with just-in-time, credential-less Boundary sessions, or standing up Boundary controllers and workers. Do not use for Google Cloud IAP identity-aware proxy - use configuring-identity-aware-proxy-with-google-iap.
domain: cybersecurity
subdomain: zero-trust-architecture
tags:
- zero-trust
- hashicorp
- boundary
- privileged-access
- vault
- identity-aware-proxy
- session-recording
- just-in-time-access
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.AA-01
- PR.AA-05
- PR.IR-01
- GV.PO-01
mitre_attack:
- T1078
- T1190
- T1059
- T1003
- T1110
mitre_f3:
  version: '1.1'
  tactics:
  - initial-access
  - positioning
  - resource-development
  techniques:
  - id: T1586
    name: Compromise Accounts
    tactic: resource-development
    source: attack
  - id: T1110
    name: Brute Force
    tactic: initial-access
    source: attack
  - id: T1110.004
    name: 'Brute Force:  Credential Stuffing'
    tactic: initial-access
    source: attack
  - id: T1219
    name: Remote Access Tools
    tactic: positioning
    source: attack
  - id: F1033
    name: Insider Access Abuse
    tactic: initial-access
    source: f3
---

# Implementing Zero Trust with HashiCorp Boundary

## Overview

HashiCorp Boundary is an identity-aware proxy that provides secure, zero trust access to infrastructure resources without traditional VPNs or direct network access. Boundary operates on a default-deny model -- users start with no access and must be explicitly granted permissions for specific resources. When integrated with HashiCorp Vault, Boundary can dynamically broker credentials, ensuring users never see or manage underlying secrets. This eliminates credential sprawl and enables just-in-time access with automatic credential revocation when sessions end. Boundary supports session recording for audit compliance, OIDC/LDAP authentication, and manages access through a hierarchical scope model of organizations and projects.


## When to Use

- When deploying or configuring implementing zero trust with hashicorp boundary capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

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

### Host Catalogs, Targets, Vault Brokering, and RBAC

Building on the scope and OIDC auth-method resources above, define static host catalogs
and host sets, SSH/database targets (with session limits, recording, and Vault
credential injection or brokering), the Vault credential store and libraries that supply
dynamic database credentials and signed SSH certificates, and least-privilege roles bound
to the OIDC managed groups. Full Terraform for these resources: see
[references/terraform-targets-vault-rbac.md](references/terraform-targets-vault-rbac.md).

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
