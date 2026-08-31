# Boundary Terraform: Host Catalogs, Targets, Vault Brokering, and RBAC

Companion depth for the Terraform Configuration section of `SKILL.md`. These resources
build on the scope and OIDC auth-method definitions in the body: static host catalogs
and hosts, SSH/database targets (with session recording and credential injection),
Vault credential stores and libraries for dynamic brokering, and least-privilege roles.

## Host Catalogs and Targets

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

## Vault Integration for Credential Brokering

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

## Role-Based Access Control

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
