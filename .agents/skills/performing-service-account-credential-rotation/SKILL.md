---
name: performing-service-account-credential-rotation
description: Automate credential rotation for service accounts across Active Directory, cloud platforms, and application databases to eliminate stale secrets and reduce compromise risk.
domain: cybersecurity
subdomain: identity-access-management
tags: [service-accounts, credential-rotation, secrets-management, pam, automation, vault]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Service Account Credential Rotation

## Overview

Service accounts are non-human identities used by applications, daemons, CI/CD pipelines, and automated processes to authenticate to systems and APIs. These accounts often have elevated privileges and their credentials (passwords, API keys, certificates, tokens) are frequently long-lived and shared across teams, making them prime targets for attackers. Credential rotation is the systematic process of replacing these secrets on a scheduled basis, propagating new credentials to all dependent systems, and verifying service continuity after rotation.

## Prerequisites

- Inventory of all service accounts across AD, cloud, and applications
- Secrets management platform (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or CyberArk)
- Service dependency mapping (which services use which credentials)
- Change management process for rotation windows
- Monitoring for service health post-rotation

## Core Concepts

### Service Account Types

| Type | Platform | Credential | Rotation Method |
|------|----------|-----------|-----------------|
| Active Directory Service Account | Windows/AD | Password | gMSA (automatic) or PAM-managed |
| AWS IAM User | AWS | Access Key/Secret Key | AWS Secrets Manager rotation Lambda |
| GCP Service Account | GCP | JSON key file | Key rotation via IAM API |
| Azure Service Principal | Azure | Client secret/certificate | Key Vault + rotation policy |
| Database Service Account | SQL/Oracle/Postgres | Password | Vault dynamic secrets |
| API Key | SaaS applications | API token | Application-specific API |

### Group Managed Service Accounts (gMSA)

Windows gMSAs provide automatic password management by Active Directory:
- AD automatically rotates the password every 30 days
- Password is 240 bytes, cryptographically random
- Multiple servers can use the same gMSA simultaneously
- No administrator knows or manages the password
- Eliminates manual rotation for Windows services

### Rotation Architecture

```
Secrets Manager / Vault
        │
        ├── Rotation Trigger (schedule or on-demand)
        │
        ├── Generate new credential
        │
        ├── Update credential at source (AD, cloud IAM, database)
        │
        ├── Update credential in all consumers:
        │   ├── Application configuration
        │   ├── CI/CD pipeline secrets
        │   ├── Kubernetes secrets
        │   └── Other dependent services
        │
        ├── Verify service health
        │   ├── Health check endpoints
        │   ├── Authentication test
        │   └── Functional smoke test
        │
        └── Revoke old credential (after grace period)
```

## Implementation Steps

### Step 1: Discover and Inventory Service Accounts

Enumerate all service accounts and their dependencies:

```powershell
# Active Directory: Find all service accounts
Get-ADServiceAccount -Filter * -Properties *
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName,PasswordLastSet,LastLogonDate

# Find accounts with passwords older than 90 days
$threshold = (Get-Date).AddDays(-90)
Get-ADUser -Filter {PasswordLastSet -lt $threshold -and Enabled -eq $true} -Properties PasswordLastSet,ServicePrincipalName |
    Where-Object {$_.ServicePrincipalName} |
    Select-Object Name, PasswordLastSet, ServicePrincipalName
```

### Step 2: Implement gMSA for Windows Services

```powershell
# Create KDS Root Key (one-time, domain-wide)
Add-KdsRootKey -EffectiveImmediately

# Create the gMSA account
New-ADServiceAccount -Name "svc-webapp-gmsa" `
    -DNSHostName "svc-webapp-gmsa.corp.example.com" `
    -PrincipalsAllowedToRetrieveManagedPassword "WebServerGroup" `
    -KerberosEncryptionType AES128,AES256

# Install on target server
Install-ADServiceAccount -Identity "svc-webapp-gmsa"

# Test the account
Test-ADServiceAccount -Identity "svc-webapp-gmsa"

# Configure IIS Application Pool to use gMSA
# Set identity to: CORP\svc-webapp-gmsa$
```

### Step 3: AWS Access Key Rotation with Secrets Manager

```python
import boto3
import json

def rotate_iam_access_key(secret_arn, iam_username):
    """Rotate an IAM user's access key via Secrets Manager."""
    iam = boto3.client("iam")
    sm = boto3.client("secretsmanager")

    # Create new access key
    new_key = iam.create_access_key(UserName=iam_username)
    new_access_key = new_key["AccessKey"]["AccessKeyId"]
    new_secret_key = new_key["AccessKey"]["SecretAccessKey"]

    # Store new credentials in Secrets Manager
    sm.put_secret_value(
        SecretId=secret_arn,
        SecretString=json.dumps({
            "accessKeyId": new_access_key,
            "secretAccessKey": new_secret_key,
            "username": iam_username,
        })
    )

    # List old access keys and deactivate them
    keys = iam.list_access_keys(UserName=iam_username)
    for key in keys["AccessKeyMetadata"]:
        if key["AccessKeyId"] != new_access_key and key["Status"] == "Active":
            iam.update_access_key(
                UserName=iam_username,
                AccessKeyId=key["AccessKeyId"],
                Status="Inactive"
            )

    return {"new_key_id": new_access_key, "old_keys_deactivated": True}
```

### Step 4: Database Credential Rotation with Vault

```python
import hvac

def configure_vault_database_rotation(vault_url, vault_token, db_config):
    """Configure HashiCorp Vault for automatic database credential rotation."""
    client = hvac.Client(url=vault_url, token=vault_token)

    # Enable database secrets engine
    client.sys.enable_secrets_engine(
        backend_type="database",
        path="database"
    )

    # Configure database connection
    client.secrets.database.configure(
        name=db_config["name"],
        plugin_name="postgresql-database-plugin",
        connection_url=f"postgresql://{{{{username}}}}:{{{{password}}}}@"
                       f"{db_config['host']}:{db_config['port']}/{db_config['database']}",
        allowed_roles=[db_config["role_name"]],
        username=db_config["admin_user"],
        password=db_config["admin_password"],
    )

    # Create a role for dynamic credentials
    client.secrets.database.create_role(
        name=db_config["role_name"],
        db_name=db_config["name"],
        creation_statements=[
            "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{{{name}}}}\";"
        ],
        default_ttl="1h",
        max_ttl="24h",
    )

    return {"status": "configured", "role": db_config["role_name"]}
```

### Step 5: Post-Rotation Verification

After every rotation, verify service continuity:

```python
import requests
import time

def verify_service_health(service_endpoints, max_retries=3, delay=10):
    """Check that services are healthy after credential rotation."""
    results = []
    for endpoint in service_endpoints:
        for attempt in range(max_retries):
            try:
                response = requests.get(
                    endpoint["health_url"],
                    timeout=10,
                    headers=endpoint.get("headers", {})
                )
                healthy = response.status_code == 200
                results.append({
                    "service": endpoint["name"],
                    "status": "healthy" if healthy else f"unhealthy ({response.status_code})",
                    "attempt": attempt + 1,
                })
                if healthy:
                    break
            except requests.RequestException as e:
                results.append({
                    "service": endpoint["name"],
                    "status": f"error: {str(e)}",
                    "attempt": attempt + 1,
                })
            if attempt < max_retries - 1:
                time.sleep(delay)

    return results
```

## Validation Checklist

- [ ] Complete inventory of service accounts with dependency mapping
- [ ] gMSA implemented for all eligible Windows service accounts
- [ ] Cloud access keys rotated via secrets manager (AWS, GCP, Azure)
- [ ] Database credentials managed via dynamic secrets (Vault) or rotation policy
- [ ] Rotation schedule defined (30-90 days depending on risk level)
- [ ] Post-rotation health checks automated
- [ ] Alerting configured for rotation failures
- [ ] Old credentials revoked after grace period
- [ ] Rotation events logged and auditable
- [ ] Rollback procedure documented and tested

## References

- [Google Cloud Service Account Key Rotation](https://cloud.google.com/iam/docs/key-rotation)
- [AWS Secrets Manager Rotation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html)
- [Microsoft gMSA Documentation](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
- [HashiCorp Vault Database Secrets Engine](https://developer.hashicorp.com/vault/docs/secrets/databases)
