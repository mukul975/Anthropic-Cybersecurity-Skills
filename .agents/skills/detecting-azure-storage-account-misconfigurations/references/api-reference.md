# Azure Storage Account Misconfiguration Detection Reference

## SDK Installation

```bash
pip install azure-mgmt-storage azure-identity
```

## StorageManagementClient Initialization

```python
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient

client = StorageManagementClient(
    credential=DefaultAzureCredential(),
    subscription_id="<subscription-id>"
)
```

## Key Operations

### List All Storage Accounts

```python
for account in client.storage_accounts.list():
    print(account.name, account.location, account.kind)
```

### Get Storage Account Properties

```python
account = client.storage_accounts.get_properties(
    resource_group_name="myResourceGroup",
    account_name="mystorageaccount"
)
```

### List Blob Containers

```python
containers = client.blob_containers.list(
    resource_group_name="myResourceGroup",
    account_name="mystorageaccount"
)
for container in containers:
    print(container.name, container.public_access)
```

## Security Properties to Audit

| Property | Secure Value | Risk if Misconfigured |
|----------|-------------|----------------------|
| `allow_blob_public_access` | `False` | Critical — data exposed to internet |
| `enable_https_traffic_only` | `True` | High — credentials sent in cleartext |
| `minimum_tls_version` | `TLS1_2` | High — vulnerable to downgrade attacks |
| `encryption.services.blob.enabled` | `True` | High — data at rest unencrypted |
| `encryption.key_source` | `Microsoft.Keyvault` | Low — Microsoft-managed keys less controlled |
| `network_rule_set.default_action` | `Deny` | High — storage open to all networks |
| `encryption.require_infrastructure_encryption` | `True` | Low — no double encryption |

## Container Public Access Levels

| Level | Description | Risk |
|-------|-------------|------|
| `None` | Private, no public access | Safe |
| `Blob` | Anonymous read for blobs only | High |
| `Container` | Anonymous read for container and blobs | Critical |

## Azure CLI Equivalents

```bash
# List storage accounts
az storage account list --query "[].{name:name, publicAccess:allowBlobPublicAccess, httpsOnly:enableHttpsTrafficOnly, minTls:minimumTlsVersion}" -o table

# Check specific account
az storage account show -n mystorageaccount -g myResourceGroup

# List containers with access level
az storage container list --account-name mystorageaccount --query "[].{name:name, publicAccess:properties.publicAccess}" -o table

# Disable public blob access
az storage account update -n mystorageaccount -g myResourceGroup --allow-blob-public-access false

# Set minimum TLS
az storage account update -n mystorageaccount -g myResourceGroup --min-tls-version TLS1_2
```

## CIS Azure Benchmark Controls

| Control | Description |
|---------|-------------|
| 3.1 | Ensure 'Secure transfer required' is enabled |
| 3.7 | Ensure default network access rule is set to deny |
| 3.8 | Ensure 'Trusted Microsoft Services' is enabled |
| 3.10 | Ensure storage logging is enabled for Blob service |
| 3.12 | Ensure storage account access keys are periodically regenerated |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AZURE_SUBSCRIPTION_ID` | Target Azure subscription |
| `AZURE_CLIENT_ID` | Service principal application ID |
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `AZURE_CLIENT_SECRET` | Service principal secret |
