# Azure Storage Misconfiguration Detection API Reference

## Azure CLI - Storage Account Enumeration

```bash
# List all storage accounts
az storage account list --query "[].{name:name, rg:resourceGroup, https:enableHttpsTrafficOnly, tls:minimumTlsVersion, publicAccess:allowBlobPublicAccess}" -o table

# Show account details
az storage account show --name mystorageacct --resource-group myrg

# Resource Graph cross-subscription query
az graph query -q "Resources | where type == 'microsoft.storage/storageaccounts' | project name, properties.allowBlobPublicAccess, properties.minimumTlsVersion"
```

## Container Access Level Checks

```bash
# List containers with access levels
az storage container list --account-name mystorageacct \
  --query "[].{name:name, access:properties.publicAccess}" -o table

# Set container to private
az storage container set-permission --name mycontainer \
  --account-name mystorageacct --public-access off
```

## Network Rules

```bash
# Show network rules
az storage account network-rule list --account-name mystorageacct --resource-group myrg

# Set default action to Deny
az storage account update --name mystorageacct --resource-group myrg \
  --default-action Deny

# Add IP rule
az storage account network-rule add --account-name mystorageacct \
  --resource-group myrg --ip-address 203.0.113.0/24
```

## Security Settings

```bash
# Enforce HTTPS only
az storage account update --name mystorageacct -g myrg --https-only true

# Set minimum TLS 1.2
az storage account update --name mystorageacct -g myrg --min-tls-version TLS1_2

# Disable public blob access
az storage account update --name mystorageacct -g myrg --allow-blob-public-access false

# Enable soft delete
az storage blob service-properties delete-policy update \
  --account-name mystorageacct --enable true --days-retained 14
```

## Azure Storage Security Checklist

| Check | CLI Command | Expected |
|-------|------------|----------|
| HTTPS only | `show --query enableHttpsTrafficOnly` | `true` |
| TLS 1.2+ | `show --query minimumTlsVersion` | `TLS1_2` |
| No public access | `show --query allowBlobPublicAccess` | `false` |
| Network deny default | `network-rule list` | `defaultAction: Deny` |
| Logging enabled | `storage logging show` | All services enabled |
| Soft delete on | `blob service-properties` | Enabled 7-14 days |

## Defender for Storage Alerts

| Alert | Description |
|-------|-------------|
| Anonymous access to storage | Unauthenticated blob access |
| Unusual data extraction | Anomalous download volume |
| Access from Tor exit node | Storage access from Tor |
| Unusual access pattern | Access from unexpected location |
