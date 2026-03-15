# API Reference: Implementing Disk Encryption with BitLocker

## manage-bde CLI

```powershell
# Check status
manage-bde -status C:

# Enable BitLocker with TPM
manage-bde -on C: -RecoveryPassword -EncryptionMethod AES256

# Backup recovery key to AD
manage-bde -protectors -adbackup C: -ID {protector-id}

# Lock/unlock
manage-bde -lock D:
manage-bde -unlock D: -RecoveryPassword 123456-...
```

## PowerShell BitLocker Cmdlets

```powershell
# Get BitLocker volume
Get-BitLockerVolume -MountPoint "C:"

# Enable with TPM + PIN
Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 `
  -TpmAndPinProtector -Pin (ConvertTo-SecureString "1234" -AsPlainText -Force)

# Add recovery password
Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector

# Backup to AD
Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $id
```

## Compliance Checks

| Check | Severity | Requirement |
|-------|----------|-------------|
| BitLocker enabled | CRITICAL | All OS drives |
| AES-256 encryption | MEDIUM | FIPS/enterprise |
| TPM protector | HIGH | Hardware-backed |
| Recovery key escrowed | HIGH | AD DS or Azure AD |
| Full disk encrypted | MEDIUM | Not used-space only |

## Microsoft Graph API (Intune)

```python
import requests
headers = {"Authorization": "Bearer <token>"}
resp = requests.get(
    "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
    "?$select=deviceName,isEncrypted",
    headers=headers)
```

### References

- BitLocker: https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/
- BitLocker PowerShell: https://learn.microsoft.com/en-us/powershell/module/bitlocker/
