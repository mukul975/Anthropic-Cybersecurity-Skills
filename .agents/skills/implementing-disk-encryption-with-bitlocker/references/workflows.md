# Workflows - Implementing Disk Encryption with BitLocker

## Workflow 1: Enterprise BitLocker Deployment

```
[Pre-deployment assessment]
    │
    ├── Verify TPM 2.0 across fleet
    ├── Confirm UEFI/Secure Boot
    ├── Plan recovery key escrow (AD DS or Azure AD)
    │
    ▼
[Configure GPO/Intune policy]
    │
    ├── Set encryption method (XTS-AES 256)
    ├── Configure key protectors (TPM + PIN for laptops, TPM for desktops)
    ├── Enable recovery key escrow
    │
    ▼
[Pilot deployment (test group)]
    │
    ├── Verify encryption completes without errors
    ├── Test recovery key retrieval
    ├── Verify no boot issues
    │
    ▼
[Production rollout (phased)]
    │
    ▼
[Monitor encryption status via Intune/SCCM reports]
    │
    ▼
[Verify 100% coverage, address failures]
```

## Workflow 2: BitLocker Recovery Process

```
[User locked out (BitLocker recovery screen)]
    │
    ▼
[User provides Recovery Key ID to helpdesk]
    │
    ▼
[Helpdesk retrieves recovery key]
    │
    ├── AD DS: RSAT BitLocker Recovery Password Viewer
    ├── Azure AD: Azure Portal → Devices → BitLocker keys
    ├── Intune: Intune Portal → Devices → Recovery keys
    │
    ▼
[User enters 48-digit recovery key]
    │
    ▼
[Investigate why recovery was triggered]
    │
    ├── BIOS/firmware update ──► [Expected, no action]
    ├── TPM failure ──► [Replace TPM or re-encrypt]
    ├── Boot configuration change ──► [Review change, re-seal TPM]
    └── Potential tampering ──► [Security investigation]
```

## Workflow 3: Key Rotation

```
[Quarterly key rotation policy]
    │
    ▼
[Generate new recovery password]
    │
    ▼
[Backup new key to AD/Azure AD]
    │
    ▼
[Remove old recovery password protector]
    │
    ▼
[Verify new key works in test recovery]
```
