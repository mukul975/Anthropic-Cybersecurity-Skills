# BitLocker Disk Encryption Template

## Endpoint Information

| Field | Value |
|-------|-------|
| Hostname | |
| OS Version | |
| TPM Version | 2.0 |
| UEFI/Secure Boot | Enabled |
| Encryption Date | |

## Encryption Configuration

| Setting | OS Drive | Fixed Drives | Removable |
|---------|----------|-------------|-----------|
| Encryption Method | XTS-AES 256 | XTS-AES 256 | AES-CBC 256 |
| Key Protectors | TPM + PIN | Auto-unlock | Password |
| Recovery Key Escrow | AD DS / Azure AD | AD DS / Azure AD | N/A |
| Full/Used Space | Full disk | Used space only | Used space only |

## Recovery Key Register

| Volume | Key Protector ID | Escrowed To | Verified |
|--------|-----------------|-------------|----------|
| C: | | AD DS / Azure AD | Yes / No |
| D: | | AD DS / Azure AD | Yes / No |

## Compliance Checklist

- [ ] TPM 2.0 present and enabled
- [ ] Secure Boot enabled
- [ ] OS drive encrypted with XTS-AES 256
- [ ] Recovery key escrowed to AD/Azure AD
- [ ] PIN configured for laptop endpoints
- [ ] Fixed data drives encrypted
- [ ] Removable drive encryption policy active
- [ ] BitLocker cannot be disabled without admin

## Sign-Off

| Role | Name | Date |
|------|------|------|
| Endpoint Admin | | |
| Security Analyst | | |
