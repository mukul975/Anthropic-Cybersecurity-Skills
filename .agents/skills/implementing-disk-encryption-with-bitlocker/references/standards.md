# Standards & References - Implementing Disk Encryption with BitLocker

## Primary Standards

### NIST SP 800-111 - Guide to Storage Encryption Technologies
- **Publisher**: NIST
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-111/final
- **Scope**: Guidance on planning, implementing, and maintaining storage encryption solutions

### FIPS 140-2/3 - Security Requirements for Cryptographic Modules
- **Publisher**: NIST
- **Relevance**: BitLocker uses FIPS 140-2 validated cryptographic modules when configured in FIPS-compliant mode

## Compliance Mappings

| Framework | Requirement | BitLocker Coverage |
|-----------|------------|-------------------|
| PCI DSS 4.0 | 3.5.1 - Render PAN unreadable in storage | BitLocker full disk encryption |
| HIPAA | 164.312(a)(2)(iv) - Encryption/decryption | BitLocker protects ePHI at rest |
| GDPR | Article 32(1)(a) - Encryption of personal data | BitLocker for data-at-rest protection |
| NIST 800-53 | SC-28 Protection of Information at Rest | BitLocker encryption |
| NIST 800-171 | 3.13.16 - Confidentiality of CUI at rest | BitLocker on CUI systems |
| ISO 27001 | A.10.1.1 - Cryptographic controls policy | BitLocker implementation |

## Microsoft References

- **BitLocker Overview**: https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/
- **BitLocker Group Policy Reference**: https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-group-policy-settings
- **BitLocker Recovery Guide**: https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-recovery-guide-plan
- **TPM Recommendations**: https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/tpm-recommendations
