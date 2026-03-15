# Ransomware Encryption Standards Reference

## Common Encryption Schemes by Family
| Family | Symmetric | Asymmetric | Key Size |
|--------|-----------|-----------|----------|
| Rhysida | AES-256-CTR | RSA-4096 | 256-bit |
| Qilin.B | AES-256-CTR/ChaCha20 | RSA-4096 OAEP | 256-bit |
| Medusa | AES-256 | RSA public key | 256-bit |
| LockBit 3.0 | AES-256-CTR | Curve25519 | 256-bit |
| BlackCat/ALPHV | AES-128/ChaCha20 | RSA-2048 | 128/256-bit |
| Conti | ChaCha20 | RSA-4096 | 256-bit |

## Windows Cryptographic API Cheat Sheet
| Function | Purpose |
|----------|---------|
| CryptAcquireContext | Acquire crypto provider handle |
| CryptGenKey | Generate symmetric/asymmetric key |
| CryptImportKey | Import key blob |
| BCryptOpenAlgorithmProvider | Open CNG algorithm |
| BCryptGenerateSymmetricKey | Create symmetric key |

## MITRE ATT&CK Techniques
- T1486: Data Encrypted for Impact
- T1490: Inhibit System Recovery
- T1083: File and Directory Discovery
- T1082: System Information Discovery

## References
- [No More Ransom Decryptors](https://www.nomoreransom.org/en/decryption-tools.html)
- [ID Ransomware](https://id-ransomware.malwarehunterteam.com/)
