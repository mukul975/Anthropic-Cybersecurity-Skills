# Standards and References - AES Encryption for Data at Rest

## Primary Standards

### NIST FIPS 197 - Advanced Encryption Standard (AES)
- **URL**: https://csrc.nist.gov/publications/detail/fips/197/final
- **Description**: Defines the AES algorithm (Rijndael) with key sizes of 128, 192, and 256 bits
- **Block size**: 128 bits (16 bytes)
- **Key sizes**: 128, 192, or 256 bits
- **Rounds**: 10 (128-bit), 12 (192-bit), 14 (256-bit)

### NIST SP 800-38D - Recommendation for Block Cipher Modes: GCM and GMAC
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-38d/final
- **Description**: Specifies Galois/Counter Mode (GCM) for authenticated encryption
- **IV length**: 96 bits recommended for GCM
- **Tag length**: 128 bits recommended (minimum 96 bits)
- **Max plaintext**: 2^39 - 256 bits per invocation

### NIST SP 800-132 - Recommendation for Password-Based Key Derivation
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-132/final
- **Description**: Covers PBKDF2 for deriving cryptographic keys from passwords
- **Minimum iterations**: 600,000 (OWASP 2024 recommendation for PBKDF2-SHA256)
- **Salt length**: Minimum 128 bits (16 bytes)

### NIST SP 800-38A - Recommendation for Block Cipher Modes of Operation
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-38a/final
- **Description**: Defines ECB, CBC, CFB, OFB, and CTR modes

### NIST SP 800-57 Part 1 Rev. 5 - Key Management
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final
- **Description**: Recommendations for cryptographic key lengths and algorithms
- **AES-256 security strength**: 256 bits
- **Recommended until**: Beyond 2031

## RFC Standards

### RFC 5116 - An Interface and Algorithms for Authenticated Encryption
- **URL**: https://www.rfc-editor.org/rfc/rfc5116
- **Description**: Defines AEAD interface including AES-GCM

### RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- **URL**: https://www.rfc-editor.org/rfc/rfc5869
- **Description**: Key derivation from existing key material (not passwords)

### RFC 9106 - Argon2 Memory-Hard Function
- **URL**: https://www.rfc-editor.org/rfc/rfc9106
- **Description**: Argon2 password hashing / key derivation specification
- **Recommended variant**: Argon2id (hybrid of Argon2i and Argon2d)

## Compliance Frameworks

### PCI DSS v4.0 - Requirement 3
- Encrypt stored cardholder data with strong cryptography
- AES-256 meets the strong cryptography requirement
- Key management procedures required

### HIPAA Security Rule - 45 CFR 164.312(a)(2)(iv)
- Encryption of ePHI at rest is an addressable implementation specification
- AES-256 is an acceptable encryption method

### GDPR Article 32 - Security of Processing
- Encryption is listed as an appropriate technical measure
- AES-256 satisfies encryption requirements for personal data protection

## Python Library References

### cryptography (pyca/cryptography)
- **URL**: https://cryptography.io/en/latest/
- **PyPI**: https://pypi.org/project/cryptography/
- **AES-GCM**: `cryptography.hazmat.primitives.ciphers.aead.AESGCM`
- **PBKDF2**: `cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC`

### PyCryptodome
- **URL**: https://pycryptodome.readthedocs.io/
- **PyPI**: https://pypi.org/project/pycryptodome/
- **AES-GCM**: `Crypto.Cipher.AES` with `MODE_GCM`
