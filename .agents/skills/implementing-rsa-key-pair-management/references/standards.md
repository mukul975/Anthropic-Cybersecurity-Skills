# Standards and References - RSA Key Pair Management

## Primary Standards

### NIST FIPS 186-5 - Digital Signature Standard (DSS)
- **URL**: https://csrc.nist.gov/publications/detail/fips/186/5/final
- **Description**: Specifies RSA digital signature generation and verification
- **RSA minimum**: 2048-bit keys

### RFC 8017 - PKCS #1: RSA Cryptography Specifications Version 2.2
- **URL**: https://www.rfc-editor.org/rfc/rfc8017
- **Description**: Defines RSA key formats, OAEP encryption, and PSS signatures
- **Key operations**: RSAEP, RSADP, RSASP1, RSAVP1

### RFC 5958 - Asymmetric Key Packages (PKCS#8 v2)
- **URL**: https://www.rfc-editor.org/rfc/rfc5958
- **Description**: Private key information syntax for storage

### RFC 7468 - Textual Encodings of PKIX, PKCS, and CMS Structures
- **URL**: https://www.rfc-editor.org/rfc/rfc7468
- **Description**: PEM encoding format specification

### NIST SP 800-57 Part 1 Rev. 5 - Key Management
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final
- **Description**: Key length recommendations and lifecycle management
- **RSA 2048**: Acceptable through 2030
- **RSA 3072+**: Recommended for beyond 2030

### NIST SP 800-131A Rev. 2 - Transitioning Cryptographic Algorithms
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final
- **Description**: Transition guidance for algorithm selection
- **PKCS#1 v1.5 signatures**: Legacy use only
- **RSA-PSS**: Recommended for all new applications

## Python Library References

### cryptography (pyca/cryptography)
- **RSA Key Generation**: `cryptography.hazmat.primitives.asymmetric.rsa`
- **Serialization**: `cryptography.hazmat.primitives.serialization`
- **Signatures**: `cryptography.hazmat.primitives.asymmetric.padding`
- **Documentation**: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
