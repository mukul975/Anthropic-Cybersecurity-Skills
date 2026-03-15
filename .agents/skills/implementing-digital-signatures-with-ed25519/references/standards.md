# Standards and References - Digital Signatures with Ed25519

## Primary Standards

### RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)
- **URL**: https://www.rfc-editor.org/rfc/rfc8032
- **Description**: Defines Ed25519 and Ed448 signature algorithms

### RFC 8709 - Ed25519 and Ed448 Public Key Algorithms for SSH
- **URL**: https://www.rfc-editor.org/rfc/rfc8709
- **Description**: SSH key format for Ed25519

### NIST FIPS 186-5 - Digital Signature Standard
- **URL**: https://csrc.nist.gov/publications/detail/fips/186/5/final
- **Description**: Includes EdDSA as approved signature algorithm

### RFC 7748 - Elliptic Curves for Security
- **URL**: https://www.rfc-editor.org/rfc/rfc7748
- **Description**: Defines Curve25519 and Curve448

## Python Libraries

### cryptography (pyca/cryptography)
- **Ed25519**: `cryptography.hazmat.primitives.asymmetric.ed25519`
- **Docs**: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/

### PyNaCl (libsodium)
- **URL**: https://pynacl.readthedocs.io/
- **Ed25519**: `nacl.signing`
- **Docs**: https://pynacl.readthedocs.io/en/latest/signing/

## Related

### Daniel J. Bernstein et al. - High-speed high-security signatures
- **URL**: https://ed25519.cr.yp.to/
- **Description**: Original Ed25519 paper and reference implementation
