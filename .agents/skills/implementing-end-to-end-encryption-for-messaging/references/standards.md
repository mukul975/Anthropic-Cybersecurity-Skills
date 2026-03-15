# Standards and References - End-to-End Encryption for Messaging

## Signal Protocol Specifications

### The Double Ratchet Algorithm
- **URL**: https://signal.org/docs/specifications/doubleratchet/
- **Description**: Core key management algorithm for E2EE messaging

### The X3DH Key Agreement Protocol
- **URL**: https://signal.org/docs/specifications/x3dh/
- **Description**: Initial key exchange using Extended Triple Diffie-Hellman

### The Sesame Algorithm
- **URL**: https://signal.org/docs/specifications/sesame/
- **Description**: Multi-device session management

## Cryptographic Standards

### RFC 7748 - Elliptic Curves for Security (X25519)
- **URL**: https://www.rfc-editor.org/rfc/rfc7748
- **Description**: X25519 Diffie-Hellman key exchange

### RFC 5869 - HKDF (HMAC-based Key Derivation Function)
- **URL**: https://www.rfc-editor.org/rfc/rfc5869
- **Description**: Key derivation for chain key updates

### RFC 8032 - Edwards-Curve Digital Signature Algorithm (Ed25519)
- **URL**: https://www.rfc-editor.org/rfc/rfc8032
- **Description**: Identity key signatures

### NIST SP 800-38D - AES-GCM
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-38d/final
- **Description**: Authenticated encryption for messages

## Python Libraries

### cryptography
- **X25519**: `cryptography.hazmat.primitives.asymmetric.x25519`
- **HKDF**: `cryptography.hazmat.primitives.kdf.hkdf`
- **AES-GCM**: `cryptography.hazmat.primitives.ciphers.aead.AESGCM`
