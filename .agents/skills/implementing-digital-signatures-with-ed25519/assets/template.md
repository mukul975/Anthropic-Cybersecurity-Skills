# Ed25519 Digital Signatures Template

## Quick Reference

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Generate
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Sign
signature = private_key.sign(b"message data")

# Verify
public_key.verify(signature, b"message data")  # raises InvalidSignature on failure
```

## Key Formats

| Format | Private Key Size | Public Key Size | Signature Size |
|--------|-----------------|-----------------|----------------|
| Raw | 32 bytes | 32 bytes | 64 bytes |
| PEM (PKCS#8) | ~119 bytes | ~90 bytes | N/A |
| SSH | ~83 bytes | ~51 bytes | ~83 bytes |

## Use Cases

- API request authentication (sign request body)
- Software/code signing
- Document signing
- Git commit signing (ssh-ed25519)
- JWT signing (EdDSA algorithm)
- Certificate signing (X.509 with Ed25519)
