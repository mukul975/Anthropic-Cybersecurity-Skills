# RSA Key Pair Management Template

## Key Generation Checklist

- [ ] Select key size (minimum 3072 bits for new deployments)
- [ ] Generate key pair using secure random number generator
- [ ] Protect private key with strong passphrase (AES-256)
- [ ] Compute and record key fingerprint (SHA-256)
- [ ] Set restrictive file permissions on private key
- [ ] Store public key in accessible location
- [ ] Document key metadata (size, algorithm, creation date)

## Key Metadata Template

```json
{
  "key_id": "rsa-prod-001",
  "algorithm": "RSA",
  "key_size": 4096,
  "public_exponent": 65537,
  "fingerprint_sha256": "<hex-digest>",
  "created_at": "2024-01-01T00:00:00Z",
  "expires_at": "2025-01-01T00:00:00Z",
  "usage": ["sign", "verify"],
  "owner": "security-team",
  "version": 1
}
```

## Key Rotation Schedule

| Environment | Rotation Frequency | Grace Period |
|------------|-------------------|--------------|
| Production | 12 months | 30 days |
| Staging    | 6 months  | 14 days |
| Development| 3 months  | 7 days  |

## Quick Reference

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Generate
key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

# Sign (RSA-PSS)
signature = key.sign(data, padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

# Verify
key.public_key().verify(signature, data, padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
```
