# AES Encryption Implementation Template

## Pre-Implementation Checklist

- [ ] Identify data classification level and regulatory requirements
- [ ] Determine key management strategy (local, HSM, KMS)
- [ ] Select AES mode (GCM recommended for authenticated encryption)
- [ ] Define key derivation parameters (algorithm, iterations)
- [ ] Plan nonce/IV generation strategy
- [ ] Determine encrypted file format and metadata storage
- [ ] Review compliance requirements (PCI-DSS, HIPAA, GDPR)

## Configuration Parameters

```yaml
encryption:
  algorithm: AES-256-GCM
  key_length: 256
  nonce_length: 96  # bits
  tag_length: 128   # bits

key_derivation:
  algorithm: PBKDF2-SHA256
  iterations: 600000
  salt_length: 128  # bits

file_format:
  magic_bytes: "AES256GCM"
  version: 1
  header: "magic || version || salt || nonce"
  body: "ciphertext || tag"
```

## Integration Code Template

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

def encrypt_data(plaintext: bytes, password: str) -> bytes:
    """Encrypt data with AES-256-GCM."""
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    key = kdf.derive(password.encode())
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext

def decrypt_data(data: bytes, password: str) -> bytes:
    """Decrypt AES-256-GCM encrypted data."""
    salt = data[:16]
    nonce = data[16:28]
    ciphertext = data[28:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    key = kdf.derive(password.encode())
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
```

## Testing Checklist

- [ ] Encrypt and decrypt a small text file
- [ ] Encrypt and decrypt a large binary file (>100MB)
- [ ] Verify wrong password raises authentication error
- [ ] Verify tampered ciphertext raises authentication error
- [ ] Verify nonce uniqueness across multiple encryptions
- [ ] Measure encryption throughput (MB/s)
- [ ] Test with empty files and edge cases

## Common Pitfalls

| Pitfall | Impact | Mitigation |
|---------|--------|------------|
| Nonce reuse with same key | Complete loss of confidentiality in GCM | Always generate random nonce per encryption |
| Low PBKDF2 iterations | Brute-force password attacks | Use minimum 600,000 iterations |
| ECB mode usage | Pattern leakage in ciphertext | Always use GCM or CBC (never ECB) |
| No authentication | Undetected ciphertext modification | Use AEAD modes (GCM, CCM) |
| Hardcoded keys | Key compromise | Use KMS, HSM, or environment variables |
| No key rotation | Extended exposure window | Implement periodic key rotation policy |
