# API Reference: Implementing AES Encryption for Data at Rest

## cryptography Library - AESGCM

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)  # 96-bit nonce, NEVER reuse

ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
```

## Key Derivation - PBKDF2

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,               # 256-bit key
    salt=os.urandom(16),
    iterations=600_000,      # NIST 2024 recommendation
)
key = kdf.derive(password.encode())
```

## Encrypted File Format

```
[salt: 16 bytes][nonce: 12 bytes][ciphertext + tag: variable]
```

| Field | Size | Purpose |
|-------|------|---------|
| Salt | 16 bytes | PBKDF2 salt (random per file) |
| Nonce | 12 bytes | GCM nonce (random per encryption) |
| Ciphertext | Variable | Encrypted data + 16-byte auth tag |

## AES Modes Comparison

| Mode | AEAD | Nonce Size | Use Case |
|------|------|------------|----------|
| GCM | Yes | 12 bytes | File/network encryption |
| CBC | No | 16 bytes | Legacy, disk encryption |
| CTR | No | 16 bytes | Streaming |
| XTS | No | 16 bytes | Full disk encryption |

## Fernet (High-Level API)

```python
from cryptography.fernet import Fernet
key = Fernet.generate_key()
f = Fernet(key)
token = f.encrypt(b"data")
plaintext = f.decrypt(token)
```

### References

- cryptography AESGCM: https://cryptography.io/en/latest/hazmat/primitives/aead/
- NIST SP 800-38D (GCM): https://csrc.nist.gov/publications/detail/sp/800-38d/final
- NIST FIPS 197 (AES): https://csrc.nist.gov/publications/detail/fips/197/final
