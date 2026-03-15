# API Reference — Implementing End-to-End Encryption for Messaging

## Libraries Used
- **cryptography**: X25519 key exchange, HKDF key derivation, AES-256-GCM encryption

## CLI Interface

```
python agent.py keygen                                    # Generate X25519 key pair
python agent.py exchange                                  # Simulate key exchange
python agent.py demo                                      # Full E2EE demo flow
python agent.py encrypt --message <text> --key <hex>      # Encrypt message
python agent.py decrypt --nonce <hex> --ciphertext <hex> --key <hex>
```

## Core Functions

### `generate_keypair()`
Generates X25519 key pair for Diffie-Hellman key exchange.
- `X25519PrivateKey.generate()` -> private key
- `private_key.public_key()` -> public key
- Returns hex-encoded private and public keys.

### `derive_shared_secret(my_private_hex, their_public_hex)`
Performs X25519 ECDH key exchange and derives symmetric key via HKDF-SHA256.
- `my_private.exchange(their_public)` -> 32-byte raw shared secret
- `HKDF(algorithm=SHA256(), length=32, info=b"e2ee-messaging-v1").derive(shared)`

### `encrypt_message(message, shared_key_hex)`
Encrypts plaintext using AES-256-GCM with random 12-byte nonce.
- `AESGCM(key).encrypt(nonce, plaintext, None)` -> ciphertext with GCM tag

### `decrypt_message(nonce_hex, ciphertext_hex, shared_key_hex)`
Decrypts and authenticates ciphertext. Raises `InvalidTag` if tampered.

## Cryptography API Calls

| Class | Module | Purpose |
|-------|--------|---------|
| `X25519PrivateKey` | `cryptography.hazmat.primitives.asymmetric.x25519` | ECDH private key |
| `X25519PublicKey` | same | ECDH public key |
| `AESGCM` | `cryptography.hazmat.primitives.ciphers.aead` | Authenticated encryption |
| `HKDF` | `cryptography.hazmat.primitives.kdf.hkdf` | Key derivation |

## Dependencies
```
pip install cryptography>=41.0
```
