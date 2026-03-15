# API Reference: Ed25519 Digital Signature Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| cryptography | >=41.0 | Ed25519 key generation, signing, verification |

## CLI Usage

```bash
# Generate keypair
python scripts/agent.py --generate-keys --output-dir /keys/

# Sign a file
python scripts/agent.py --sign release.tar.gz --private-key /keys/ed25519_private.pem

# Verify files
python scripts/agent.py --verify release.tar.gz --public-key /keys/ed25519_public.pem
```

## Functions

### `generate_keypair(output_dir, key_name) -> dict`
`Ed25519PrivateKey.generate()`, serializes with `private_bytes(PEM, PKCS8, NoEncryption)` and `public_bytes(PEM, SubjectPublicKeyInfo)`.

### `sign_message(private_key_path, message) -> dict`
Loads key via `load_pem_private_key()`, calls `key.sign(message)`. Returns base64 and hex signature.

### `sign_file(private_key_path, file_path) -> dict`
Signs file contents, writes `.ed25519.sig` JSON containing signature, hash, timestamp.

### `verify_message(public_key_path, message, signature_b64) -> dict`
Calls `key.verify(signature, message)`. Catches `InvalidSignature`.

### `verify_file(public_key_path, file_path, sig_path) -> dict`
Verifies file against `.ed25519.sig` JSON, checks hash match.

## cryptography API

| Method | Purpose |
|--------|---------|
| `Ed25519PrivateKey.generate()` | Generate 32-byte private key |
| `private_key.sign(data)` | Create 64-byte signature |
| `public_key.verify(signature, data)` | Verify signature |
| `load_pem_private_key(data, password)` | Load PEM key |

## Output Schema

```json
{
  "verifications": [{"file": "release.tar.gz", "valid": true}],
  "valid": 3, "invalid": 0
}
```
