# API Reference: Code Signing Verification Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| cryptography | >=41.0 | Ed25519 key generation, signing, and verification |

## CLI Usage

```bash
# Generate keypair
python scripts/agent.py --generate-keys --output-dir /keys/

# Sign artifact
python scripts/agent.py --sign build/app.tar.gz --private-key /keys/signing_key.pem

# Verify artifacts
python scripts/agent.py \
  --artifacts build/app.tar.gz build/lib.so \
  --public-key /keys/signing_key.pub \
  --output-dir /reports/
```

## Functions

### `generate_ed25519_keypair(output_dir) -> dict`
Calls `Ed25519PrivateKey.generate()`, serializes to PEM using `private_bytes()` and `public_bytes()`.

### `sign_artifact(file_path, private_key_path) -> dict`
Loads PEM key via `serialization.load_pem_private_key()`, calls `private_key.sign(data)`. Writes 64-byte signature to `.sig` file.

### `verify_signature(file_path, signature_path, public_key_path) -> dict`
Loads public key, calls `public_key.verify(signature, data)`. Catches `InvalidSignature`.

### `verify_cosign_signature(image) -> dict`
Runs `cosign verify <image>` via subprocess for container image signature verification.

### `batch_verify(artifacts, public_key_path) -> list`
Verifies multiple artifacts against the same public key.

## cryptography API Used

| Class/Method | Purpose |
|-------------|---------|
| `Ed25519PrivateKey.generate()` | Generate signing keypair |
| `private_key.sign(data)` | Sign data (returns 64 bytes) |
| `public_key.verify(signature, data)` | Verify signature |
| `serialization.load_pem_private_key()` | Load PEM private key |

## Output Schema

```json
{
  "summary": {"total": 3, "valid": 2, "invalid": 1},
  "verifications": [{"file": "app.tar.gz", "valid": true, "algorithm": "Ed25519"}]
}
```
