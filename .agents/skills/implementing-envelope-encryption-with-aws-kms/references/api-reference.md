# API Reference — Implementing Envelope Encryption with AWS KMS

## Libraries Used
- **boto3**: AWS SDK for KMS key management and data key generation
- **cryptography**: AES-256-GCM for local data encryption with generated data keys

## CLI Interface

```
python agent.py --region us-east-1 encrypt --input <file> --output <out> --key-id <kms_key>
python agent.py --region us-east-1 decrypt --input <encrypted> --output <out>
python agent.py --region us-east-1 list-keys
python agent.py --region us-east-1 audit --key-id <kms_key>
```

## Core Functions

### `generate_data_key(kms_key_id, region)`
Generates a data encryption key (DEK) using AWS KMS.
- `kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")`
- Returns plaintext key (for local encryption) and encrypted key (for storage).

### `encrypt_data(plaintext_bytes, kms_key_id, region)`
Performs envelope encryption: generates DEK via KMS, encrypts data locally with AES-256-GCM, stores encrypted DEK alongside ciphertext.

### `decrypt_data(envelope, region)`
Decrypts envelope: calls `kms.decrypt(CiphertextBlob=encrypted_key)` to recover DEK, then decrypts data locally.

### `list_kms_keys(region)`
Lists KMS keys with metadata using `kms.list_keys()` and `kms.describe_key()`.

### `audit_key_policy(key_id, region)`
Audits KMS key policy for overly permissive principals (`Principal: "*"`).
- `kms.get_key_policy(KeyId=key_id, PolicyName="default")`

## boto3 KMS API Calls

| Method | Purpose |
|--------|---------|
| `kms.generate_data_key(KeyId, KeySpec)` | Generate plaintext + encrypted DEK |
| `kms.decrypt(CiphertextBlob)` | Decrypt encrypted DEK back to plaintext |
| `kms.list_keys()` | List all KMS keys in the account |
| `kms.describe_key(KeyId)` | Get key metadata (state, usage, origin) |
| `kms.get_key_policy(KeyId, PolicyName)` | Get key resource policy JSON |

## Dependencies
```
pip install boto3>=1.28 cryptography>=41.0
```
