# Workflows - Envelope Encryption with AWS KMS

## Workflow 1: Encrypt Data with Envelope Encryption

```
[Application]
      |
[Call KMS GenerateDataKey]
(KeyId=CMK ARN, KeySpec=AES_256)
      |
[KMS Returns]:
  - Plaintext DEK (32 bytes)
  - Encrypted DEK (ciphertext blob)
      |
[Encrypt Data Locally]
(AES-256-GCM with plaintext DEK)
      |
[Store]:
  - Encrypted DEK (ciphertext blob)
  - Encrypted data (nonce + ciphertext + tag)
  - Encryption context metadata
      |
[Wipe Plaintext DEK from Memory]
```

## Workflow 2: Decrypt Data

```
[Read Stored Data]
  - Encrypted DEK
  - Encrypted data
  - Encryption context
      |
[Call KMS Decrypt]
(CiphertextBlob=Encrypted DEK, EncryptionContext)
      |
[KMS Returns Plaintext DEK]
      |
[Decrypt Data Locally]
(AES-256-GCM with plaintext DEK)
      |
[Return Plaintext Data]
      |
[Wipe Plaintext DEK from Memory]
```

## Workflow 3: Key Rotation

```
[Enable Automatic Key Rotation on CMK]
(KMS rotates backing key annually)
      |
[New GenerateDataKey calls use new backing key]
      |
[Old encrypted DEKs still decrypt]
(KMS tracks all backing key versions)
      |
[Optional: Re-encrypt old DEKs]
[Call KMS ReEncrypt to update DEK encryption]
```

## Workflow 4: Multi-Region Encryption

```
[Primary Region (us-east-1)]
  |
  [Create Multi-Region CMK]
  [Replicate to us-west-2, eu-west-1]
  |
  [Encrypt with Regional Endpoint]
  |
[Secondary Region (us-west-2)]
  |
  [Same Key ID works for Decrypt]
  [No cross-region API calls needed]
```
