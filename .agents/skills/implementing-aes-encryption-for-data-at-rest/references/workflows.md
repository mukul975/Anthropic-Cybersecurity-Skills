# Workflows - AES Encryption for Data at Rest

## Workflow 1: Single File Encryption

```
[Input File] --> [Read File Bytes]
                      |
              [Derive Key from Password]
              (PBKDF2 / Argon2id + random salt)
                      |
              [Generate Random Nonce]
              (12 bytes from CSPRNG)
                      |
              [AES-256-GCM Encrypt]
              (key + nonce + plaintext --> ciphertext + tag)
                      |
              [Write Encrypted File]
              (salt || nonce || ciphertext || tag)
```

## Workflow 2: Single File Decryption

```
[Encrypted File] --> [Parse Header]
                     (extract salt, nonce)
                          |
                  [Derive Key from Password]
                  (same PBKDF2 / Argon2id params + extracted salt)
                          |
                  [AES-256-GCM Decrypt]
                  (key + nonce + ciphertext + tag)
                          |
                  [Verify Authentication Tag]
                  (reject if tag invalid)
                          |
                  [Write Decrypted File]
```

## Workflow 3: Streaming Encryption for Large Files

```
[Large Input File]
      |
[Read in Chunks] (e.g., 64KB chunks)
      |
[For Each Chunk]:
  - [Encrypt chunk with AES-256-CTR]
  - [Update HMAC with ciphertext chunk]
  - [Write encrypted chunk to output]
      |
[Finalize HMAC]
[Append HMAC tag to output]
```

## Workflow 4: Directory Tree Encryption

```
[Source Directory]
      |
[Walk Directory Tree]
      |
[For Each File]:
  - [Derive unique file key from master key + file path]
  - [Generate random nonce]
  - [AES-256-GCM encrypt file]
  - [Write encrypted file preserving directory structure]
      |
[Create Manifest File]
(maps original paths to encrypted paths with metadata)
```

## Workflow 5: Key Derivation Pipeline

```
[User Password]
      |
[Generate Random Salt] (16 bytes)
      |
[PBKDF2-SHA256]
  - iterations: 600,000+
  - dkLen: 32 bytes (256 bits)
      |
[Derived Key (256-bit)]
      |
[Optional: HKDF Expand]
  - Derive multiple subkeys from single derived key
  - info="encryption" --> encryption key
  - info="authentication" --> HMAC key
```

## Workflow 6: Envelope Encryption Pattern

```
[Master Key] (stored in HSM/KMS)
      |
[Generate Random Data Encryption Key (DEK)]
(32 bytes from CSPRNG)
      |
[Encrypt DEK with Master Key] --> [Encrypted DEK]
      |
[Encrypt Data with DEK] --> [Ciphertext]
      |
[Store: Encrypted DEK + Ciphertext]
[Securely Wipe DEK from Memory]
```

## Error Handling Workflow

```
[Decryption Attempt]
      |
  [Parse Header] --FAIL--> [Return: Corrupt/invalid file format]
      |
  [Derive Key] --FAIL--> [Return: KDF parameter error]
      |
  [Decrypt + Verify Tag]
      |
  [Tag Valid?]
    YES --> [Return plaintext]
    NO  --> [Return: Authentication failed - data tampered]
            [DO NOT return partial plaintext]
```
