# Workflows - RSA Key Pair Management

## Workflow 1: Key Pair Generation

```
[Select Key Size] (3072 or 4096 bits)
      |
[Generate RSA Key Pair]
(public_exponent=65537)
      |
[Serialize Private Key]
(PEM/PKCS#8 with AES-256-CBC passphrase)
      |
[Extract and Serialize Public Key]
(PEM/SubjectPublicKeyInfo)
      |
[Compute Key Fingerprint]
(SHA-256 of DER-encoded public key)
      |
[Store Keys with Metadata]
(key_id, creation_date, algorithm, size)
```

## Workflow 2: Digital Signature (RSA-PSS)

```
[Document/Data to Sign]
      |
[Hash Data] (SHA-256)
      |
[Load Private Key] (decrypt with passphrase)
      |
[RSA-PSS Sign]
(padding=PSS, mgf=MGF1(SHA256), salt_length=PSS.MAX_LENGTH)
      |
[Output Signature] (DER or Base64)
```

## Workflow 3: Signature Verification

```
[Document + Signature + Public Key]
      |
[Load Public Key]
      |
[RSA-PSS Verify]
(same padding parameters as signing)
      |
[Valid?]
  YES --> Accept
  NO  --> Reject (data or signature tampered)
```

## Workflow 4: Key Rotation

```
[Current Key Pair (version N)]
      |
[Generate New Key Pair (version N+1)]
      |
[Update Active Key Reference]
      |
[Archive Old Key Pair]
(mark as "decrypt/verify only")
      |
[After Grace Period: Destroy Old Private Key]
(keep public key for verification)
```

## Workflow 5: RSA Encryption (OAEP)

```
[Plaintext] (max size depends on key and padding)
      |
[Load Recipient's Public Key]
      |
[RSA-OAEP Encrypt]
(padding=OAEP, mgf=MGF1(SHA256), algorithm=SHA256)
      |
[Ciphertext]
```
