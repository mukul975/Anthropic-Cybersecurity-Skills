# Workflows - Digital Signatures with Ed25519

## Workflow 1: Key Generation and Storage

```
[Generate Ed25519 Key Pair]
(32-byte private seed -> 32-byte public key)
      |
[Serialize Private Key (PKCS#8 PEM)]
[Serialize Public Key (SubjectPublicKeyInfo PEM)]
      |
[Encrypt Private Key with Passphrase]
      |
[Store with Metadata]
(key_id, fingerprint, creation_date)
```

## Workflow 2: Sign Document

```
[Document to Sign]
      |
[Load Private Key (decrypt passphrase)]
      |
[Ed25519 Sign]
(deterministic: SHA-512 internal hash)
      |
[Output: 64-byte Signature]
      |
[Create Signature File]
(signature + public key reference + metadata)
```

## Workflow 3: Verify Signature

```
[Document + Signature + Public Key]
      |
[Load Public Key]
      |
[Ed25519 Verify]
      |
[Valid?]
  YES -> Accept document as authentic
  NO  -> Reject (tampering detected)
```

## Workflow 4: Code Signing System

```
[Build Artifact] (binary, package, container)
      |
[Hash Artifact] (SHA-256)
      |
[Create Signing Manifest]
(artifact_name, hash, timestamp, signer_id)
      |
[Sign Manifest with Ed25519]
      |
[Distribute: Artifact + Manifest + Signature + Public Key]
      |
[Recipient Verifies]:
  1. Verify signature on manifest
  2. Hash artifact and compare to manifest
  3. Check signer identity against trust store
```
