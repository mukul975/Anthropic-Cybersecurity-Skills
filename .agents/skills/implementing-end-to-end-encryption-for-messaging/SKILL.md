---
name: implementing-end-to-end-encryption-for-messaging
description: End-to-end encryption (E2EE) ensures that only the communicating parties can read messages, with no intermediary (including the server) able to decrypt them. This skill implements a simplified version
domain: cybersecurity
subdomain: cryptography
tags: [cryptography, encryption, e2e, messaging, signal-protocol]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Implementing End-to-End Encryption for Messaging

## Overview

End-to-end encryption (E2EE) ensures that only the communicating parties can read messages, with no intermediary (including the server) able to decrypt them. This skill implements a simplified version of the Signal Protocol's Double Ratchet algorithm, using X25519 for key exchange, HKDF for key derivation, and AES-256-GCM for message encryption.

## Objectives

- Implement X25519 Diffie-Hellman key exchange for session establishment
- Build the Double Ratchet key management algorithm
- Encrypt and decrypt messages with per-message keys
- Implement forward secrecy (compromise of current key does not reveal past messages)
- Handle out-of-order message delivery
- Implement key agreement using X3DH (Extended Triple Diffie-Hellman)

## Key Concepts

### Signal Protocol Components

| Component | Purpose | Algorithm |
|-----------|---------|-----------|
| X3DH | Initial key agreement | X25519 |
| Double Ratchet | Ongoing key management | X25519 + HKDF + AES-GCM |
| Sending Chain | Per-message encryption keys | HMAC-SHA256 chain |
| Receiving Chain | Per-message decryption keys | HMAC-SHA256 chain |
| Root Chain | Derives new chain keys on DH ratchet | HKDF |

### Forward Secrecy

Each message uses a unique encryption key derived from a ratcheting chain. After a key is used, it is deleted, ensuring that compromise of the current state does not reveal previously sent/received messages.

## Security Considerations

- Delete message keys immediately after decryption
- Implement message ordering and replay protection
- Use authenticated encryption (AES-GCM) for all messages
- Protect identity keys with device-level security
- Verify identity keys out-of-band (safety numbers)

## Validation Criteria

- [ ] X25519 key exchange produces shared secret
- [ ] Messages encrypt and decrypt correctly between two parties
- [ ] Different messages produce different ciphertexts
- [ ] Forward secrecy: old keys cannot decrypt new messages
- [ ] Out-of-order messages can be decrypted
- [ ] Tampered messages are rejected by authentication
