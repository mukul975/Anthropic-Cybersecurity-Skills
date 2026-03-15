# E2E Encryption for Messaging Template

## Protocol Summary

| Phase | Algorithm | Purpose |
|-------|-----------|---------|
| Key Exchange | X3DH (X25519) | Initial shared secret |
| Key Ratchet | Double Ratchet | Per-message key derivation |
| Encryption | AES-256-GCM | Message confidentiality + integrity |
| Key Derivation | HKDF-SHA256 | Derive keys from DH outputs |
| Chain KDF | HMAC-SHA256 | Advance symmetric ratchet |

## Security Properties Checklist

- [ ] Forward secrecy: Past messages safe if current keys compromised
- [ ] Post-compromise security: Recovery after temporary key compromise
- [ ] Deniability: No cryptographic proof of message authorship
- [ ] Authenticated encryption: Tampered messages detected and rejected
- [ ] Replay protection: Message counters prevent replay attacks
- [ ] Out-of-order delivery: Skipped keys stored for late messages

## Message Format

```
[Header (40 bytes)]
  - DH Public Key: 32 bytes
  - Previous Chain Length: 4 bytes (big-endian)
  - Message Number: 4 bytes (big-endian)

[Encrypted Payload]
  - Nonce: 12 bytes
  - Ciphertext + Tag: variable
```

## Integration Notes

- Identity keys should be stored in secure device storage (Keychain, TEE)
- Implement safety number verification for identity key comparison
- Handle device changes by re-running X3DH with new identity keys
- Store skipped message keys with a maximum limit (e.g., 1000)
- Delete message keys immediately after successful decryption
