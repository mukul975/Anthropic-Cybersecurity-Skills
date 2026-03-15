# API Reference: Reverse Engineering Ransomware Encryption

## Cryptographic Algorithm Constants

| Algorithm | Signature | Description |
|-----------|-----------|-------------|
| AES | S-Box starting `0x63 0x7C 0x77` | AES Rijndael substitution box |
| RSA | DER `0x30 0x82` prefix | ASN.1 RSA key structure |
| ChaCha20/Salsa20 | `expand 32-byte k` | Stream cipher constant |
| RC4 | Sequential 0-255 state | Key scheduling algorithm init |

## Encryption Analysis Techniques

| Technique | Tool | Purpose |
|-----------|------|---------|
| Entropy analysis | `ent`, Python | Detect encrypted regions |
| Constant scanning | IDA/Ghidra YARA | Find crypto implementations |
| API tracing | x64dbg, Frida | Trace CryptEncrypt/BCrypt calls |
| Key extraction | Volatility3 | Dump keys from memory |

## Ransomware Encryption Patterns

| Pattern | Indicator |
|---------|-----------|
| Full encryption | Entropy > 7.9 across entire file |
| Intermittent | High entropy blocks with gaps |
| Header-only | First N bytes encrypted, rest plain |
| Appended metadata | File larger than original (key/IV at end) |

## Common Ransomware Crypto

| Family | Algorithm | Key Mgmt |
|--------|-----------|----------|
| LockBit 3.0 | AES-256-CBC + RSA-2048 | Per-file AES key, RSA-encrypted |
| BlackCat/ALPHV | ChaCha20 + RSA-4096 | Rust implementation |
| Royal | AES-256-CBC + RSA-2048 | Intermittent encryption |
| Akira | ChaCha20 | Partial file encryption |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `hashlib` | stdlib | SHA256 hashing |
| `struct` | stdlib | Binary data parsing |
| `re` | stdlib | Pattern extraction |
| `math` | stdlib | Shannon entropy calculation |

## References

- ID Ransomware: https://id-ransomware.malwarehunterteam.com/
- NoMoreRansom Decryptors: https://www.nomoreransom.org/en/decryption-tools.html
- Ghidra: https://ghidra-sre.org/
