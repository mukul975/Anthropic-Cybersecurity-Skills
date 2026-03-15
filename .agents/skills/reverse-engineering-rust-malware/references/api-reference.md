# API Reference: Reverse Engineering Rust Malware

## Rust Binary Indicators

| Indicator | Pattern | Description |
|-----------|---------|-------------|
| Panic strings | `panicked at` | Rust panic handler messages |
| Unwrap failure | `called.*unwrap.*on.*None` | Option/Result unwrap |
| Core panic | `core::panicking` | Standard library panic |
| Runtime start | `std::rt::lang_start` | Rust runtime entry point |
| Cargo registry | `.cargo/registry` | Crate dependency paths |
| Rustc version | `rustc X.Y.Z` | Compiler version string |

## Crate Extraction Pattern

| Pattern | Example Match |
|---------|---------------|
| `crates.io-<hash>/<name>-<ver>` | `crates.io-abc123/reqwest-0.11.22` |
| `.cargo/registry/src/<index>/<name>-<ver>` | `.cargo/registry/src/index.crates.io/aes-0.8.3` |

## Suspicious Crate Capabilities

| Crate | Capability | Malware Use |
|-------|-----------|-------------|
| reqwest / hyper | HTTP client | C2 communication |
| aes / chacha20 / rsa | Encryption | Ransomware encryption |
| ring | Crypto primitives | Key generation |
| winapi / winreg | Windows API | Persistence, injection |
| sysinfo | System info | Host enumeration |
| native-tls | TLS | Encrypted C2 channel |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `re` | stdlib | Pattern matching for Rust indicators |
| `struct` | stdlib | PE header parsing |
| `hashlib` | stdlib | SHA256 sample hashing |
| `json` | stdlib | Report generation |

## References

- Ghidra: https://ghidra-sre.org/
- Binary Defense Rust Analysis: https://binarydefense.com/resources/blog/
- Bishop Fox Rust Malware: https://bishopfox.com/blog/rust-for-malware-development
