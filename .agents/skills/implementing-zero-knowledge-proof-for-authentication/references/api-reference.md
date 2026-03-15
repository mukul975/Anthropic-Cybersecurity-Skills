# API Reference: Zero-Knowledge Proof Authentication

## hashlib (Python Standard Library)

### PBKDF2 Key Derivation
```python
import hashlib
key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
```

### SHA-256 Hashing (Fiat-Shamir Heuristic)
```python
challenge = int(hashlib.sha256(data.encode()).hexdigest(), 16) % prime
```

## secrets (Python Standard Library)

| Function | Description |
|----------|-------------|
| `secrets.randbelow(n)` | Cryptographically secure random int in [0, n) |
| `secrets.token_hex(n)` | Random hex string of n bytes |
| `secrets.token_bytes(n)` | Random bytes of length n |

## Schnorr Protocol Steps

| Step | Prover | Verifier |
|------|--------|----------|
| Setup | Private key x, public key y=g^x mod p | Knows g, p, y |
| Commit | Pick random k, send r=g^k mod p | Receive r |
| Challenge | - | Send random c |
| Response | Send s = k - c*x mod (p-1) | Check g^s * y^c == r mod p |

## Fiat-Shamir Heuristic (Non-Interactive)
```
c = H(g || r || y)   # Challenge derived from hash
s = k - c * x mod (p-1)
```

## ZKP Properties
| Property | Guarantee |
|----------|-----------|
| Completeness | Honest prover always convinces verifier |
| Soundness | Dishonest prover fails with high probability |
| Zero-Knowledge | Verifier learns nothing beyond validity |

## References
- Schnorr Protocol: https://en.wikipedia.org/wiki/Schnorr_identification
- RFC 8235 (Schnorr NIZK): https://www.rfc-editor.org/rfc/rfc8235
- hashlib docs: https://docs.python.org/3/library/hashlib.html
- secrets docs: https://docs.python.org/3/library/secrets.html
