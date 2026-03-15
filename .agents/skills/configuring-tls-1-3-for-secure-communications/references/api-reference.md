# TLS 1.3 Configuration — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| cryptography | `pip install cryptography` | X.509 certificate parsing |
| ssl | stdlib | TLS connection testing |
| sslyze | `pip install sslyze` | Comprehensive TLS/SSL scanner |

## Python ssl Module Methods

| Method | Description |
|--------|-------------|
| `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` | Create TLS client context |
| `ctx.minimum_version = ssl.TLSVersion.TLSv1_3` | Set minimum TLS version |
| `ctx.wrap_socket(sock, server_hostname=)` | Wrap socket with TLS |
| `ssock.cipher()` | Get negotiated cipher tuple |
| `ssock.getpeercert(binary_form=True)` | Get server certificate DER bytes |

## TLS 1.3 Cipher Suites

| Cipher Suite | Security |
|-------------|----------|
| TLS_AES_256_GCM_SHA384 | Recommended |
| TLS_AES_128_GCM_SHA256 | Recommended |
| TLS_CHACHA20_POLY1305_SHA256 | Recommended (mobile) |

## Deprecated Versions

| Version | Status | Risk |
|---------|--------|------|
| SSL 3.0 | Deprecated (RFC 7568) | POODLE attack |
| TLS 1.0 | Deprecated (RFC 8996) | BEAST, CRIME |
| TLS 1.1 | Deprecated (RFC 8996) | Weak ciphers |

## External References

- [RFC 8446 TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [sslyze Documentation](https://nabla-c0d3.github.io/sslyze/documentation/)
- [cryptography.io Docs](https://cryptography.io/)
