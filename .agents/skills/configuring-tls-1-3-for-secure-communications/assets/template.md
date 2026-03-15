# TLS 1.3 Configuration Template

## Pre-Configuration Checklist

- [ ] Verify OpenSSL version >= 1.1.1 (`openssl version`)
- [ ] Obtain valid TLS certificate from trusted CA
- [ ] Identify all server endpoints requiring TLS
- [ ] Determine minimum TLS version (1.2 or 1.3 only)
- [ ] Plan certificate renewal automation (Let's Encrypt / ACME)
- [ ] Review compliance requirements (PCI-DSS, HIPAA)

## nginx Configuration Template

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
ssl_prefer_server_ciphers off;
ssl_ecdh_curve X25519:secp256r1:secp384r1;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

## Python TLS 1.3 Client Template

```python
import ssl
import socket

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_default_certs()

with socket.create_connection(("example.com", 443)) as sock:
    with context.wrap_socket(sock, server_hostname="example.com") as tls:
        print(f"Protocol: {tls.version()}")
        print(f"Cipher: {tls.cipher()}")
```

## Validation Commands

```bash
# Test TLS 1.3 support
openssl s_client -connect example.com:443 -tls1_3

# Show full certificate chain
openssl s_client -connect example.com:443 -showcerts

# List supported cipher suites
openssl s_client -connect example.com:443 -cipher 'ALL' -tls1_3

# Test with testssl.sh
./testssl.sh --protocols --ciphers --headers example.com
```

## Security Headers Checklist

| Header | Value | Purpose |
|--------|-------|---------|
| Strict-Transport-Security | max-age=63072000; includeSubDomains; preload | Force HTTPS |
| X-Content-Type-Options | nosniff | Prevent MIME sniffing |
| X-Frame-Options | DENY | Prevent clickjacking |
| Content-Security-Policy | default-src 'self' | Prevent XSS |
| Referrer-Policy | strict-origin-when-cross-origin | Limit referrer leakage |
