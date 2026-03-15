# API Reference: SSL Certificate Lifecycle Management

## cryptography Library - CSR Generation

| Class / Method | Description |
|----------------|-------------|
| `ec.generate_private_key(ec.SECP256R1())` | Generate ECDSA P-256 private key |
| `rsa.generate_private_key(65537, 2048)` | Generate RSA 2048-bit private key |
| `x509.CertificateSigningRequestBuilder()` | Build a PKCS#10 CSR |
| `.subject_name(x509.Name([...]))` | Set CSR subject |
| `.add_extension(SubjectAlternativeName(...))` | Add SAN extension |
| `.sign(private_key, hashes.SHA256())` | Sign CSR with private key |

## cryptography Library - Certificate Parsing

| Method | Description |
|--------|-------------|
| `x509.load_pem_x509_certificate(data)` | Parse PEM certificate |
| `x509.load_der_x509_certificate(data)` | Parse DER certificate |
| `cert.subject` | Get subject Distinguished Name |
| `cert.issuer` | Get issuer Distinguished Name |
| `cert.not_valid_after_utc` | Expiration datetime |
| `cert.serial_number` | Certificate serial number |
| `cert.extensions.get_extension_for_oid(OID)` | Get specific extension |

## Python ssl Module

| Function | Description |
|----------|-------------|
| `ssl.create_default_context()` | Create SSL context with system CAs |
| `ctx.wrap_socket(sock, server_hostname=host)` | TLS handshake |
| `s.getpeercert(binary_form=True)` | Get DER-encoded server certificate |
| `s.getpeercert()` | Get parsed certificate dict |

## Certificate Types

| Type | Validation | Typical Use |
|------|-----------|-------------|
| DV | Domain ownership | Websites, APIs |
| OV | Organization verified | Business applications |
| EV | Full legal verification | E-commerce, banking |
| Wildcard | `*.domain.com` | Multi-subdomain |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `cryptography` | >=41.0 | CSR generation, certificate parsing |
| `ssl` | stdlib | TLS handshake, remote cert fetch |
| `socket` | stdlib | TCP connections |

## References

- cryptography docs: https://cryptography.io/en/latest/x509/
- Let's Encrypt ACME: https://letsencrypt.org/docs/
- OCSP Stapling: https://datatracker.ietf.org/doc/html/rfc6960
- Certificate Transparency: https://certificate.transparency.dev/
