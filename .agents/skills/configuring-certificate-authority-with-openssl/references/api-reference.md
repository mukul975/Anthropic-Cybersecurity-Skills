# Certificate Authority with OpenSSL — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| cryptography | `pip install cryptography` | X.509 certificate generation, parsing, and validation |
| pyOpenSSL | `pip install pyOpenSSL` | OpenSSL wrapper for certificate operations |

## Key cryptography Methods

| Method | Description |
|--------|-------------|
| `x509.CertificateBuilder()` | Build X.509 certificates |
| `rsa.generate_private_key(65537, key_size)` | Generate RSA private key |
| `x509.load_pem_x509_certificate(data)` | Parse PEM certificate |
| `cert.subject.rfc4514_string()` | Get subject as RFC 4514 string |
| `x509.random_serial_number()` | Generate unique serial number |

## OpenSSL CLI Commands

| Command | Purpose |
|---------|---------|
| `openssl req -x509 -newkey rsa:4096 -sha256 -days 3650` | Create self-signed CA |
| `openssl req -new -key server.key -out server.csr` | Generate CSR |
| `openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key` | Sign certificate |
| `openssl verify -CAfile ca.crt server.crt` | Verify certificate chain |
| `openssl x509 -in cert.pem -text -noout` | Display certificate details |

## Certificate Best Practices

| Parameter | Recommended Value |
|-----------|-------------------|
| Root CA Key Size | RSA 4096 or EC P-384 |
| Server Key Size | RSA 2048+ or EC P-256 |
| Signature Algorithm | SHA-256 or SHA-384 |
| Root CA Validity | 10-20 years |
| Server Cert Validity | 1 year (398 days max for public) |

## External References

- [cryptography.io X.509 Docs](https://cryptography.io/en/latest/x509/)
- [OpenSSL Cookbook](https://www.feistyduck.com/library/openssl-cookbook/)
- [RFC 5280 X.509 PKI](https://datatracker.ietf.org/doc/html/rfc5280)
