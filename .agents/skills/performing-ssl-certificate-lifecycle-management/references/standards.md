# Standards and References - SSL Certificate Lifecycle Management

## Primary Standards

### RFC 5280 - Internet X.509 PKI Certificate and CRL Profile
- **URL**: https://www.rfc-editor.org/rfc/rfc5280
- **Description**: Core X.509 certificate format and Certificate Revocation List (CRL)

### RFC 6960 - X.509 Online Certificate Status Protocol (OCSP)
- **URL**: https://www.rfc-editor.org/rfc/rfc6960
- **Description**: Real-time certificate revocation checking

### RFC 8555 - Automatic Certificate Management Environment (ACME)
- **URL**: https://www.rfc-editor.org/rfc/rfc8555
- **Description**: Protocol for automating certificate issuance (Let's Encrypt)

### RFC 6962 - Certificate Transparency
- **URL**: https://www.rfc-editor.org/rfc/rfc6962
- **Description**: Public logging framework for TLS certificates

### RFC 2986 - PKCS #10: Certification Request Syntax
- **URL**: https://www.rfc-editor.org/rfc/rfc2986
- **Description**: CSR format specification

### NIST SP 800-57 Part 3 - Application-Specific Key Management
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-57-part-3/rev-1/final
- **Description**: Key management guidance for TLS certificates

## Tools

### Let's Encrypt / Certbot
- **URL**: https://letsencrypt.org/
- **Certbot**: https://certbot.eff.org/
- **Rate limits**: 50 certificates per domain per week

### Certificate Transparency Logs
- **Google**: https://ct.googleapis.com/logs
- **crt.sh**: https://crt.sh/ (certificate search)

### Mozilla Observatory
- **URL**: https://observatory.mozilla.org/
- **Description**: Web security scanning including TLS configuration
