# Standards and References - TLS 1.3 Configuration

## Primary Standards

### RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3
- **URL**: https://www.rfc-editor.org/rfc/rfc8446
- **Description**: The core TLS 1.3 specification
- **Key changes**: 1-RTT handshake, mandatory PFS, removed RSA key transport, encrypted handshake messages

### RFC 8447 - IANA Registry Updates for TLS and DTLS
- **URL**: https://www.rfc-editor.org/rfc/rfc8447
- **Description**: Updates IANA registries for TLS cipher suites and extensions

### RFC 8449 - Record Size Limit Extension for TLS
- **URL**: https://www.rfc-editor.org/rfc/rfc8449
- **Description**: Allows endpoints to negotiate maximum record size

### RFC 8470 - Using Early Data in HTTP (0-RTT)
- **URL**: https://www.rfc-editor.org/rfc/rfc8470
- **Description**: Defines how 0-RTT early data works with HTTP, including replay protections

### RFC 6961 - TLS Multiple Certificate Status Extension (OCSP Stapling)
- **URL**: https://www.rfc-editor.org/rfc/rfc6961
- **Description**: Allows servers to provide OCSP responses during handshake

### RFC 6797 - HTTP Strict Transport Security (HSTS)
- **URL**: https://www.rfc-editor.org/rfc/rfc6797
- **Description**: Forces browsers to use HTTPS for all connections

## NIST Guidelines

### NIST SP 800-52 Rev. 2 - Guidelines for TLS Implementations
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final
- **Description**: Federal guidelines for TLS deployment
- **TLS 1.3**: Recommended for all new deployments
- **TLS 1.2**: Acceptable with approved cipher suites
- **TLS 1.0/1.1**: Prohibited

### NIST SP 800-57 Part 3 Rev. 1 - Application-Specific Key Management
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-57-part-3/rev-1/final
- **Description**: Key management guidance for TLS

## Testing Tools

### testssl.sh
- **URL**: https://testssl.sh/
- **GitHub**: https://github.com/drwetter/testssl.sh
- **Description**: Command-line tool for checking TLS/SSL configurations

### SSL Labs Server Test
- **URL**: https://www.ssllabs.com/ssltest/
- **Description**: Online TLS configuration analyzer (Qualys)

### Mozilla SSL Configuration Generator
- **URL**: https://ssl-config.mozilla.org/
- **Description**: Generate recommended TLS configurations for various servers

## Compliance

### PCI DSS v4.0
- TLS 1.0 and early TLS prohibited since June 2018
- TLS 1.2+ required; TLS 1.3 recommended
- Strong cipher suites must be configured

### HIPAA
- Encryption in transit required for ePHI
- TLS 1.2+ satisfies the requirement
