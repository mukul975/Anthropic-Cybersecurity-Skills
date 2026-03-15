# API Reference: Performing SSL/TLS Security Assessment

## sslyze Python API

```python
from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation

location = ServerNetworkLocation(hostname="example.com", port=443)
request = ServerScanRequest(server_location=location)
scanner = Scanner()
scanner.queue_scans([request])

for result in scanner.get_results():
    scan = result.scan_result
    # Access individual scan command results
    tls12 = scan.tls_1_2_cipher_suites
    cert = scan.certificate_info
    heartbleed = scan.heartbleed
```

Install: `pip install sslyze`

## Scan Command Attributes

| Attribute | Check |
|-----------|-------|
| ssl_2_0_cipher_suites | SSLv2 support (must be disabled) |
| ssl_3_0_cipher_suites | SSLv3 support (must be disabled) |
| tls_1_0_cipher_suites | TLS 1.0 (deprecated) |
| tls_1_1_cipher_suites | TLS 1.1 (deprecated) |
| tls_1_2_cipher_suites | TLS 1.2 (current) |
| tls_1_3_cipher_suites | TLS 1.3 (recommended) |
| certificate_info | Certificate chain validation |
| heartbleed | CVE-2014-0160 Heartbleed |
| robot | ROBOT RSA oracle attack |
| openssl_ccs_injection | CVE-2014-0224 |
| session_renegotiation | Client-initiated renego |

## Weak Cipher Suite Keywords

| Keyword | Risk | Description |
|---------|------|-------------|
| RC4 | High | Broken stream cipher |
| DES / 3DES | High | Weak block cipher |
| NULL | Critical | No encryption |
| EXPORT | Critical | Weak export-grade cipher |
| anon | Critical | No authentication |

## sslyze CLI

```bash
sslyze example.com --regular
sslyze example.com --certinfo --tlsv1_2 --heartbleed --robot
sslyze example.com --json_out results.json
```

## References

- sslyze GitHub: https://github.com/nabla-c0d3/sslyze
- sslyze Docs: https://nabla-c0d3.github.io/sslyze/documentation/
- sslyze PyPI: https://pypi.org/project/sslyze/
- Mozilla TLS Config: https://wiki.mozilla.org/Security/Server_Side_TLS
