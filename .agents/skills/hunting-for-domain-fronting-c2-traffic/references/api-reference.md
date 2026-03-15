# Domain Fronting C2 Traffic Detection API Reference

## Domain Fronting Mechanism

```
TLS ClientHello:  SNI = legitimate-cdn-domain.cloudfront.net
HTTP Request:     Host: attacker-c2-server.evil.com
```

The CDN accepts the TLS connection based on SNI, then routes the HTTP request
to the backend specified in the Host header. Network monitoring sees only the
legitimate SNI domain.

## MITRE ATT&CK

| Technique | ID | Description |
|---|---|---|
| Proxy: Domain Fronting | T1090.004 | Route C2 through CDN using SNI/Host mismatch |

## CDN Provider Identification

### Certificate Issuers
| CDN | Certificate CN Pattern |
|---|---|
| CloudFront | *.cloudfront.net |
| Azure CDN | *.azureedge.net |
| Cloudflare | sni.cloudflaressl.com |
| Akamai | *.akamaiedge.net |
| Fastly | *.fastly.net |

## Proxy Log Detection

### Squid Proxy Log Fields
```
timestamp src_ip CONNECT sni:443 -> status Host: host_header
```

### Palo Alto Threat ID
```
Threat ID 86467: Domain fronting detected (SNI/Host mismatch)
```

### Splunk Detection Query
```spl
index=proxy sourcetype=squid OR sourcetype=bluecoat
| eval sni_root=mvindex(split(sni, "."), -2) + "." + mvindex(split(sni, "."), -1)
| eval host_root=mvindex(split(host_header, "."), -2) + "." + mvindex(split(host_header, "."), -1)
| where sni_root != host_root
| stats count by sni, host_header, src_ip
| sort -count
```

## pyOpenSSL Certificate Inspection

```python
from OpenSSL import crypto
import ssl, socket

ctx = ssl.create_default_context()
with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
    s.connect((hostname, 443))
    der_cert = s.getpeercert(True)

x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)
subject_cn = x509.get_subject().CN
issuer_cn = x509.get_issuer().CN

for i in range(x509.get_extension_count()):
    ext = x509.get_extension(i)
    if ext.get_short_name() == b"subjectAltName":
        print(str(ext))  # DNS:*.cloudfront.net, DNS:cloudfront.net
```

## CLI Usage
```bash
python agent.py --proxy-log squid_access.csv --output fronting_report.json
python agent.py --proxy-log logs.csv --check-certs
```
