# API Reference: Certificate Transparency Phishing Detection

## crt.sh API

### Search Certificates
```bash
# JSON output
curl "https://crt.sh/?q=%.example.com&output=json"

# Exclude expired
curl "https://crt.sh/?q=%.example.com&output=json&exclude=expired"

# Exact match
curl "https://crt.sh/?q=example.com&output=json"
```

### Response Fields
| Field | Description |
|-------|-------------|
| `id` | Certificate ID in crt.sh database |
| `common_name` | Certificate CN |
| `name_value` | All SANs (newline-separated) |
| `issuer_name` | Certificate Authority |
| `not_before` | Validity start |
| `not_after` | Validity end |
| `serial_number` | Certificate serial |

## Certstream - Real-time CT Monitoring

### Python Client
```python
import certstream

def callback(message, context):
    if message["message_type"] == "certificate_update":
        data = message["data"]
        domains = data["leaf_cert"]["all_domains"]
        for domain in domains:
            if "example" in domain:
                print(f"[ALERT] {domain}")

certstream.listen_for_events(callback, url="wss://certstream.calidog.io/")
```

### Message Fields
| Field | Path |
|-------|------|
| Domains | `data.leaf_cert.all_domains` |
| Issuer | `data.leaf_cert.issuer.O` |
| Subject | `data.leaf_cert.subject.CN` |
| Fingerprint | `data.leaf_cert.fingerprint` |
| Source | `data.source.name` |

## CT Log Servers

| Log | Operator | URL |
|-----|----------|-----|
| Argon | Google | `ct.googleapis.com/logs/argon2024` |
| Xenon | Google | `ct.googleapis.com/logs/xenon2024` |
| Nimbus | Cloudflare | `ct.cloudflare.com/logs/nimbus2024` |
| Oak | Let's Encrypt | `oak.ct.letsencrypt.org/2024h1` |
| Yeti | DigiCert | `yeti2024.ct.digicert.com/log` |

## Phishing Detection Techniques

### Homoglyph / IDN Attacks
| Original | Lookalike | Technique |
|----------|-----------|-----------|
| example.com | examp1e.com | Character substitution (l→1) |
| google.com | gооgle.com | Cyrillic о (U+043E) |
| paypal.com | paypa1.com | l→1 substitution |
| microsoft.com | mіcrosoft.com | Cyrillic і (U+0456) |

### dnstwist Integration
```bash
dnstwist -r -f json example.com   # Generate and resolve permutations
dnstwist -w wordlist.txt example.com  # Dictionary-based
```

## Certificate Details Lookup
```bash
# Get full certificate from crt.sh
curl "https://crt.sh/?d=<cert_id>"

# OpenSSL inspection
openssl s_client -connect domain.com:443 -servername domain.com </dev/null 2>/dev/null | \
  openssl x509 -noout -text
```

## Suspicious Indicators
| Pattern | Risk Level |
|---------|-----------|
| Free CA + new domain + brand keyword | HIGH |
| Wildcard cert on recently registered domain | HIGH |
| Multiple certs for slight domain variants | MEDIUM |
| IDN/punycode domain mimicking brand | HIGH |
| Cert issued same day as domain registration | MEDIUM |
