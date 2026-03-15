# API Reference: Analyzing TLS Certificate Transparency Logs

## pycrtsh

```python
from pycrtsh import Crtsh
c = Crtsh()

# Search certificates by domain
certs = c.search("example.com")      # exact match
certs = c.search("%.example.com")    # wildcard subdomains

# Get certificate details by ID
details = c.get(cert_id, type="id")
details = c.get(sha1_hash, type="sha1")
details = c.get(sha256_hash, type="sha256")
```

## crt.sh REST API (Direct)

```python
import requests

# JSON output
resp = requests.get("https://crt.sh/?q=%.example.com&output=json")
records = resp.json()
# Fields: id, issuer_ca_id, issuer_name, common_name,
#          name_value, not_before, not_after, serial_number
```

## certstream (Real-Time CT Monitoring)

```python
import certstream

def callback(message, context):
    if message["message_type"] == "certificate_update":
        all_domains = message["data"]["leaf_cert"]["all_domains"]
        print(all_domains)

certstream.listen_for_events(callback, url="wss://certstream.calidog.io/")
```

## Key Certificate Fields

| Field | Description |
|-------|-------------|
| `common_name` | Primary domain on certificate |
| `name_value` | SAN (Subject Alternative Names) |
| `issuer_name` | Certificate Authority |
| `not_before` | Issuance date |
| `not_after` | Expiration date |

### References

- pycrtsh: https://pypi.org/project/pycrtsh/
- crt.sh: https://crt.sh/
- certstream: https://certstream.calidog.io/
- CT RFC 6962: https://datatracker.ietf.org/doc/html/rfc6962
