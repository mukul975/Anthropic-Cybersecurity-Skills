# API Reference: Analyzing Cobalt Strike Malleable Profiles

## pyMalleableC2

```python
from malleablec2 import Profile
from malleablec2.components import HttpGetBlock, HttpPostBlock, ClientBlock, ServerBlock

# Parse from file or string
p = Profile.from_file("amazon.profile")
p = Profile.from_string(code_string)
p = Profile.from_scratch()

# Set global options
p.set_option("sleeptime", "3000")
p.set_option("jitter", "0")
p.set_option("pipename", "mojo__##")

# HTTP blocks
http_get = HttpGetBlock()
http_get.set_option("uri", "/updates")
client = ClientBlock()
client.add_statement("header", "Accept", "*/*")
http_get.add_code_block(client)
p.add_code_block(http_get)

# AST and reconstruction
print(p.ast.pretty())   # Display AST
print(p)                # Reconstruct source
```

## JARM TLS Fingerprinting

```bash
# Scan a single host
python3 jarm.py www.example.com

# Scan with specific port
python3 jarm.py 192.168.1.1 -p 8443

# Batch scan from file
python3 jarm.py -i targets.txt -o results.csv
```

Fingerprint format: 62-char hybrid hash
- First 30 chars: cipher + TLS version (10 handshakes x 3 chars)
- Last 32 chars: truncated SHA256 of cumulative extensions

## Known Cobalt Strike JARM Hashes

| JARM Hash | Description |
|-----------|-------------|
| `07d14d16d21d21d07c42d41d00041d...` | CS default config |
| `07d14d16d21d21d00042d41d00041d...` | CS with Java 11 |

## dissect.cobaltstrike (Alternative)

```python
from dissect.cobaltstrike import beacon
b = beacon.BeaconConfig.from_file("beacon.bin")
print(b.protocol, b.port, b.sleeptime)
```

### References

- pyMalleableC2: https://github.com/byt3bl33d3r/pyMalleableC2
- JARM scanner: https://github.com/salesforce/jarm
- dissect.cobaltstrike: https://github.com/fox-it/dissect.cobaltstrike
- C2 JARM list: https://github.com/cedowens/C2-JARM
