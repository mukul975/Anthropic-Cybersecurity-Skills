# API Reference: Typosquatting Detection with dnstwist

## dnstwist CLI

### Syntax
```bash
dnstwist example.com                    # Basic scan
dnstwist -r example.com                 # Resolve DNS
dnstwist -r -f json example.com         # JSON output
dnstwist -r -f csv example.com          # CSV output
dnstwist -r --ssdeep example.com        # Fuzzy hashing comparison
dnstwist -r --phash example.com         # Perceptual hash (screenshot)
dnstwist -r -w wordlist.txt example.com # Dictionary-based
dnstwist --nameservers 8.8.8.8 example.com  # Custom DNS
```

### Fuzzing Techniques
| Technique | Description |
|-----------|-------------|
| Addition | Append character: `examplea.com` |
| Bitsquatting | Bit-flip: `dxample.com` |
| Homoglyph | Lookalike chars: `examp1e.com` |
| Hyphenation | Insert hyphen: `exam-ple.com` |
| Insertion | Insert char: `exaample.com` |
| Omission | Remove char: `examle.com` |
| Repetition | Double char: `exxample.com` |
| Replacement | Keyboard neighbor: `rxample.com` |
| Subdomain | Insert dot: `ex.ample.com` |
| Transposition | Swap chars: `exmaple.com` |
| Vowel-swap | Replace vowel: `exomple.com` |

### Output Fields
| Field | Description |
|-------|-------------|
| `fuzzer` | Technique used |
| `domain` | Permuted domain |
| `dns_a` | A record IP addresses |
| `dns_aaaa` | AAAA record addresses |
| `dns_mx` | Mail server records |
| `dns_ns` | Nameserver records |
| `geoip` | GeoIP country |
| `whois_registrar` | Domain registrar |
| `ssdeep_score` | Fuzzy hash similarity (0-100) |

## Python Integration

### Installation
```bash
pip install dnstwist
```

### CLI via subprocess
```python
import subprocess, json
result = subprocess.run(
    ["dnstwist", "-r", "-f", "json", "example.com"],
    capture_output=True, text=True)
domains = json.loads(result.stdout)
for d in domains:
    if d.get("dns_a"):
        print(f"{d['domain']} -> {d['dns_a']}")
```

## WHOIS Lookup
```python
import whois
w = whois.whois("suspicious-domain.com")
print(w.creation_date, w.registrar)
```

## VirusTotal Domain Check
```bash
curl -H "x-apikey: KEY" \
  "https://www.virustotal.com/api/v3/domains/<domain>"
```
