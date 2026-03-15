# API Reference: Tracking Threat Actor Infrastructure

## Pivoting Techniques

| Technique | Source | Discovers |
|-----------|--------|-----------|
| Passive DNS | DNS resolvers | Domains on same IP, historical mappings |
| Reverse WHOIS | Registrar data | Domains by same registrant |
| SSL Certificate | CT logs, direct | Shared certs, SANs, issuers |
| Shodan/Censys | Internet scanning | Open ports, services, banners |
| HTTP fingerprint | Server responses | Body hash, headers, favicon |
| JARM/JA3S | TLS handshake | C2 framework identification |

## API Endpoints

| Service | Endpoint | Auth |
|---------|----------|------|
| Shodan Host | `GET /shodan/host/{ip}?key=` | API key |
| VirusTotal IP | `GET /api/v3/ip-addresses/{ip}` | x-apikey header |
| VirusTotal Domain | `GET /api/v3/domains/{domain}` | x-apikey header |
| SecurityTrails | `GET /v1/domain/{d}/subdomains` | APIKEY header |
| RDAP WHOIS | `GET https://rdap.org/domain/{d}` | None |

## Network Fingerprinting

| Method | Tool | Description |
|--------|------|-------------|
| JARM | jarm.py | Active TLS server fingerprint |
| JA3S | Zeek/Wireshark | Passive TLS Server Hello hash |
| Favicon hash | Shodan `http.favicon.hash` | mmh3 hash of favicon.ico |
| HTTP body hash | SHA-256 | Response body fingerprint |
| Server banner | HTTP Server header | Software identification |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | API queries to Shodan/VT |
| `ssl` | stdlib | TLS certificate retrieval |
| `socket` | stdlib | DNS resolution, connections |
| `hashlib` | stdlib | Certificate/content fingerprinting |

## References

- Shodan API: https://developer.shodan.io/api
- VirusTotal API v3: https://docs.virustotal.com/reference/overview
- Certificate Transparency: https://certificate.transparency.dev/
- JARM: https://github.com/salesforce/jarm
