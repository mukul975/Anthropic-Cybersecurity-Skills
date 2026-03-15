# API Reference: Hunting for DNS-based Persistence

## SecurityTrails API

```bash
# Get current DNS records
curl -s "https://api.securitytrails.com/v1/domain/example.com" \
  -H "APIKEY: ${ST_API_KEY}"

# Get subdomains
curl -s "https://api.securitytrails.com/v1/domain/example.com/subdomains" \
  -H "APIKEY: ${ST_API_KEY}"

# Historical A records
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/a" \
  -H "APIKEY: ${ST_API_KEY}"

# Historical NS records
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/ns" \
  -H "APIKEY: ${ST_API_KEY}"

# WHOIS history
curl -s "https://api.securitytrails.com/v1/history/example.com/whois" \
  -H "APIKEY: ${ST_API_KEY}"
```

## DNS Record Types to Hunt

| Record | Persistence Risk | Detection |
|--------|-----------------|-----------|
| A/AAAA | IP hijacking to attacker infra | Compare against baseline |
| CNAME | Subdomain takeover via dangling records | Resolve target, check NXDOMAIN |
| NS | Full zone delegation hijack | Compare against registrar NS |
| MX | Email interception | Monitor for unauthorized MX |
| TXT | C2 data exfiltration channel | Check for encoded payloads |
| Wildcard (*) | Catch-all subdomain resolution | Test random subdomain resolution |

## Dangling CNAME Services (Subdomain Takeover)

| Service | CNAME Pattern | Takeover Method |
|---------|---------------|-----------------|
| AWS S3 | *.s3.amazonaws.com | Create matching bucket |
| GitHub Pages | *.github.io | Create matching repo |
| Azure Web Apps | *.azurewebsites.net | Register app name |
| Heroku | *.herokuapp.com | Create matching app |
| Shopify | *.myshopify.com | Claim custom domain |
| CloudFront | *.cloudfront.net | Create matching distribution |

## dig Commands for Hunting

```bash
# Check all record types
dig ANY example.com +noall +answer

# Test for wildcard records
dig A randomtest123.example.com +short

# Check NS delegation chain
dig NS example.com +trace

# Verify DNSSEC
dig DNSKEY example.com +dnssec +short

# Check for zone transfer (authorized testing only)
dig AXFR example.com @ns1.example.com
```

## MITRE ATT&CK DNS Techniques

| Technique | ID | Description |
|-----------|----|-------------|
| DNS Hijacking | T1584.001 | Modify DNS records to redirect traffic |
| DNS Server | T1583.002 | Acquire DNS server for C2 |
| Domain Fronting | T1090.004 | Use CDN to mask C2 |
| DNS Tunneling | T1572 | Encode data in DNS queries |

### References

- SecurityTrails API: https://securitytrails.com/corp/api
- Can I Take Over XYZ: https://github.com/EdOverflow/can-i-take-over-xyz
- Passive DNS databases: https://www.farsightsecurity.com/solutions/dnsdb/
