# Threat Actor Infrastructure Tracking Report

## Report Metadata
| Field | Value |
|-------|-------|
| Report ID | INFRA-YYYY-NNNN |
| Date | YYYY-MM-DD |
| Classification | TLP:AMBER |
| Analyst | [Name] |

## Infrastructure Summary
| Metric | Count |
|--------|-------|
| C2 Servers Identified | |
| Domains Tracked | |
| SSL Certificates Found | |
| ASNs Involved | |
| Countries | |

## C2 Servers
| IP Address | Ports | Framework | ASN | Country | First Seen | Last Seen |
|-----------|-------|-----------|-----|---------|-----------|----------|
| | | | | | | |

## Associated Domains
| Domain | Resolved IP | First Seen | Last Seen | Source |
|--------|-----------|-----------|----------|--------|
| | | | | pDNS/CT/WHOIS |

## SSL Certificates
| Common Name | Issuer | Not Before | Not After | SANs |
|------------|--------|-----------|----------|------|
| | | | | |

## Pivot Map
```
[Seed IP] --> [Domain A] --> [IP B] --> [Domain C]
                  |                         |
                  v                         v
            [CT: Domain D]           [WHOIS: Domain E]
```

## Recommendations
1. Block identified C2 IPs and domains at network perimeter
2. Deploy JARM/JA3S signatures for C2 framework detection
3. Monitor CT logs for new certificates matching tracked domains
4. Set up passive DNS alerts for domain resolution changes
