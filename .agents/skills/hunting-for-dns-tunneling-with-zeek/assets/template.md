# DNS Tunneling Hunt Template

## Hunt Metadata
| Field | Value |
|-------|-------|
| Hunt ID | TH-DNSTUNNEL-YYYY-MM-DD-NNN |
| Analyst | |
| Date | |
| Status | [ ] In Progress / [ ] Complete |

## Hypothesis
> Adversaries are using DNS tunneling to establish covert C2 channels or exfiltrate data by encoding information in DNS query subdomain labels.

## DNS Tunneling Findings

| # | Source IP | Host | Domain | Queries | Unique Subs | Avg Length | Entropy | Record Types | Risk |
|---|----------|------|--------|---------|-------------|-----------|---------|-------------|------|
| 1 | | | | | | | | | |

## Data Exfiltration Estimate

| Domain | Total Queries | Avg Subdomain Size | Estimated Data Volume | Assessment |
|--------|--------------|--------------------|-----------------------|------------|
| | | | | |

## Recommendations
1. **Sinkhole**: [DNS domains to sinkhole]
2. **Block**: [Domains at DNS resolver and firewall]
3. **Isolate**: [Source endpoints for investigation]
4. **Monitor**: [Deploy DNS tunneling detection rules]
