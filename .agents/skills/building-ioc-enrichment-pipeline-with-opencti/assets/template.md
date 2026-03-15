# IOC Enrichment Report Template

## Report Metadata
| Field | Value |
|-------|-------|
| Report ID | ENRICH-YYYY-NNNN |
| Date | YYYY-MM-DD HH:MM UTC |
| Platform | OpenCTI v6.x |
| Analyst | [Analyst Name] |
| Classification | TLP:AMBER |

## Observable Summary

| Observable | Type | Initial Score | Enriched Score | Priority |
|-----------|------|---------------|----------------|----------|
| x.x.x.x | IPv4-Addr | 0 | 85 | Critical |
| evil.com | Domain-Name | 0 | 62 | High |

## Enrichment Results

### Observable: [Value]
**Type**: IPv4-Addr / Domain-Name / StixFile

#### VirusTotal
| Metric | Value |
|--------|-------|
| Malicious Detections | X / Y engines |
| Suspicious | X |
| Reputation Score | X |
| AS Owner | |
| Country | |

#### Shodan
| Metric | Value |
|--------|-------|
| Open Ports | |
| Known Vulnerabilities | |
| ISP | |
| Organization | |
| Operating System | |

#### AbuseIPDB
| Metric | Value |
|--------|-------|
| Abuse Confidence Score | X% |
| Total Reports | X |
| Distinct Reporters | X |
| Is Tor Exit Node | Yes/No |
| Usage Type | |

#### GreyNoise
| Metric | Value |
|--------|-------|
| Classification | malicious/benign/unknown |
| Internet Noise | Yes/No |
| RIOT (Benign Service) | Yes/No |
| Name | |
| Last Seen | |

## Confidence Scoring Breakdown

| Source | Weight | Score Contribution |
|--------|--------|--------------------|
| VirusTotal | 30% | X points |
| AbuseIPDB | 30% | X points |
| GreyNoise | 20% | X points |
| Shodan | 20% | X points |
| **Total** | **100%** | **X / 100** |

## Recommended Actions

| Priority | Action | Observable | Reason |
|----------|--------|-----------|--------|
| Critical | Block immediately | | Score > 80 |
| High | Add to watchlist | | Score 50-79 |
| Medium | Monitor | | Score 20-49 |
| Low | No action needed | | Score < 20 |

## STIX Relationships Created

| Source | Relationship | Target |
|--------|-------------|--------|
| [Observable] | indicates | [Malware/Campaign] |
| [Observable] | related-to | [Infrastructure] |
| [Threat Actor] | uses | [Observable] |
