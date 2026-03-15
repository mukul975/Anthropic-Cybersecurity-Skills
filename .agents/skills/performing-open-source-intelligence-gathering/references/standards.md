# Standards and Framework References

## MITRE ATT&CK - Reconnaissance (TA0043)

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1595.001 | Active Scanning: Scanning IP Blocks | Scanning target IP ranges for active hosts |
| T1595.002 | Active Scanning: Vulnerability Scanning | Scanning for vulnerabilities on discovered hosts |
| T1592.001 | Gather Victim Host Information: Hardware | Identifying target hardware configurations |
| T1592.002 | Gather Victim Host Information: Software | Identifying installed software and versions |
| T1592.004 | Gather Victim Host Information: Client Configurations | Discovering client-side configurations |
| T1589.001 | Gather Victim Identity Information: Credentials | Searching for exposed credentials |
| T1589.002 | Gather Victim Identity Information: Email Addresses | Harvesting email addresses |
| T1589.003 | Gather Victim Identity Information: Employee Names | Collecting employee information |
| T1590.001 | Gather Victim Network Information: Domain Properties | DNS and domain enumeration |
| T1590.002 | Gather Victim Network Information: DNS | DNS record collection |
| T1590.004 | Gather Victim Network Information: Network Topology | Mapping network architecture |
| T1590.005 | Gather Victim Network Information: IP Addresses | Identifying target IP addresses |
| T1591.001 | Gather Victim Org Information: Determine Physical Locations | Physical location mapping |
| T1591.002 | Gather Victim Org Information: Business Relationships | Identifying vendors and partners |
| T1591.004 | Gather Victim Org Information: Identify Roles | Mapping organizational roles |
| T1593.001 | Search Open Websites/Domains: Social Media | Social media intelligence |
| T1593.002 | Search Open Websites/Domains: Search Engines | Google dorking and search engine recon |
| T1594 | Search Victim-Owned Websites | Analyzing target websites |
| T1596.001 | Search Open Technical Databases: DNS/Passive DNS | Passive DNS intelligence |
| T1596.005 | Search Open Technical Databases: Scan Databases | Shodan, Censys, ZoomEye queries |
| T1597.001 | Search Closed Sources: Threat Intel Vendors | Threat intelligence platform queries |

## PTES - Intelligence Gathering

### Level 1: Passive Information Gathering
- WHOIS lookups
- DNS enumeration
- Search engine queries
- Social media analysis
- Public records review

### Level 2: Semi-Passive Information Gathering
- Website analysis and spidering
- Metadata extraction from documents
- Job posting analysis
- Technology stack identification

### Level 3: Active Information Gathering
- Port scanning
- Service enumeration
- Web application fingerprinting
- Active subdomain brute-forcing

## OSSTMM - Information Security Testing

### Section 5: Human Security Testing
- Social engineering reconnaissance
- Personnel profiling
- Communication channel mapping

### Section 6: Physical Security Testing
- Location reconnaissance
- Access control assessment
- Surveillance analysis

## NIST SP 800-115 Section 3: Review Techniques
- Documentation review
- Log review
- Ruleset review
- System configuration review
- Network sniffing (passive)
