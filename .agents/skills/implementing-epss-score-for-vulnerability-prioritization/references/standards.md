# Standards and References - EPSS Vulnerability Prioritization

## Primary Standards

### FIRST EPSS
- **Source**: Forum of Incident Response and Security Teams
- **URL**: https://www.first.org/epss/
- **API**: https://api.first.org/data/v1/epss
- **Model**: Machine learning trained on real exploitation events, updated daily
- **Versions**: v1 (2021), v2 (2022), v3 (2023), v4 (2025)

### CVSS v3.1 and v4.0
- **Source**: FIRST
- **URL**: https://www.first.org/cvss/
- **Relevance**: EPSS complements CVSS; CVSS measures severity, EPSS measures exploitation probability

### CISA Stakeholder-Specific Vulnerability Categorization (SSVC)
- **URL**: https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc
- **Relevance**: SSVC uses exploitation status as a key decision point; EPSS provides data-driven input

### CISA Known Exploited Vulnerabilities (KEV)
- **URL**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **Relevance**: KEV confirms active exploitation; EPSS predicts future exploitation probability

## Research Papers

### Original EPSS Paper
- **Title**: "Improving Vulnerability Remediation Through Better Exploit Prediction"
- **Authors**: Jay Jacobs, Sasha Romanosky, Benjamin Edwards, Michael Roytman, Idris Adjerid
- **Published**: Workshop on the Economics of Information Security (WEIS), 2021

### EPSS v3 Model
- **Features**: 1,477 features including CVE properties, vendor data, social media mentions, exploit code availability
- **Training Data**: Historical exploitation events from multiple sources
- **Performance**: AUC of 0.85+ for 30-day exploitation prediction

## Data Sources Used by EPSS

| Source | Data Type | Update Frequency |
|--------|----------|-----------------|
| NVD | CVE metadata, CVSS scores | Real-time |
| CISA KEV | Confirmed exploitation | As new CVEs added |
| Exploit-DB | Public exploit code | Daily |
| GitHub | Exploit PoC repositories | Daily |
| Metasploit | Exploit modules | Weekly |
| SecurityFocus | Vulnerability discussions | Daily |
| Social Media | Twitter/X mentions of CVEs | Real-time |
| Fortinet | Exploitation telemetry | Daily |
| AlienVault OTX | Threat intelligence | Daily |

## API Reference

### Endpoints
- **Single CVE**: `GET https://api.first.org/data/v1/epss?cve=CVE-YYYY-NNNNN`
- **Multiple CVEs**: `GET https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2,...`
- **Date-specific**: `GET https://api.first.org/data/v1/epss?cve=CVE-YYYY-NNNNN&date=YYYY-MM-DD`
- **Time series**: `GET https://api.first.org/data/v1/epss?cve=CVE-YYYY-NNNNN&scope=time-series`
- **Top scoring**: `GET https://api.first.org/data/v1/epss?percentile-gt=0.95`
- **Full download**: `https://epss.cyentia.com/epss_scores-current.csv.gz`
