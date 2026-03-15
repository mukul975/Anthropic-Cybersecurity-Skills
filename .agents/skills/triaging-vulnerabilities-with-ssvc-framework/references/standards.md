# Standards and References - SSVC Vulnerability Triage

## Primary Standards

### CISA SSVC Framework
- **Source**: Cybersecurity and Infrastructure Security Agency (CISA)
- **URL**: https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc
- **Version**: SSVC v2.0 (2022 revision by CISA with SEI)
- **Purpose**: Provides a decision-tree methodology for vulnerability prioritization based on five decision points specific to the stakeholder's context

### CERT/CC SSVC Original Research
- **Source**: Carnegie Mellon University Software Engineering Institute
- **URL**: https://certcc.github.io/SSVC/
- **Publication**: "Prioritizing Vulnerability Response: A Stakeholder-Specific Vulnerability Categorization" (2019)
- **Authors**: Jonathan Spring, Eric Hatleback, Allen Householder, Art Manion, Deana Shick
- **DOI**: https://doi.org/10.1184/R1/12124386

### CVSS v3.1 and v4.0
- **Source**: Forum of Incident Response and Security Teams (FIRST)
- **URL**: https://www.first.org/cvss/
- **CVSS v3.1 Specification**: https://www.first.org/cvss/v3.1/specification-document
- **CVSS v4.0 Specification**: https://www.first.org/cvss/v4.0/specification-document
- **Relevance**: SSVC complements CVSS by adding contextual decision points beyond base score severity

### EPSS - Exploit Prediction Scoring System
- **Source**: FIRST EPSS Special Interest Group
- **URL**: https://www.first.org/epss/
- **API Endpoint**: https://api.first.org/data/v1/epss
- **Model Documentation**: https://www.first.org/epss/model
- **Relevance**: EPSS probability scores inform the exploitation status decision point in SSVC

## Regulatory and Compliance Context

### CISA Binding Operational Directive 22-01
- **Title**: Reducing the Significant Risk of Known Exploited Vulnerabilities
- **URL**: https://www.cisa.gov/binding-operational-directive-22-01
- **Relevance**: Mandates federal agencies to remediate KEV-listed vulnerabilities within specified timeframes; SSVC aligns remediation priorities with BOD 22-01 requirements

### NIST SP 800-40 Rev 4
- **Title**: Guide to Enterprise Patch Management Planning
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-40/rev-4/final
- **Relevance**: Provides organizational context for patch management decisions that SSVC informs

### NIST Cybersecurity Framework (CSF) 2.0
- **Function**: IDENTIFY (ID.RA - Risk Assessment)
- **URL**: https://www.nist.gov/cyberframework
- **Relevance**: SSVC directly supports the risk assessment category for vulnerability prioritization

## Data Sources

### CISA Known Exploited Vulnerabilities (KEV) Catalog
- **URL**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **JSON Feed**: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- **Update Frequency**: Updated as new exploited vulnerabilities are confirmed

### National Vulnerability Database (NVD)
- **URL**: https://nvd.nist.gov/
- **API v2**: https://services.nvd.nist.gov/rest/json/cves/2.0
- **Relevance**: Provides CVSS scores and vulnerability details used in SSVC decision points

### MITRE CVE Program
- **URL**: https://cve.mitre.org/
- **CVE List**: https://www.cve.org/
- **Relevance**: CVE identifiers are the primary key for linking vulnerability data across SSVC decision points
