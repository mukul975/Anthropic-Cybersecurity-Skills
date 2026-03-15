# API Reference: Patch Tuesday Response Process

## MSRC Security Update API
```
GET https://api.msrc.microsoft.com/cvrf/v3.0/Updates('{yyyy-Mon}')
api-key: YOUR_MSRC_KEY
Accept: application/json
```

## CVRF Vulnerability Fields
| Field | Description |
|-------|-------------|
| `CVE` | CVE identifier |
| `Title.Value` | Vulnerability title |
| `Threats[].Description.Value` | Severity, exploitation status |
| `CVSSScoreSets[].BaseScore` | CVSS v3 base score |
| `ProductStatuses[].ProductID` | Affected product IDs |
| `Remediations[].URL` | KB article / patch URL |

## CISA Known Exploited Vulnerabilities (KEV)
```
GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

### KEV Entry Fields
| Field | Description |
|-------|-------------|
| `cveID` | CVE identifier |
| `vendorProject` | Vendor name |
| `product` | Product name |
| `dateAdded` | Date added to KEV |
| `dueDate` | Remediation due date |

## Patch Priority Matrix
| Priority | Criteria | SLA |
|----------|----------|-----|
| Emergency | Exploited + KEV + CVSS >= 9.0 | 24 hours |
| Critical | Exploited OR KEV + CVSS >= 7.0 | 72 hours |
| Standard | CVSS >= 7.0, no exploitation | 7 days |
| Routine | CVSS < 7.0, no exploitation | 30 days |

## NVD API v2
```
GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE-ID}
apiKey: YOUR_NVD_KEY
```

## WSUS Deployment API (PowerShell)
```powershell
$wsus = Get-WsusServer
$update = $wsus.SearchUpdates("KB5034441")
$group = $wsus.GetComputerTargetGroup("Production")
$update.Approve("Install", $group)
```

## Deployment Phase Timeline
| Phase | Window | Targets |
|-------|--------|---------|
| Emergency | 0-24h | Critical servers, exploited CVEs |
| Pilot | 24-72h | Test group (5% of fleet) |
| Broad | 3-7d | All production systems |
| Cleanup | 7-30d | Exceptions, rollback monitoring |
