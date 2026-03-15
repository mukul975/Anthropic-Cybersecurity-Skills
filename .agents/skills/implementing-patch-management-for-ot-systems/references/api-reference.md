# API Reference: Implementing Patch Management for OT Systems

## ICS-CERT Advisory API

```bash
# Query CISA ICS advisories (RSS/JSON)
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" | jq '.vulnerabilities[] | select(.vendorProject | test("Siemens|Rockwell|Schneider"))'

# NVD API for ICS CVEs
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=SCADA&resultsPerPage=20"
```

## Vendor Patch Sources

| Vendor | Advisory Source | Notification |
|--------|----------------|-------------|
| Siemens | ProductCERT (cert.siemens.com) | RSS + Email |
| Rockwell | Knowledgebase (rockwellautomation.custhelp.com) | Email |
| Schneider | PSIRT (se.com/ww/en/work/support/cybersecurity) | RSS + Email |
| ABB | Cybersecurity Advisory (abb.com) | Email |
| Honeywell | PSIRT Advisories | Email |

## Patch Prioritization Matrix

| CVSS Score | Exploited | OT Impact | Priority | SLA |
|------------|-----------|-----------|----------|-----|
| 9.0 - 10.0 | Yes | Safety system | P1 Emergency | Next maintenance window |
| 7.0 - 8.9 | Yes | Control system | P2 Critical | 30 days |
| 7.0 - 8.9 | No | Non-safety | P3 High | 90 days |
| 4.0 - 6.9 | No | Any | P4 Medium | 180 days |
| 0.1 - 3.9 | No | Any | P5 Low | Next scheduled outage |

## NERC CIP-007-6 R2 Requirements

| Sub-Requirement | Description |
|-----------------|-------------|
| R2.1 | Patch management process for tracking |
| R2.2 | Evaluate patches within 35 days of availability |
| R2.3 | Implement applicable patches within timeframe |
| R2.4 | Document mitigation plans for patches not applied |

## IEC 62443-2-3 Patch Management Lifecycle

| Phase | Action |
|-------|--------|
| Monitor | Subscribe to vendor advisories and ICS-CERT |
| Assess | Evaluate patch compatibility with OT environment |
| Test | Validate in staging environment mirroring production |
| Plan | Schedule during maintenance window with rollback |
| Deploy | Staged rollout with process verification |
| Verify | Confirm functionality and safety post-patch |

## Compensating Controls (When Patching Not Possible)

| Control | Use Case |
|---------|----------|
| Network segmentation | Isolate unpatched systems |
| Application whitelisting | Prevent exploit execution |
| Virtual patching (IPS rules) | Block known exploit vectors |
| Enhanced monitoring | Detect exploitation attempts |
| Physical access restriction | Limit console access |

## WSUS/SCCM OT Configuration

```powershell
# WSUS: Approve patch for OT test group only
Approve-WsusUpdate -Update $update -Action Install -TargetGroupName "OT-Test-Ring"
```

### References

- IEC 62443-2-3: https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards
- NERC CIP-007-6: https://www.nerc.com/pa/Stand/Reliability%20Standards/CIP-007-6.pdf
- CISA ICS Advisories: https://www.cisa.gov/news-events/ics-advisories
- NVD API: https://nvd.nist.gov/developers/vulnerabilities
