# Threat Actor TTP Analysis Report Template

## Report Metadata
| Field | Value |
|-------|-------|
| Report ID | TTP-YYYY-NNNN |
| Date | YYYY-MM-DD |
| Threat Actor | [Group Name] |
| ATT&CK ID | G[NNNN] |
| Classification | TLP:AMBER |
| Analyst | [Name] |

## Threat Actor Profile

| Attribute | Detail |
|-----------|--------|
| Name | |
| Aliases | |
| Suspected Origin | |
| Motivation | Espionage / Financial / Disruption |
| Active Since | |
| Targeted Sectors | |
| Targeted Regions | |
| Associated Malware | |

## TTP Summary

| Tactic | Technique Count | Key Techniques |
|--------|----------------|----------------|
| Reconnaissance | | |
| Resource Development | | |
| Initial Access | | |
| Execution | | |
| Persistence | | |
| Privilege Escalation | | |
| Defense Evasion | | |
| Credential Access | | |
| Discovery | | |
| Lateral Movement | | |
| Collection | | |
| Command and Control | | |
| Exfiltration | | |
| Impact | | |

## Detailed Technique Mapping

### [Tactic Name]

| ATT&CK ID | Technique | Sub-technique | Procedure Example |
|-----------|-----------|---------------|-------------------|
| T1566.001 | Phishing | Spearphishing Attachment | Actor sends macro-enabled documents |
| | | | |

## Detection Coverage

| Status | Count | Percentage |
|--------|-------|-----------|
| Detected | | % |
| Partial Detection | | % |
| No Detection (Gap) | | % |

## Detection Gaps (Priority Order)

| Priority | ATT&CK ID | Technique | Required Data Source | Effort |
|----------|-----------|-----------|---------------------|--------|
| 1 | | | | Low/Med/High |
| 2 | | | | |

## Recommended Data Sources

| Data Source | Techniques Covered | Current Status |
|------------|-------------------|----------------|
| Process Creation | X techniques | Collecting/Not Collecting |
| Network Traffic Flow | X techniques | |
| File Monitoring | X techniques | |

## ATT&CK Navigator Layer

Layer file: `[group]_navigator_layer.json`

Load at: https://mitre-attack.github.io/attack-navigator/

## Recommendations

1. **Immediate**: Deploy detections for [top 3 gap techniques]
2. **Short-term**: Enable [data source] collection to cover N techniques
3. **Long-term**: Build behavioral analytics for [tactic] coverage
