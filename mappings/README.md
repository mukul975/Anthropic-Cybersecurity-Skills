# MITRE ATT&CK Navigator Layer - Anthropic Cybersecurity Skills

This directory contains a MITRE ATT&CK Navigator layer file that maps the coverage of the Anthropic Cybersecurity Skills repository against the ATT&CK Enterprise matrix.

## Files

| File | Description |
|------|-------------|
| `attack-navigator-layer.json` | ATT&CK Navigator layer (v4.5 format, Enterprise ATT&CK v19.1) |

## How to View

1. Open the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
2. Click **Open Existing Layer**
3. Select **Upload from local** and choose `attack-navigator-layer.json`
4. The matrix will display with blue-shaded techniques indicating coverage

Alternatively, paste the raw JSON URL into the Navigator's "Load from URL" option if this file is hosted publicly.

## Coverage Statistics

| Metric | Value |
|--------|-------|
| Total skills scanned | 754 |
| Unique ATT&CK techniques referenced | 361 |
| Parent techniques | 174 |
| Sub-techniques | 187 |
| Tactics with coverage | 16/16 |

## Coverage by Tactic

| Tactic | Techniques Covered |
|--------|-------------------|
| Defense Evasion | 36 |
| Credential Access | 33 |
| Persistence | 29 |
| Initial Access | 17 |
| Command and Control | 17 |
| Privilege Escalation | 13 |
| Discovery | 12 |
| Exfiltration | 12 |
| Reconnaissance | 11 |
| Collection | 10 |
| Lateral Movement | 9 |
| Execution | 8 |
| Resource Development | 6 |
| Impact | 5 |
| Defense Impairment | 4 |
| Stealth | 4 |

## Color Scale

The layer uses a blue gradient to indicate coverage depth:

- **Light blue** (`#cfe2f3`): 1-2 skills reference this technique
- **Medium blue** (`#6fa8dc`): 3-5 skills reference this technique
- **Dark blue** (`#3d85c6`): 6-10 skills reference this technique
- **Deep blue** (`#1155cc`): 11+ skills reference this technique

## Top 10 Most Covered Techniques

| Technique | Name | Skills |
|-----------|------|--------|
| T1059.001 | PowerShell | 26 |
| T1055 | Process Injection | 17 |
| T1053.005 | Scheduled Task | 16 |
| T1566.001 | Spearphishing Attachment | 15 |
| T1558.003 | Kerberoasting | 14 |
| T1547.001 | Registry Run Keys / Startup Folder | 13 |
| T1078 | Valid Accounts | 13 |
| T1003.006 | DCSync | 13 |
| T1071.001 | Web Protocols | 12 |
| T1021.002 | SMB/Windows Admin Shares | 12 |

## Methodology

Techniques were extracted by scanning all `SKILL.md` files in the repository for ATT&CK technique ID patterns (`T1XXX` and `T1XXX.XXX`). Each technique's score is proportional to the number of distinct skills that reference it, normalized to a 1-100 scale.

## Layer Format

- **Format version**: 4.5
- **ATT&CK version**: 19.1 (Enterprise)
- **Navigator version**: 4.9.1
- **Domain**: enterprise-attack

## Related Links

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [ATT&CK Navigator GitHub](https://github.com/mitre-attack/attack-navigator)
