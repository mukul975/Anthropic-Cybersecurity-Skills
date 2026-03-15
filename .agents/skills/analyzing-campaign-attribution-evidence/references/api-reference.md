# API Reference: Campaign Attribution Evidence Analysis

## Diamond Model of Intrusion Analysis

### Four Core Features
| Feature | Description | Attribution Value |
|---------|-------------|-------------------|
| Adversary | Threat actor identity | Direct attribution |
| Capability | Malware, exploits, tools | Indirect - shared tooling |
| Infrastructure | C2, domains, IPs | Strong - operational overlap |
| Victim | Targets, sectors, regions | Contextual - targeting pattern |

### Pivot Analysis
```
Adversary ←→ Capability ←→ Infrastructure ←→ Victim
    ↕              ↕              ↕              ↕
  (HUMINT)     (Malware DB)   (WHOIS/DNS)   (Victimology)
```

## Analysis of Competing Hypotheses (ACH)

### Matrix Format
```
Evidence \ Hypothesis  |  APT28  |  APT29  |  Lazarus  |  Unknown
-----------------------------------------------------------------
Infrastructure overlap  |   ++    |    -    |     -     |    N
TTP consistency        |   ++    |   ++    |     -     |    N
Malware similarity     |    +    |    -    |     -     |    N
Timing (UTC+3)         |   ++    |   ++    |     -     |    N
Language (Russian)     |   ++    |   ++    |     -     |    N
```

### Scoring
| Symbol | Meaning | Weight |
|--------|---------|--------|
| `++` | Strongly consistent | +2 |
| `+` | Consistent | +1 |
| `N` | Neutral | 0 |
| `-` | Inconsistent | -1 |
| `--` | Strongly inconsistent | -2 |

## MITRE ATT&CK Group Queries

### Python (mitreattack-python)
```python
from mitreattack.stix20 import MitreAttackData
attack = MitreAttackData("enterprise-attack.json")
group = attack.get_group_by_alias("APT29")
techniques = attack.get_techniques_used_by_group(group.id)
```

### STIX2 Relationship Query
```python
from stix2 import Filter
relationships = src.query([
    Filter("type", "=", "relationship"),
    Filter("source_ref", "=", group_id),
    Filter("relationship_type", "=", "uses"),
])
```

## Infrastructure Overlap Tools

### PassiveTotal / RiskIQ
```bash
# WHOIS history
curl -u user:key "https://api.passivetotal.org/v2/whois?query=domain.com"

# Passive DNS
curl -u user:key "https://api.passivetotal.org/v2/dns/passive?query=1.2.3.4"
```

### VirusTotal Relations
```bash
curl -H "x-apikey: KEY" \
  "https://www.virustotal.com/api/v3/domains/example.com/communicating_files"
```

## Confidence Assessment Framework

| Level | Score Range | Criteria |
|-------|------------|---------|
| HIGH | 0.8-1.0 | Multiple independent evidence types converge |
| MEDIUM | 0.5-0.8 | Significant evidence with some gaps |
| LOW | 0.2-0.5 | Limited evidence, alternative hypotheses remain |
| NEGLIGIBLE | 0.0-0.2 | Insufficient evidence for attribution |

## STIX Attribution Objects

### Campaign Object
```json
{
  "type": "campaign",
  "name": "Operation DarkShadow",
  "first_seen": "2024-01-15T00:00:00Z",
  "last_seen": "2024-03-20T00:00:00Z",
  "objective": "Espionage targeting defense sector"
}
```

### Attribution Relationship
```json
{
  "type": "relationship",
  "relationship_type": "attributed-to",
  "source_ref": "campaign--abc123",
  "target_ref": "intrusion-set--def456",
  "confidence": 75
}
```
