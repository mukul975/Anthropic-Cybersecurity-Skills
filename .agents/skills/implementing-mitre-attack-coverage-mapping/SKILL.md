---
name: implementing-mitre-attack-coverage-mapping
description: Implement MITRE ATT&CK coverage mapping to identify detection gaps, prioritize rule development, and measure SOC detection maturity against adversary techniques.
domain: cybersecurity
subdomain: soc-operations
tags: [mitre-attack, detection-coverage, gap-analysis, attack-navigator, soc, detection-engineering]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing MITRE ATT&CK Coverage Mapping

## Overview

MITRE ATT&CK coverage mapping gives SOC teams a structured, adversary-centric lens to evaluate detection capabilities. Enterprise SIEMs on average have detection coverage for only 21% of ATT&CK techniques (2025 CardinalOps report), with 13% of existing rules being non-functional due to misconfigured data sources. Systematic coverage mapping identifies gaps, prioritizes rule development, and tracks detection maturity over time. ATT&CK v18.1 (December 2025) is the latest version.

## Prerequisites

- Access to MITRE ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/)
- Inventory of all active SIEM detection rules
- MITRE ATT&CK technique mapping for each detection rule
- Data source inventory (which log sources are ingested)
- Understanding of adversary threat profiles relevant to your industry

## Coverage Mapping Process

### Step 1: Export Current Detection Rules

```spl
# Splunk ES - Export all active correlation searches with MITRE mappings
| rest /services/saved/searches
| search disabled=0 action.correlationsearch.enabled=1
| table title, search, action.notable.param.security_domain,
    action.notable.param.severity, action.correlationsearch.annotations
| eval mitre_techniques=mvfilter(match('action.correlationsearch.annotations', "mitre_attack"))
```

```kql
// Microsoft Sentinel - Export analytics rules with MITRE mapping
SecurityAlert
| summarize count() by AlertName, ProductName
| join kind=inner (
    resources
    | where type == "microsoft.securityinsights/alertrules"
    | extend tactics = properties.tactics
) on $left.AlertName == $right.name
```

### Step 2: Build the Coverage Matrix

#### ATT&CK Navigator Layer Format

```json
{
    "name": "SOC Detection Coverage - 2025",
    "versions": {
        "attack": "16",
        "navigator": "5.1",
        "layer": "4.5"
    },
    "domain": "enterprise-attack",
    "description": "Current detection coverage mapping",
    "techniques": [
        {
            "techniqueID": "T1110",
            "tactic": "credential-access",
            "color": "#00ff00",
            "comment": "2 active rules - Brute Force detection via EventCode 4625",
            "score": 75,
            "metadata": [
                {"name": "rule_count", "value": "2"},
                {"name": "data_sources", "value": "Windows Security Log, Linux Auth"},
                {"name": "last_validated", "value": "2025-01-15"}
            ]
        },
        {
            "techniqueID": "T1059.001",
            "tactic": "execution",
            "color": "#00ff00",
            "comment": "3 rules - PowerShell Script Block Logging",
            "score": 85
        },
        {
            "techniqueID": "T1055",
            "tactic": "defense-evasion",
            "color": "#ff0000",
            "comment": "NO DETECTION - Requires Sysmon EventCode 8/10",
            "score": 0
        }
    ],
    "gradient": {
        "colors": ["#ff0000", "#ffff00", "#00ff00"],
        "minValue": 0,
        "maxValue": 100
    }
}
```

### Step 3: Score Each Technique

| Score | Color | Meaning | Criteria |
|---|---|---|---|
| 0 | Red | No Detection | No rules, missing data sources |
| 25 | Orange | Minimal | Rule exists but not validated/tested |
| 50 | Yellow | Partial | Rule works but limited coverage |
| 75 | Light Green | Good | Validated rule with good data sources |
| 100 | Green | Excellent | Multiple validated rules, tested with emulation |

### Scoring Criteria Detail

```
Score = Data_Source_Score (0-25) + Rule_Quality_Score (0-25) +
        Validation_Score (0-25) + Enrichment_Score (0-25)

Data_Source_Score:
  25: All required data sources ingested and parsed
  15: Primary data source available
  5:  Partial data source coverage
  0:  Required data sources not available

Rule_Quality_Score:
  25: Rule uses CIM-compliant queries with proper thresholds
  15: Rule works but may generate false positives
  5:  Basic rule with no tuning
  0:  No detection rule

Validation_Score:
  25: Validated with adversary emulation (Atomic Red Team)
  15: Tested with synthetic data
  5:  Logic reviewed but not tested
  0:  Not validated

Enrichment_Score:
  25: Context-rich with asset, identity, and TI enrichment
  15: Basic enrichment (asset lookup)
  5:  No enrichment
  0:  N/A (no rule)
```

### Step 4: Identify Priority Gaps

#### Gap Prioritization Framework

```
Priority = Technique_Prevalence x Impact x Feasibility

Technique_Prevalence (0-10):
  - Based on MITRE Top Techniques report
  - Frequency in your industry's threat landscape
  - Observed in recent incidents/breaches

Impact (0-10):
  - Damage potential if technique succeeds
  - Difficulty of recovery
  - Data sensitivity at risk

Feasibility (0-10):
  - Data source availability
  - Rule complexity
  - Engineering effort required
```

#### Top Priority Techniques to Cover (2025)

| Technique | ID | Prevalence | Typical Gap Reason |
|---|---|---|---|
| Command and Scripting Interpreter | T1059 | Very High | Requires script block logging |
| Phishing | T1566 | Very High | Email gateway integration |
| Valid Accounts | T1078 | High | Baseline behavior needed |
| Process Injection | T1055 | High | Requires Sysmon or EDR |
| Lateral Movement (RDP/SMB) | T1021 | High | Network segmentation visibility |
| Scheduled Task/Job | T1053 | High | Event log collection |
| Data Encrypted for Impact | T1486 | High | File system monitoring |
| Ingress Tool Transfer | T1105 | Medium | Network traffic analysis |

### Step 5: Build Detection Roadmap

```
Quarter 1: Close Critical Gaps (Score 0, High Prevalence)
  Week 1-2: Enable missing data sources
  Week 3-4: Build and test rules for top 5 gap techniques
  Week 5-8: Validate with adversary emulation
  Week 9-12: Tune and operationalize

Quarter 2: Improve Partial Coverage (Score 25-50)
  - Upgrade existing rules with enrichment
  - Add secondary detection methods
  - Validate with purple team exercises

Quarter 3: Mature Good Coverage (Score 50-75)
  - Add behavioral analytics
  - Implement detection-as-code pipeline
  - Cross-technique correlation rules

Quarter 4: Excellence (Score 75-100)
  - Continuous testing with BAS tools
  - Automated coverage regression testing
  - Red team validation
```

## Automated Coverage Assessment

### Data Source to Technique Mapping

```python
# Map available data sources to detectable techniques
DATA_SOURCE_TECHNIQUE_MAP = {
    "Windows Security Event Log": [
        "T1110", "T1078", "T1053.005", "T1098", "T1136",
        "T1070.001", "T1021.001", "T1543.003"
    ],
    "Sysmon": [
        "T1055", "T1059", "T1003", "T1547.001", "T1036",
        "T1218", "T1105", "T1071"
    ],
    "Network Traffic (Firewall/IDS)": [
        "T1071", "T1048", "T1105", "T1572", "T1090",
        "T1571", "T1573"
    ],
    "DNS Logs": [
        "T1071.004", "T1568", "T1583.001", "T1048.003"
    ],
    "Email Gateway": [
        "T1566.001", "T1566.002", "T1534"
    ],
    "Cloud Audit Logs": [
        "T1078.004", "T1537", "T1530", "T1580",
        "T1087.004", "T1098.001"
    ],
}
```

## Reporting Dashboard Queries

### Coverage Summary by Tactic

```spl
| inputlookup mitre_coverage_lookup
| stats avg(score) as avg_score count(eval(score=0)) as no_coverage
    count(eval(score>0 AND score<50)) as partial
    count(eval(score>=50 AND score<75)) as good
    count(eval(score>=75)) as excellent
    count as total
    by tactic
| eval coverage_pct=round((total - no_coverage) / total * 100, 1)
| sort -coverage_pct
```

## References

- [CyberDefenders - MITRE ATT&CK for SOC & DFIR Analysts](https://cyberdefenders.org/blog/mitre-attack-framework/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [CardinalOps - SIEM Detection Coverage Report 2025](https://www.helpnetsecurity.com/2025/06/09/siem-detection-coverage/)
- [Datadog - Cloud SIEM MITRE ATT&CK Map](https://www.datadoghq.com/blog/cloud-siem-mitre-attack-map/)
- [Picus Security - MITRE ATT&CK Framework Guide](https://www.picussecurity.com/mitre-attack-framework)
