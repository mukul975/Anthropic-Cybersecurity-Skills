---
name: threat-intelligence
description: Orchestrates threat intelligence operations using OpenCTI as the central TIP. Produces actor profiles, IOC enrichment, campaign maps, and dispatches downstream skills for detection and hunting.
domain: cybersecurity
subdomain: threat-intelligence
tags: [opencti, threat-intel, ioc-enrichment, campaign-analysis, actor-profiling]
version: "1.0"
author: HRD-Security
license: Apache-2.0
---

# Threat Intelligence -- Multi-Agent Architecture

Supervisor of a decomposed threat intelligence pipeline. Classifies incoming requests, determines the correct phase sequence, launches specialized workers, and coordinates handoffs between them.

## Architecture Overview

```text
                          SUPERVISOR
                     classify | dispatch | compress
                               |
          +----------+---------+---------+----------+
          |          |         |         |          |
   actor-profiler  ioc-enricher  campaign-mapper  hunt-dispatcher  qa-agent
```

### Principles

1. **Lossy compression**: Pass structured context-packets to workers, never raw artifacts
2. **Context budget**: Supervisor uses <=45% of context; each worker uses <=45% of its own context
3. **File-based handoff**: Workers write artifacts to disk; supervisor extracts context-packets from them
4. **Self-validating workers**: Each worker runs EXECUTE-CHALLENGE-TEST-EVALUATE before handoff

## Request Classification

| Request Type               | Phase Sequence                                                    |
| -------------------------- | ----------------------------------------------------------------- |
| Actor analysis             | actor-profiler -> hunt-dispatcher -> qa-agent                     |
| IOC enrichment             | ioc-enricher -> hunt-dispatcher -> qa-agent                       |
| Campaign mapping           | campaign-mapper -> actor-profiler -> hunt-dispatcher -> qa-agent  |
| Threat article processing  | ioc-enricher -> campaign-mapper -> hunt-dispatcher -> qa-agent    |
| Full intelligence cycle    | All phases in sequence                                            |

## Worker Specifications

### actor-profiler Worker

Produces structured threat actor profiles:

- Query OpenCTI for threat actor data (aliases, motivations, capabilities)
- Map actor TTPs to MITRE ATT&CK techniques
- Identify associated malware families, tools, and infrastructure
- Assess relevance to the organization's attack surface
- Cross-reference with industry-specific threat landscape

### ioc-enricher Worker

Enriches raw indicators of compromise:

- Validate IOC format and type (IP, domain, hash, URL, email)
- Query OpenCTI for existing intelligence on each IOC
- Correlate IOCs across multiple intelligence sources
- Determine IOC confidence level and relevance
- Cross-reference against SIEM, WAF, and case management data

### campaign-mapper Worker

Maps threat campaigns to organizational risk:

- Identify campaign objectives and targeting patterns
- Map campaign TTPs to MITRE ATT&CK matrix
- Assess temporal patterns and campaign lifecycle stage
- Determine organizational exposure and relevance
- Link campaigns to threat actors and malware families

### hunt-dispatcher Worker

Dispatches downstream detection and hunting actions:

- Identify detection gaps for profiled actor TTPs
- Generate hunting hypotheses from enriched IOCs
- Create detection engineering requests for coverage gaps
- Dispatch threat hunt queries for active campaign indicators
- Track downstream action completion

### qa-agent Worker

Quality assurance for intelligence products:

- Verify TLP classification and handling markings
- Validate MITRE ATT&CK technique mappings
- Check IOC format correctness and deduplication
- Ensure actor profile completeness
- Validate campaign timeline accuracy

## Intelligence Product Templates

### Threat Actor Profile

```markdown
## Threat Actor Profile: [Actor Name]

### Overview
- **Name**: [Primary name]
- **Aliases**: [Known aliases]
- **Motivation**: [Financial / Espionage / Hacktivism / Destructive]
- **Sophistication**: [Advanced / Intermediate / Basic]
- **Active Since**: [Date]

### Targeting
- **Sectors**: [Targeted industries]
- **Geographies**: [Targeted regions]
- **Relevance to Organization**: [High/Medium/Low with rationale]

### TTPs (MITRE ATT&CK)
| Tactic | Technique ID | Technique Name | Confidence |
| ------ | ------------ | -------------- | ---------- |
| [Tac]  | T1XXX        | [Name]         | High/Med   |

### Associated Malware & Tools
- [Malware/Tool 1]: [Description]
- [Malware/Tool 2]: [Description]

### IOCs
| Type   | Value    | First Seen | Last Seen | Confidence |
| ------ | -------- | ---------- | --------- | ---------- |
| [Type] | [Value]  | [Date]     | [Date]    | [Level]    |

### Recommended Actions
1. [Detection recommendation]
2. [Hunting recommendation]
3. [Mitigation recommendation]
```

### IOC Enrichment Report

```markdown
## IOC Enrichment Report

### Summary
- **Total IOCs Processed**: X
- **High Confidence**: X
- **Medium Confidence**: X
- **Low/Unknown**: X

### Enriched IOCs
| IOC | Type | OpenCTI Match | SIEM Hits | WAF Hits | Confidence | Action |
| --- | ---- | ------------- | --------- | -------- | ---------- | ------ |
```

### Campaign Intelligence Brief

```markdown
## Campaign Intelligence Brief: [Campaign Name]

### Executive Summary
[1-2 sentence BLUF]

### Campaign Overview
- **Campaign Name**: [Name]
- **Attribution**: [Actor/Group]
- **Objective**: [Financial gain / Espionage / Disruption]
- **Active Period**: [Start] - [End/Ongoing]
- **Confidence**: [High/Medium/Low]

### Kill Chain
[Mapped to MITRE ATT&CK phases]

### Organizational Exposure
- **Relevance**: [High/Medium/Low]
- **Exposed Assets**: [Systems/data at risk]
- **Detection Coverage**: [X% of campaign TTPs detected]

### Recommended Actions
1. [Immediate action]
2. [Short-term action]
3. [Long-term action]
```

## Integration Points

- **TIP**: OpenCTI (central threat intelligence platform)
- **SIEM**: Microsoft Sentinel (log analytics and detection)
- **WAF**: Cloudflare (web application firewall telemetry)
- **SOAR**: TheHive (case management and alert correlation)
- **Ticketing**: Jira (tracking downstream actions)
