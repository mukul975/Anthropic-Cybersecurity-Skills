---
name: executing-diamond-model-analysis
description: >
  Applies the Diamond Model of Intrusion Analysis to structure adversary activity into its four
  core vertices (adversary, capability, infrastructure, victim) and identifies relationships between
  them to pivot investigations and attribute campaigns. Use when analyzing a completed intrusion,
  linking disparate incidents to a common threat actor, or building structured analytic products
  for threat intelligence dissemination. Activates for requests involving Diamond Model, intrusion
  analysis, campaign clustering, or adversary attribution methodology.
domain: cybersecurity
subdomain: threat-intelligence
tags: [Diamond-Model, intrusion-analysis, attribution, campaign-clustering, CTI, MITRE-ATT&CK]
version: 1.0.0
author: team-cybersecurity
license: Apache-2.0
---
# Executing Diamond Model Analysis

## When to Use

Use this skill when:
- Analyzing a confirmed intrusion to understand the complete adversary-capability-infrastructure-victim relationship
- Attempting to link two or more incidents to a common threat actor using shared infrastructure or capability indicators
- Structuring a finished intelligence product that explains adversary behavior in a formal analytic framework

**Do not use** this skill during active incident containment — Diamond Model analysis is a post-event or concurrent intelligence activity, not a response procedure.

## Prerequisites

- Completed incident investigation data: logs, forensic artifacts, malware samples, network captures
- Access to MITRE ATT&CK, VirusTotal, Shodan, and passive DNS databases for vertex enrichment
- Link analysis platform (Maltego, Analyst's Notebook, or graph database like Neo4j) for multi-event correlation
- Familiarity with the original Diamond Model paper: Caltagirone, Pendergast, Betz (2013)

## Workflow

### Step 1: Populate the Four Core Vertices

**Adversary Vertex**: Who conducted the activity?
- Operator (direct keyboard access) vs. Customer (who commissioned the attack) distinction
- Attribution confidence level (Low/Medium/High) with supporting evidence
- Known aliases, ATT&CK Group ID, sector targeting history

**Capability Vertex**: What tools and techniques were used?
- Malware families: names, YARA signatures, behavioral characteristics
- Exploits: CVEs exploited, exploit kit identifiers
- ATT&CK techniques employed (T-numbers)
- Capability sophistication: commodity (off-shelf) vs. custom-developed

**Infrastructure Vertex**: What systems were used to conduct the attack?
- C2 servers: IPs, domains, hosting providers, certificate fingerprints
- Delivery infrastructure: phishing domains, watering holes, compromised servers
- Operational relay boxes (ORBs): intermediate proxies obscuring true origin

**Victim Vertex**: Who/what was targeted?
- Organization profile: sector, size, geography, technology stack
- Personae: specific individuals targeted (CISO, finance team, executives)
- Assets targeted: intellectual property, financial systems, OT/ICS

### Step 2: Identify Vertex Relationships (Edges)

Document relationships between vertices:
- Adversary → uses → Capability (malware development/deployment relationship)
- Adversary → uses → Infrastructure (operational relationship)
- Infrastructure → delivers → Capability (technical delivery mechanism)
- Capability → targets → Victim (attack surface relationship)
- Infrastructure → attacks → Victim (direct connection)

Each edge should be supported by at least two independent data points (evidence-backed, not inferred).

### Step 3: Apply Meta-Features for Enrichment

Meta-features provide additional context beyond the four vertices:

**Timestamp**: When did each phase of the intrusion occur? Map to cyber kill chain phases.

**Phase**: Which kill chain phase does this activity represent?
- Reconnaissance → Weaponization → Delivery → Exploitation → Installation → C2 → Actions on Objectives

**Direction**: Attack direction (external-to-internal, internal-to-external for exfiltration)

**Result**: Outcome of each adversary action (success/failure/partial)

**Resources**: Adversary resources invested (time, money, infrastructure cost, zero-day usage)

### Step 4: Cluster Events Using Vertex Pivoting

Apply Diamond Model pivoting logic to cluster related incidents:
- **Infrastructure pivot**: Same C2 IP across multiple incidents → same or related adversary
- **Capability pivot**: Same malware hash or YARA signature → same tool developer
- **Adversary pivot**: Same victimology pattern (sector + geography + asset type) → same targeting criteria
- **Victim pivot**: Same victim across multiple incidents → sustained campaign against organization

```
Incident A: IP 185.220.101.x, domain evil-redir[.]com, SUNBURST malware variant
Incident B: IP 185.220.101.y (same /24), domain redir-evil[.]com, modified SUNBURST
→ Infrastructure cluster (same /24 block) + Capability cluster (same malware family) = High confidence same actor
```

### Step 5: Produce Structured Analytic Output

Document analysis in structured format:
- Diamond event diagram for each discrete intrusion event
- Activity thread connecting multiple events across time
- Activity group (cluster) with confidence assessment
- Competing hypotheses analysis: alternative attribution explanations with evidence weighting (ACH methodology)

## Key Concepts

| Term | Definition |
|------|-----------|
| **Diamond Model** | Intrusion analysis framework with four vertices (adversary, capability, infrastructure, victim) connected by edges representing relationships |
| **Activity Thread** | A time-ordered sequence of Diamond events representing a single adversary operation |
| **Activity Group** | A cluster of Diamond events linked by shared vertex properties, suggesting a common adversary |
| **Adversary Operator vs. Customer** | Diamond Model distinction: operator has keyboard access; customer directs/funds the operation |
| **Pivoting** | Using a known vertex value to discover additional related events or infrastructure (e.g., one IP revealing 20 more C2 domains) |
| **ACH** | Analysis of Competing Hypotheses — structured analytic technique for evaluating evidence against multiple attribution hypotheses |

## Tools & Systems

- **Maltego**: Graph-based link analysis ideal for visualizing Diamond vertex relationships and infrastructure pivots
- **Neo4j**: Graph database for storing and querying complex Diamond event clusters at scale; supports Cypher query language
- **MISP**: Diamond Model meta-feature tagging supported via MISP galaxies and correlation engine
- **Analyst's Notebook (IBM i2)**: Law enforcement/intelligence-grade link analysis for adversary relationship mapping

## Common Pitfalls

- **Conflating operator and customer**: Not distinguishing between who conducted the attack and who directed it leads to incorrect attribution targeting.
- **Infrastructure re-use assumption**: Bulletproof hosting providers sell the same IP blocks to multiple criminal groups. Shared IP ≠ same actor without additional corroboration.
- **Analysis without confidence levels**: Diamond Model conclusions presented without confidence qualifiers appear more certain than the evidence supports.
- **Ignoring the victim vertex**: Analysis often over-focuses on adversary/capability and neglects victim characterization, which provides crucial context for predicting future targeting.
- **Static diagrams**: Diamond events should be time-stamped and evolve as new evidence emerges. Static diagrams without version history mask analytic evolution.
