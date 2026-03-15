---
name: managing-intelligence-lifecycle
description: >
  Manages the end-to-end cyber threat intelligence lifecycle from planning and direction through
  collection, processing, analysis, dissemination, and feedback to ensure intelligence products
  meet stakeholder requirements and continuously improve. Use when establishing or maturing a CTI
  program, defining intelligence requirements with business stakeholders, or building feedback loops
  between intelligence consumers and producers. Activates for requests involving CTI program
  maturity, intelligence requirements, PIRs, or intelligence lifecycle management.
domain: cybersecurity
subdomain: threat-intelligence
tags: [CTI, intelligence-lifecycle, PIR, NIST-SP-800-150, threat-intelligence-program, NIST-CSF]
version: 1.0.0
author: team-cybersecurity
license: Apache-2.0
---
# Managing Intelligence Lifecycle

## When to Use

Use this skill when:
- Establishing a formal CTI program and defining its operational model
- Conducting quarterly intelligence requirements reviews with business stakeholders
- Evaluating CTI program maturity against established frameworks (FIRST CTI-SIG maturity model)

**Do not use** this skill for day-to-day IOC triage or incident-specific intelligence tasks — those use operational intelligence workflows, not lifecycle management.

## Prerequisites

- Executive sponsorship and defined CTI team structure (1+ dedicated analysts)
- Stakeholder map identifying intelligence consumers (SOC, IR, executive team, vulnerability management)
- Existing feed subscriptions or ISAC memberships for collection baseline
- CTI platform (MISP, ThreatConnect, OpenCTI) for lifecycle management

## Workflow

### Step 1: Planning and Direction

Define Priority Intelligence Requirements (PIRs) with stakeholders:
- Interview SOC leads, IR team, CISO, risk management, and product security
- Document PIRs in structured format: "What is the current capability and intent of [threat actor] to attack [critical asset] using [technique]?"
- Prioritize 5–10 PIRs for the quarter, reviewed monthly

Example PIR: "Is ransomware group Cl0p currently targeting organizations in our sector using MoveIT or GoAnywhere vulnerabilities?"

### Step 2: Collection Planning

Map PIRs to required collection sources:
- Technical sources: commercial feeds, TAXII, ISAC data, honeypot telemetry, darkweb monitoring
- Human sources: vendor threat briefings, industry working groups, law enforcement partnerships
- Internal sources: SIEM logs, EDR telemetry, phishing submission mailbox

Document collection gaps and associated costs to fill them.

### Step 3: Processing and Normalization

Implement automated processing pipeline:
- Ingest → normalize to STIX 2.1 → deduplicate → enrich → score confidence
- Reject unverifiable or duplicate indicators before analysis
- Tag all processed data with source, collection date, and expiration

### Step 4: Analysis and Production

Produce intelligence at three levels:
- **Strategic**: Quarterly threat landscape report for executives; sector trends, geopolitical context
- **Operational**: Weekly campaign reports for security leadership; active campaigns, adversary activity
- **Tactical**: Daily IOC bulletins for SOC; actionable indicators with block/monitor recommendations

Apply structured analytic techniques: Analysis of Competing Hypotheses (ACH), Key Assumptions Check, Devil's Advocacy.

### Step 5: Dissemination

Match product format to audience:
- Executives: 1-page PDF with risk ratings, business impact, recommended decisions
- SOC analysts: SIEM-ready IOC list, Sigma rules, MISP events
- Vulnerability management: CVE lists with EPSS scores and exploitation likelihood
- IT/Security leadership: Full intelligence report with technical appendix

Apply TLP classifications and distribution lists per product type.

### Step 6: Feedback and Evaluation

Collect feedback within 5 business days of dissemination:
- Did the product address the PIR?
- Was actionability sufficient?
- What data was missing?

Track metrics quarterly: PIR coverage rate, IOC true positive rate, time-to-disseminate, stakeholder satisfaction score (NPS or structured survey).

## Key Concepts

| Term | Definition |
|------|-----------|
| **PIR** | Priority Intelligence Requirement — specific, actionable question driving intelligence collection and analysis |
| **Intelligence Lifecycle** | Six-phase iterative process: Planning → Collection → Processing → Analysis → Dissemination → Feedback |
| **Strategic Intelligence** | Long-term threat trend analysis for executive decision-making; time horizon 6–24 months |
| **Operational Intelligence** | Campaign-level analysis for security program decisions; time horizon 1–6 months |
| **Tactical Intelligence** | Specific IOCs and TTPs for immediate detection and blocking; time horizon hours to days |
| **FIRST CTI-SIG** | Forum of Incident Response and Security Teams — CTI Special Interest Group maturity model |

## Tools & Systems

- **ThreatConnect**: TIP with built-in intelligence lifecycle workflows, PIR tracking, and stakeholder reporting dashboards
- **MISP**: Open-source TIP supporting intelligence lifecycle from collection through sharing
- **OpenCTI**: Graph-based CTI platform with workflow management for intelligence products
- **Recorded Future**: Commercial platform with structured intelligence reports aligned to the intelligence lifecycle

## Common Pitfalls

- **Collection without direction**: Ingesting every available feed without PIRs produces data overload and no actionable intelligence.
- **Missing feedback loops**: Without structured feedback, CTI teams produce reports that don't meet stakeholder needs and lose organizational relevance.
- **Tactical-only focus**: Overemphasis on IOC sharing neglects strategic intelligence that informs security investment and risk decisions.
- **No metrics program**: Cannot demonstrate CTI program value without tracking detection contributions, true positive rates, and stakeholder satisfaction.
- **Underfunded collection**: PIRs cannot be answered without appropriate collection sources; document and escalate gaps rather than producing low-confidence estimates.
