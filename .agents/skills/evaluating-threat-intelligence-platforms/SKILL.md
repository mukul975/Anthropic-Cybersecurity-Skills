---
name: evaluating-threat-intelligence-platforms
description: >
  Evaluates and selects Threat Intelligence Platform (TIP) products based on organizational
  requirements including feed integration capability, STIX/TAXII support, workflow automation,
  analyst interface, and total cost of ownership. Use when conducting a TIP procurement, migrating
  between TIP solutions, or assessing whether the current TIP meets program maturity requirements.
  Activates for requests involving ThreatConnect, MISP, OpenCTI, Anomali, EclecticIQ, or TIP
  procurement decisions.
domain: cybersecurity
subdomain: threat-intelligence
tags: [TIP, ThreatConnect, MISP, OpenCTI, Anomali, EclecticIQ, STIX-TAXII, CTI-program, procurement]
version: 1.0.0
author: team-cybersecurity
license: Apache-2.0
---
# Evaluating Threat Intelligence Platforms

## When to Use

Use this skill when:
- Conducting a formal RFP or vendor evaluation for a TIP solution
- Assessing whether the current TIP (e.g., MISP) needs to be replaced or augmented as the CTI program scales
- Establishing evaluation criteria aligned to organizational maturity and budget

**Do not use** this skill for evaluating feed quality independently of the TIP — feed evaluation is a separate workflow focused on data quality rather than platform capabilities.

## Prerequisites

- Documented CTI program requirements: team size, feed sources, integration targets, use cases
- Budget range and procurement timeline
- Technical staff who will administer the platform (Python/API experience for open-source TIPs)
- List of current and planned integrations (SIEM, SOAR, EDR, firewalls)

## Workflow

### Step 1: Define Evaluation Criteria

Structure requirements into mandatory (M) and desired (D) categories:

**Core TIP Functions**:
- M: STIX 2.1 import/export with TAXII 2.1 server
- M: REST API for automated IOC ingestion and export
- M: Indicator deduplication and TTL management
- M: TLP classification enforcement
- D: Built-in MITRE ATT&CK integration and technique tagging
- D: Graph visualization of indicator relationships
- D: Workflow automation for analyst triage

**Integrations**:
- M: SIEM integration (Splunk, Sentinel, QRadar) via syslog, API, or native connector
- M: EDR integration for IOC push (CrowdStrike, Defender, SentinelOne)
- D: SOAR integration (XSOAR, Splunk SOAR) for playbook triggers
- D: Ticketing system (ServiceNow, Jira) for intelligence task tracking

**Operational**:
- M: Role-based access control with TLP-aware data segregation
- M: Audit logging for all analyst actions
- D: Multi-tenancy for MSSP use cases

### Step 2: Evaluate Major TIP Options

**MISP (Open Source)**:
- Cost: Free (self-hosted infrastructure cost only)
- Strengths: Largest community, 250+ modules, extensive ISAC usage, STIX 2.0 native
- Weaknesses: Requires dedicated admin, limited visualization, UI dated
- Best for: Budget-constrained teams with technical staff; government/ISAC sharing programs

**OpenCTI (Open Source)**:
- Cost: Free (self-hosted); paid SaaS at ~$3,000–$15,000/year
- Strengths: Native STIX 2.1, graph visualization, ATT&CK integration, modern API
- Weaknesses: Resource-intensive deployment (Elasticsearch, MinIO required)
- Best for: Teams wanting open source with modern UX; SOC/CTI integration focus

**ThreatConnect (Commercial)**:
- Cost: $50,000–$500,000/year depending on scale
- Strengths: End-to-end CTI lifecycle, playbook automation, TC Exchange marketplace, analyst workflow
- Weaknesses: High cost; complex implementation; best value at larger scale
- Best for: Mature enterprise CTI programs; MSSPs; red team/blue team integration

**Anomali ThreatStream (Commercial)**:
- Cost: $30,000–$200,000/year
- Strengths: Strong feed aggregation, Splunk-native integration, extensive pre-built connectors
- Weaknesses: Graph visualization weaker than OpenCTI; UI refresh lagging
- Best for: Splunk-heavy environments; teams prioritizing feed volume over analysis workflows

**EclecticIQ Platform (Commercial)**:
- Cost: $40,000–$300,000/year
- Strengths: STIX 2.1 native, collaborative intelligence workbench, strong European customer base
- Weaknesses: Smaller partner ecosystem than ThreatConnect
- Best for: Teams with MITRE ATT&CK-centric workflows; EMEA-focused organizations

### Step 3: Conduct Proof of Concept

Request 30-day PoC from finalists. Test:
1. Feed onboarding: Can your top 5 feeds be ingested within 4 hours?
2. SIEM integration: Can enriched IOCs push to your SIEM in <5 minutes?
3. ATT&CK mapping: Can analysts tag indicators with ATT&CK techniques efficiently?
4. Report generation: Can the platform produce a tactical IOC bulletin with one click?
5. API performance: Can the REST API handle 10,000 indicator queries per day?

### Step 4: Score and Select

Use weighted scoring matrix (weight each criterion by organizational priority):
```
Criterion                 Weight   Vendor A   Vendor B
STIX 2.1 compliance       20%      95         85
SIEM integration          25%      90         70
ATT&CK mapping            15%      85         95
Cost (inverse)            20%      60         90
UI/analyst experience     10%      80         75
Vendor support quality    10%      85         80
TOTAL                     100%     82.0       81.5
```

### Step 5: Implementation and Onboarding Planning

Plan 90-day implementation:
- Week 1–2: Infrastructure deployment (cloud or on-prem)
- Week 3–4: Feed onboarding and deduplication tuning
- Week 5–6: SIEM/SOAR integration and testing
- Week 7–8: Analyst workflow configuration and training
- Week 9–12: Operational validation and go-live

## Key Concepts

| Term | Definition |
|------|-----------|
| **TIP** | Threat Intelligence Platform — software for collecting, processing, analyzing, and disseminating cyber threat intelligence |
| **TAXII Server** | Component of a TIP that serves STIX bundles to consuming systems on request |
| **TC Exchange** | ThreatConnect's commercial marketplace for pre-built feed integrations and app connectors |
| **Multi-tenancy** | TIP capability to serve multiple organizational units or customers with isolated data environments |
| **Deduplication** | Process of identifying and merging duplicate indicators within a TIP to reduce analyst noise |

## Tools & Systems

- **MISP**: Open-source TIP used by 6,000+ organizations; strongest ISAC/government community integration
- **OpenCTI**: Modern open-source TIP with native STIX 2.1 and graph-based analysis
- **ThreatConnect**: Enterprise commercial TIP with lifecycle management and SOAR playbook integration
- **Anomali ThreatStream**: Commercial TIP with strong Splunk ecosystem integration
- **EclecticIQ**: Commercial TIP with ATT&CK-centric workflow design

## Common Pitfalls

- **Selecting TIP before defining requirements**: Technology selection before use case definition leads to expensive mismatches.
- **Underestimating administration burden**: MISP and OpenCTI require dedicated admin time (minimum 0.25 FTE); budget accordingly.
- **Ignoring data migration costs**: Moving historical intelligence from one TIP to another is costly and often impractical for legacy systems.
- **Not testing SIEM integration in PoC**: TIP value depends heavily on downstream integration quality; always test SIEM/SOAR connectivity during evaluation.
