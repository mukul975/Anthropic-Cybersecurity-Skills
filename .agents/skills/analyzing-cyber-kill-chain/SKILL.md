---
name: analyzing-cyber-kill-chain
description: >
  Analyzes intrusion activity against the Lockheed Martin Cyber Kill Chain framework to identify
  which phases an adversary has completed, where defenses succeeded or failed, and what controls
  would have interrupted the attack at earlier phases. Use when conducting post-incident analysis,
  building prevention-focused security controls, or mapping detection gaps to kill chain phases.
  Activates for requests involving kill chain analysis, intrusion kill chain, attack phase mapping,
  or Lockheed Martin kill chain framework.
domain: cybersecurity
subdomain: threat-intelligence
tags: [kill-chain, Lockheed-Martin, MITRE-ATT&CK, intrusion-analysis, defense-in-depth, NIST-CSF]
version: 1.0.0
author: team-cybersecurity
license: Apache-2.0
---
# Analyzing Cyber Kill Chain

## When to Use

Use this skill when:
- Conducting post-incident analysis to determine how far an adversary progressed through an attack sequence
- Designing layered defensive controls with the goal of interrupting attacks at the earliest possible phase
- Producing threat intelligence reports that communicate attack progression to non-technical stakeholders

**Do not use** this skill as a standalone framework — combine with MITRE ATT&CK for technique-level granularity beyond what the 7-phase kill chain provides.

## Prerequisites

- Complete incident timeline with forensic artifacts mapped to specific adversary actions
- MITRE ATT&CK Enterprise matrix for technique-level mapping within each kill chain phase
- Access to threat intelligence on the suspected adversary group's typical kill chain progression
- Post-incident report or IR timeline from responding team

## Workflow

### Step 1: Map Observed Actions to Kill Chain Phases

The Lockheed Martin Cyber Kill Chain consists of seven phases. Map all observed adversary actions:

**Phase 1 - Reconnaissance**: Adversary gathers target information before attack.
- Indicators: DNS queries from adversary IP, LinkedIn scraping, job posting analysis, Shodan scans of organization infrastructure

**Phase 2 - Weaponization**: Adversary creates attack tool (malware + exploit).
- Indicators: Malware compilation timestamps, exploit document metadata, builder artifacts in malware samples

**Phase 3 - Delivery**: Adversary transmits weapon to target.
- Indicators: Phishing emails, malicious attachments, drive-by downloads, USB drops, supply chain compromise

**Phase 4 - Exploitation**: Adversary exploits vulnerability to execute code.
- Indicators: CVE exploitation events in application/OS logs, memory corruption artifacts, shellcode execution

**Phase 5 - Installation**: Adversary establishes persistence on target.
- Indicators: New scheduled tasks, registry run keys, service installation, web shells, bootkits

**Phase 6 - Command & Control (C2)**: Adversary communicates with compromised system.
- Indicators: Beaconing traffic (regular intervals), DNS tunneling, HTTPS to uncommon domains, C2 framework signatures (Cobalt Strike, Sliver)

**Phase 7 - Actions on Objectives**: Adversary achieves goals.
- Indicators: Data staging/exfiltration, lateral movement, ransomware execution, destructive activity

### Step 2: Identify Phase Completion and Detection Points

Create a phase matrix for the incident:
```
Phase 1: Recon        → Completed (undetected)
Phase 2: Weaponize    → Completed (undetected — pre-attack)
Phase 3: Delivery     → Completed; phishing email bypassed SEG
Phase 4: Exploit      → Completed; CVE-2023-23397 exploited
Phase 5: Install      → DETECTED: EDR flagged scheduled task creation (attack stalled here)
Phase 6: C2           → Not achieved (installation blocked)
Phase 7: Objectives   → Not achieved
```

For each phase completed without detection, document the defensive control gap.

### Step 3: Map to MITRE ATT&CK for Technique Detail

Each kill chain phase maps to multiple ATT&CK tactics:
- Delivery → Initial Access (TA0001)
- Exploitation → Execution (TA0002)
- Installation → Persistence (TA0003), Privilege Escalation (TA0004)
- C2 → Command and Control (TA0011)
- Actions on Objectives → Exfiltration (TA0010), Impact (TA0040)

Within each phase, enumerate specific ATT&CK techniques observed and map to existing detections.

### Step 4: Identify Courses of Action per Phase

For each phase, document applicable defensive courses of action (COAs):
- **Detect COA**: What detection would alert on adversary activity in this phase?
- **Deny COA**: What control would prevent the adversary from completing this phase?
- **Disrupt COA**: What control would interrupt the adversary mid-phase?
- **Degrade COA**: What control would reduce the adversary's effectiveness in this phase?
- **Deceive COA**: What deception (honeypots, canary tokens) would expose activity in this phase?
- **Destroy COA**: What active defense capability would neutralize adversary infrastructure?

### Step 5: Produce Kill Chain Analysis Report

Structure findings as:
1. Attack narrative (timeline of phases)
2. Phase-by-phase analysis with evidence
3. Detection point analysis (what worked, what failed)
4. Defensive recommendation per phase prioritized by cost/effectiveness
5. Control improvement roadmap

## Key Concepts

| Term | Definition |
|------|-----------|
| **Kill Chain** | Sequential model of adversary intrusion phases; breaking any link theoretically stops the attack |
| **Courses of Action (COA)** | Defensive responses mapped to each kill chain phase: detect, deny, disrupt, degrade, deceive, destroy |
| **Beaconing** | Regular, periodic C2 check-in pattern from compromised host to adversary server; detectable by frequency analysis |
| **Phase Completion** | Adversary successfully finishes a kill chain phase and progresses to the next; defense-in-depth aims to prevent this |
| **Intelligence Gain/Loss** | Analysis of whether detecting at Phase 5 (vs. Phase 3) reduced intelligence about adversary capabilities or intent |

## Tools & Systems

- **MITRE ATT&CK Navigator**: Overlay kill chain phases with ATT&CK technique coverage for integrated analysis
- **Elastic Security EQL**: Event Query Language for querying multi-phase attack sequences in Elastic SIEM
- **Splunk ES**: Timeline visualization and correlation searches for kill chain phase sequencing
- **MISP**: Kill chain tagging via galaxy clusters for structured incident event documentation

## Common Pitfalls

- **Linear assumption**: Adversaries don't always progress linearly — they may skip phases (weaponization already complete from previous campaign) or loop back (re-establish C2 after detection).
- **Ignoring Phases 1 and 2**: Reconnaissance and weaponization occur before the defender has visibility. Intelligence about these phases requires external sources (OSINT, threat intelligence).
- **Missing insider threats**: The kill chain was designed for external adversaries. Insider threats may skip directly to Phase 7 without traversing earlier phases.
- **Confusing with ATT&CK tactics**: The 7-phase kill chain and 14 ATT&CK tactics are complementary but not directly equivalent. Maintain distinction to prevent analytic confusion.
