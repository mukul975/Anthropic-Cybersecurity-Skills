---
name: performing-ransomware-tabletop-exercise
description: >
  Plans and facilitates tabletop exercises simulating ransomware incidents to test
  organizational readiness, decision-making, and communication procedures. Designs
  realistic scenarios based on current ransomware threat actors (LockBit, ALPHV/BlackCat,
  Cl0p), injects covering double extortion, backup destruction, and regulatory notification
  requirements. Evaluates participant responses against NIST CSF and CISA guidelines.
  Activates for requests involving ransomware tabletop, incident response exercise, or
  ransomware readiness drill.
domain: cybersecurity
subdomain: ransomware-defense
tags: [ransomware, incident-response, tabletop-exercise, defense, preparedness]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Performing Ransomware Tabletop Exercise

## When to Use

- Testing organizational ransomware response procedures annually or after major infrastructure changes
- Validating decision-making processes for ransom payment, regulatory notification, and public disclosure
- Training executives, IT, legal, PR, and operations teams on their roles during a ransomware incident
- Meeting cyber insurance policy requirements for documented incident response testing
- Identifying gaps in recovery playbooks, communication plans, and backup procedures

**Do not use** as a substitute for technical controls testing. Tabletop exercises validate procedures and decision-making, not technical detection or prevention capabilities.

## Prerequisites

- Documented incident response plan (IRP) that participants should have read before the exercise
- Identified exercise participants from: executive leadership, IT/security, legal, communications/PR, HR, operations, and external counsel
- Facilitator who is independent from the IR team (to provide objective evaluation)
- Ransomware scenario designed with injects that escalate over multiple rounds
- Evaluation criteria aligned to NIST CSF Respond/Recover functions
- Conference room or virtual meeting for 2-4 hours with no interruptions

## Workflow

### Step 1: Design the Exercise Scenario

Build a realistic scenario based on current threat actor TTPs:

**Scenario Structure:**
```
Phase 1: Initial Detection (30 min)
  - SOC receives alert for suspicious process execution on file server
  - EDR detects Cobalt Strike beacon on 3 workstations
  - Inject: External threat intel report links C2 IP to LockBit affiliate

Phase 2: Escalation (30 min)
  - Ransomware executes on 40% of servers during overnight hours
  - Ransom note demands $2M in Bitcoin with 72-hour deadline
  - Inject: Attackers contact media claiming data theft of customer PII

Phase 3: Decision Points (45 min)
  - Backup assessment reveals immutable copies are intact but primary backups encrypted
  - Legal advises on breach notification timeline (72 hours GDPR, varies by US state)
  - Inject: Threat actor publishes sample of stolen data on leak site

Phase 4: Recovery and Communication (45 min)
  - Recovery time estimate: 5-7 days from immutable backups
  - Insurance carrier engages negotiation firm
  - Inject: Major customer threatens contract termination without update within 24 hours
```

**Scenario Variables to Customize:**
- Threat actor group and known TTPs
- Percentage of infrastructure encrypted
- Whether backups are intact, partially compromised, or fully destroyed
- Type of data exfiltrated (PII, PHI, financial, trade secrets)
- Applicable regulatory frameworks (GDPR, HIPAA, PCI DSS, SEC rules)
- Ransom amount and payment deadline

### Step 2: Prepare Exercise Materials

Create the following documents for participants:

1. **Exercise Overview Briefing** - Ground rules, objectives, scope, and participants
2. **Situation Reports (SITREPs)** - One per phase, distributed as the exercise progresses
3. **Inject Cards** - New information introduced at specific times to force decision-making
4. **Decision Point Worksheets** - Structured forms for documenting group decisions
5. **Evaluation Scorecard** - Criteria for assessing response quality

**Key Decision Points to Include:**
- When to activate the incident response team
- Whether to shut down systems or contain selectively
- Whether to engage law enforcement (FBI IC3, CISA)
- Whether to pay the ransom and under what conditions
- When and how to notify regulators, customers, and the public
- How to prioritize system recovery order

### Step 3: Facilitate the Exercise

**Facilitator Responsibilities:**
- Present each phase scenario and distribute SITREPs
- Introduce injects at predetermined times to increase pressure
- Ask probing questions to test decision-making reasoning
- Ensure all participant groups contribute (prevent IT from dominating)
- Document all decisions, rationales, and action items
- Track time management (many teams lose time on early phases)

**Probing Questions by Phase:**

Phase 1 - Detection:
- Who makes the call to declare an incident? What criteria trigger it?
- How do we determine the scope of compromise from initial alerts?
- Do we have the forensic capability to investigate or do we need external help?

Phase 2 - Escalation:
- What is our communication plan for employees? Do they know not to turn on affected machines?
- Have we isolated the network to prevent further encryption?
- Who authorizes system shutdowns that impact business operations?

Phase 3 - Decision:
- Under what conditions would we consider paying the ransom?
- What are the legal obligations for notification at this point?
- How do we handle the public leak of customer data?

Phase 4 - Recovery:
- What is the recovery priority order? Is it documented or decided ad hoc?
- How long until critical business operations resume?
- What evidence preservation is required for law enforcement and insurance?

### Step 4: Evaluate and Score Responses

Score each functional area against defined criteria:

| Evaluation Area | Score (1-5) | Criteria |
|----------------|-------------|----------|
| Detection & Escalation | | Timely incident declaration, proper chain of command |
| Containment | | Network isolation, credential reset, scope assessment |
| Communication - Internal | | Employee notification, executive briefing, documented decisions |
| Communication - External | | Regulatory notification, customer communication, media response |
| Recovery Planning | | Backup verification, recovery priority, RTO tracking |
| Legal & Compliance | | Breach notification timelines, evidence preservation, law enforcement engagement |
| Business Continuity | | Manual operations, customer impact mitigation, revenue loss estimation |
| Payment Decision | | Structured framework, legal review, OFAC sanctions check |

### Step 5: Document Findings and Remediation Plan

Produce an after-action report (AAR) within 5 business days:

**AAR Contents:**
1. Exercise overview and objectives
2. Scenario summary and injects
3. Key decisions made and rationale
4. Strengths observed
5. Gaps identified with severity rating
6. Remediation actions with owners and deadlines
7. Comparison to previous exercise results (if applicable)

## Key Concepts

| Term | Definition |
|------|------------|
| **Tabletop Exercise (TTX)** | Discussion-based exercise where participants walk through a simulated incident scenario to test plans and procedures |
| **Inject** | New information introduced during the exercise to change the scenario and force additional decision-making |
| **SITREP** | Situation Report providing current status of the simulated incident at each exercise phase |
| **After-Action Report (AAR)** | Post-exercise document capturing findings, gaps, strengths, and remediation actions |
| **Double Extortion** | Ransomware tactic where attackers both encrypt data and threaten to publish stolen data unless ransom is paid |
| **OFAC Check** | Verification that ransom payment recipient is not on the US Treasury OFAC sanctions list, which would make payment illegal |

## Tools & Systems

- **CISA Tabletop Exercise Packages (CTEPs)**: Free scenario packages from CISA designed for critical infrastructure sectors
- **FEMA Homeland Security Exercise and Evaluation Program (HSEEP)**: Methodology for designing, conducting, and evaluating exercises
- **Immersive Labs**: Platform providing interactive cyber crisis simulations with real-time scoring
- **Tabletop Scenarios (from NCSC UK)**: Exercise in a Box tool providing free guided tabletop exercises
- **Ransomware Readiness Assessment (CISA)**: Self-assessment tool for evaluating ransomware preparedness

## Common Scenarios

### Scenario: Healthcare System Double Extortion Exercise

**Context**: A 5-hospital healthcare system conducts an annual ransomware tabletop. Previous exercise revealed gaps in HIPAA breach notification and clinical system recovery priority. This year's scenario simulates a double extortion attack targeting the EMR system.

**Approach**:
1. Design scenario based on Cl0p MOO (Managed Operations Operator) TTPs: exploitation of MOVEit vulnerability for initial access, data exfiltration of 500,000 patient records, followed by encryption of EMR database servers
2. Participants: CISO, CIO, CMO (Chief Medical Officer), General Counsel, VP Communications, Director of Clinical Operations, Privacy Officer, External IR firm representative
3. Phase 1 inject: EMR system down, emergency department diverting patients to neighboring hospital
4. Phase 2 inject: HHS OCR (Office for Civil Rights) contacts organization about reports of patient data on dark web
5. Phase 3 inject: Attacker provides decryption key sample for $3.5M, 48-hour deadline
6. Key finding: Organization lacks documented criteria for ransom payment decision and had not pre-identified an OFAC-compliant payment mechanism
7. Remediation: Establish payment decision framework, pre-engage ransomware negotiation firm, update HIPAA breach notification procedures with specific timelines

**Pitfalls**:
- Designing unrealistic scenarios that do not reflect actual ransomware TTPs, reducing exercise credibility
- Allowing technical teams to dominate the exercise while business and legal participants remain passive
- Not testing the communication plan (many organizations discover their notification list is outdated during the actual incident)
- Failing to follow up on remediation actions identified in the AAR, negating the exercise value

## Output Format

```
## Ransomware Tabletop Exercise - After Action Report

**Exercise Date**: [Date]
**Facilitator**: [Name]
**Scenario**: [Brief description]
**Duration**: [Hours]
**Participants**: [Count by department]

### Exercise Objectives
1. [Objective] - Met / Partially Met / Not Met
2. [Objective] - Met / Partially Met / Not Met

### Key Decisions Log
| Time | Decision Point | Decision Made | Rationale | Assessment |
|------|---------------|--------------|-----------|------------|

### Strengths Observed
1. [Strength]

### Gaps Identified
| Gap | Severity | Affected Area | Current State | Desired State |
|-----|----------|--------------|---------------|---------------|

### Remediation Actions
| Action | Owner | Deadline | Priority | Status |
|--------|-------|----------|----------|--------|

### Comparison to Previous Exercise
| Area | Previous Score | Current Score | Trend |
|------|---------------|--------------|-------|
```
