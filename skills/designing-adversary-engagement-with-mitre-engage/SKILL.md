---
name: designing-adversary-engagement-with-mitre-engage
description: 'Plan, run, and measure an adversary engagement operation using the MITRE Engage framework so that deployed deception is driven by strategy instead of deployed ad hoc. Covers the Engage Matrix (Prepare, Expose, Affect, Elicit, Understand), the 10-Step Operational Process, mapping engagement Activities to the ATT&CK techniques they expose, and defining measurable Goals and Operational Objectives. Use when a team has honeypots, honeytokens, or canary tokens but no coordinating strategy, when building a deception/denial program, when writing an adversary engagement operation plan, or when deciding which deception Activities to deploy against a specific threat actor. Keywords - MITRE Engage, adversary engagement, cyber deception strategy, Engage Matrix, deception program, engagement operation. Do not use for hands-on deployment of honeypots and deception tooling - use performing-deception-technology-deployment.'
domain: cybersecurity
subdomain: deception-technology
tags:
- mitre-engage
- adversary-engagement
- deception
- denial-and-deception
- engage-matrix
- cyber-deception
- threat-intelligence
- detection-engineering
version: "1.0"
author: andrewibrah
license: Apache-2.0
nist_csf:
- GV.RM-01
- ID.RA-01
- ID.IM-02
- DE.CM-01
- DE.AE-02
mitre_attack:
- T1078
- T1083
- T1021
- T1552
- T1046
---

# Designing Adversary Engagement with MITRE Engage

## When to Use

- When an organization owns deception tooling (honeypots, honeytokens, canary tokens, decoy files) but deploys it tactically with no unifying strategy or measurable outcome.
- When leadership asks whether the organization *should* engage adversaries, and what the legal, operational, and resourcing implications are.
- When writing a formal adversary engagement operation plan that must justify every deployed deceptive artifact against a strategic goal.
- When selecting which specific deception Activities to deploy against a known or suspected threat actor based on that actor's ATT&CK TTPs.
- When building a denial, deception, and adversary engagement (DD&AE) program that must integrate with existing SOC, threat intel, and incident response functions.
- When a deception deployment generates alerts that nobody knows how to act on, because Expose was never connected to Affect or Elicit goals.

This skill is the **strategy and operations layer** that sits above tactical deployment skills (honeypot, honeytoken, canary-token, and decoy-file deployment). Use those skills to *implement* the Activities this skill selects and sequences.

## Prerequisites

- Familiarity with MITRE ATT&CK (tactics, techniques, and how to read a technique page), because Engagement Activities are mapped to the ATT&CK techniques they expose.
- A documented set of critical assets and an understanding of which adversaries plausibly target them (a threat model or prioritized threat actor list).
- Executive sponsorship and a written legal review. Engagement operations interact with live adversaries and raise entrapment, evidence-handling, and liability questions; **never run an engagement operation without legal sign-off.**
- An existing detection and response capability. Engage is an additive strategy, not a replacement for defense-in-depth; if a defense-in-depth control fails, engagement keeps you in control rather than blind.
- Access to the live matrix at https://engage.mitre.org/matrix/ for canonical Activity names and IDs.

## Workflow

Engage operations follow the **10-Step Operational Process**. The matrix is linear to read but cyclical to run — you continuously realign Activities toward your Goals as the adversary reacts.

### 1. Confirm strategic fit (Prepare)
Decide where denial, deception, and adversary engagement fit in the existing cyber strategy. The `Prepare` goal (a strategic bookend, alongside `Understand`) defines the inputs to the operation. Document the strategic goal in plain language, e.g. "reduce dwell time of insider threats around the source-code repository" or "generate first-party CTI on the actor targeting our VPN."

### 2. Define Engagement Goals and Operational Objectives
Select from the three Engagement Goals. Goals set direction; **Operational Objectives** take measurable steps in that direction.

| Engagement Goal (EGO) | What it does | Example Operational Objective |
|---|---|---|
| Expose | Reveal adversary presence with high-fidelity, low-false-positive alerts | "Alert within 5 minutes of any touch on a decoy credential" |
| Affect | Negatively change the adversary's cost-value calculation (defender network only) | "Redirect the adversary away from 3 unpatchable legacy hosts" |
| Elicit | Observe the adversary to learn TTPs and produce CTI | "Obtain a second-stage malware sample" or "identify ≥10 new indicators" |

Write objectives as falsifiable, time-bound statements. A goal without an objective is unmeasurable.

### 3. Build the threat model and select Approaches
For each Goal, pick the Engagement Approaches (EAP) that fit the adversary you modeled:

- **Expose** → Collection, Detection
- **Affect** → Prevention, Direction, Disruption
- **Elicit** → Reassurance, Motivation

### 4. Map ATT&CK techniques to Engagement Activities
For each technique your target adversary uses, find the Engage Activity that exposes the weakness that technique creates. Example mappings:

| Adversary technique (ATT&CK) | Weakness exposed | Engage Activity (EAC) |
|---|---|---|
| T1078 Valid Accounts | Must test credentials | Decoy Credentials, Lures |
| T1083 File & Directory Discovery | Must enumerate files | Decoy Content, Pocket Litter |
| T1046 Network Service Discovery | Must scan the network | Network Diversity, Decoy Systems |
| T1021 Remote Services | Must move laterally | Decoy Systems, Network Manipulation |
| T1552 Unsecured Credentials | Harvests secrets | Decoy Credentials, Artifact Diversity |

Pull the authoritative Activity list and IDs from the live matrix; Engage IDs use the prefixes **SGO/EGO** (Goals), **SAP/EAP** (Approaches), and **SAC/EAC** (Activities).

### 5. Design the engagement environment
Decide realism and isolation. Choose between standalone, connected, or integrated decoy environments (see D3FEND honeynet types in `references/standards.md`). Populate it with diverse, believable artifacts — Persona Creation, Pocket Litter, Artifact Diversity, Application Diversity — so the environment survives adversary scrutiny.

### 6. Define gating criteria and rules of engagement
Document, before deployment: what the adversary is allowed to reach, the maximum blast radius, the trigger for tear-down or hand-off to IR, evidence preservation steps, and who has authority to escalate. **Affect Activities are limited to the defender's own network** — never act on infrastructure you do not own.

### 7. Deploy the Activities
Implement the selected Activities using the tactical deployment skills (honeypots, honeytokens, canary tokens, decoy files). Instrument every artifact so a touch produces telemetry routed to the SOC.

### 8. Operate and observe
Run the operation. Triage Expose alerts as high-fidelity (a touch on a decoy almost always means malicious or unauthorized activity). Feed observations back into Approach selection — realign Affect/Elicit Activities as the adversary behaves.

### 9. Analyze (Understand)
The `Understand` goal (the output bookend) turns observations into decisions: new detections for production, CTI for sharing, and validated or invalidated threat-model assumptions.

### 10. After-action and feedback
Score the operation against the Operational Objectives from Step 2. Capture what intel was gained, what Activities triggered, dwell time, and lessons learned. Update the threat model and feed the next cycle.

## Key Concepts

| Concept | Definition |
|---|---|
| Goal (SGO/EGO) | High-level outcome of the operation. Prepare/Understand are strategic bookends; Expose/Affect/Elicit are the engagement goals. |
| Approach (SAP/EAP) | The method used to make progress toward a Goal (e.g., Detection, Direction, Motivation). |
| Activity (SAC/EAC) | The concrete denial/deception action deployed (e.g., Decoy Credentials, Network Manipulation). |
| Operate | The default matrix view = Expose + Affect + Elicit, the three engagement goals. |
| Operational Objective | A measurable, time-bound target that operationalizes a Goal. |
| Gating Criteria | Pre-defined boundaries and triggers that constrain the operation's blast radius. |
| High-fidelity alert | An alert from a decoy that legitimate users have no reason to touch, yielding near-zero false positives. |
| Denial vs. Deception | Denial blocks the adversary's access to real information; deception feeds plausible false information. |

## Tools & Systems

- **MITRE Engage Matrix and Starter Kit** (https://engage.mitre.org) — canonical Goals/Approaches/Activities, the 10-Step Process, and operation-planning worksheets.
- **MITRE ATT&CK Navigator** — to lay out the target adversary's techniques and overlay selected Engagement Activities.
- **MITRE D3FEND** — the `Deceive` tactic provides defensive countermeasure naming (Decoy Environment, Decoy Object, honeynet types) that complements Engage.
- **Deception platforms / open tooling** — OpenCanary, T-Pot, Cowrie (honeypots); Canarytokens, Thinkst Canary (honeytokens); to *implement* selected Activities.
- **SIEM/SOAR** — to route decoy telemetry to high-priority detections and automate Expose → IR hand-off.
- **CTI platform (MISP, OpenCTI)** — to store and share the first-party intelligence produced under the Elicit goal.

## Common Scenarios

- **"We have honeypots but no value."** Map existing honeypots to the Expose goal, define an Operational Objective (alert latency, dwell-time reduction), and connect alerts to an IR hand-off so the deployment produces decisions, not noise.
- **"Targeted by a specific actor."** Build the actor's ATT&CK technique set, map each to the Activity that exposes it, and prioritize the smallest set of Activities that covers the actor's likely kill chain.
- **"Protect unpatchable legacy systems."** Use Affect Activities (Direction, Network Manipulation, decoys) to steer adversaries away from systems that cannot be remediated.
- **"Tired of CVE whack-a-mole."** Use the Elicit goal to generate a first-party CTI feed so defense is driven by observed adversary TTPs rather than the vulnerability of the week.
- **"Insider threat near critical data."** Seed Expose Activities (Decoy Content, Decoy Credentials, Pocket Litter) around the crown-jewel asset for high-fidelity detection of unauthorized internal access.

## Output Format

Produce an **Adversary Engagement Operation Plan** using `assets/template.md`, containing:

1. **Strategic context** — where DD&AE fits the cyber strategy; executive sponsor; legal sign-off reference.
2. **Engagement Goals + Operational Objectives** — each objective falsifiable and time-bound.
3. **Threat model** — target adversary, prioritized ATT&CK techniques.
4. **Activity selection matrix** — technique → exposed weakness → selected Engage Activity (with EAC IDs) → tactical deployment owner.
5. **Engagement environment design** — realism, isolation/honeynet type, artifact diversity plan.
6. **Gating criteria and rules of engagement** — blast radius, tear-down triggers, evidence handling, escalation authority.
7. **Measurement plan** — metrics per objective (alert latency, dwell time, indicators gained, samples obtained).
8. **After-action report** — objectives met/missed, intel produced, detections promoted to production, threat-model updates.

Use `scripts/process.py` to validate technique→Activity coverage and generate the operation-plan skeleton from a threat-model input.
