---
name: executing-nist-rmf-authorization-to-operate
description: Drive a federal system through the NIST Risk Management Framework (SP 800-37 Rev 2) to an Authorization to Operate (ATO) - Prepare, Categorize (FIPS 199), Select a control baseline (FIPS 200 / SP 800-53 Rev 5), Implement, Assess (SP 800-53A), Authorize, and Monitor continuously. Use when a system needs an ATO or a renewal, when working a FISMA/FedRAMP authorization package, when building or reviewing an SSP, SAR, or POA&M, when categorizing a system as Low/Moderate/High impact, when selecting or tailoring a control baseline, or when standing up continuous monitoring (ConMon) after authorization. Covers ATO, conditional ATO (cATO), and the artifacts assessors expect. Keywords - NIST RMF, 800-37, ATO, authorization to operate, FISMA, FedRAMP, SSP, SAR, POA&M, FIPS 199, FIPS 200, 800-53, 800-53A, control baseline, security categorization, continuous monitoring. Do not use for a standalone NIST 800-30 risk assessment or risk register - use conducting-cyber-risk-assessment-with-nist-800-30.
domain: cybersecurity
subdomain: compliance-governance
tags:
- nist-rmf
- nist-800-37
- ato
- fisma
- fedramp
- nist-800-53
- fips-199
- ssp
- poam
- continuous-monitoring
- governance
version: "1.0"
author: andrewibrah
license: Apache-2.0
nist_csf:
- GV.OC-03
- GV.RM-01
- ID.AM-08
- ID.RA-05
- PR.IR-01
mitre_attack:
- T1078
- T1190
- T1068
- T1210
- T1486
---

# Executing the NIST RMF to an Authorization to Operate (ATO)

## When to Use

- When a federal or federally-aligned system (or a FedRAMP cloud service) needs an **Authorization to Operate**, a re-authorization, or has fallen out of authorization.
- When you must produce or review the core authorization artifacts: **System Security Plan (SSP)**, **Security Assessment Report (SAR)**, and **Plan of Action & Milestones (POA&M)**.
- When categorizing a system's impact level (Low / Moderate / High) under **FIPS 199**.
- When selecting, tailoring, or implementing a **NIST SP 800-53 Rev 5** control baseline.
- When standing up **continuous monitoring (ConMon)** or pursuing **ongoing authorization / cATO** after an initial ATO.

## Prerequisites

- A defined **system** and **authorization boundary** (what's in, what's inherited, what's a leveraged service).
- An identified **Authorizing Official (AO)**, **System Owner**, and **ISSO**.
- The information types the system handles (use **SP 800-60** to map them to impact levels).
- For cloud: the provider's **Customer Responsibility Matrix (CRM)** and any inherited/leveraged ATO.
- Access to assessment evidence sources (config, scans, policies) for the Assess step.

## Workflow

NIST SP 800-37 Rev 2 defines **seven steps**. Prepare is the foundation; the rest run in order and then loop through Monitor.

### 0/1. Prepare (organization and system level)
Establish context: roles (AO, SO, ISSO, assessor), risk-management strategy and tolerance (ties to SP 800-39), a control baseline strategy, common controls available for inheritance, and the system's mission/business context. Define the **authorization boundary** precisely — scope creep here inflates the whole package.

### 2. Categorize (FIPS 199 + SP 800-60)
Determine the impact level for **confidentiality, integrity, and availability** for each information type, then take the **high-water mark** across the three to set the overall system categorization: **Low**, **Moderate**, or **High**. Document in the SSP. This single decision drives the entire control baseline.

### 3. Select (FIPS 200 + SP 800-53 Rev 5 + SP 800-53B)
Start from the SP 800-53B baseline matching the categorization (Low/Moderate/High). Then **tailor**: apply scoping guidance, select compensating controls where needed, and assign values to organization-defined parameters. Add overlays (e.g., privacy, FedRAMP). Record the tailored set and the rationale in the SSP. Identify which controls are **common (inherited)**, **system-specific**, or **hybrid**.

### 4. Implement
Deploy the selected controls and **document how each is implemented** in the SSP — the implementation statement, not just "yes." This is the artifact assessors read first; vague statements generate findings.

### 5. Assess (SP 800-53A Rev 5)
An independent assessor evaluates controls using the **examine / interview / test** methods against assessment objectives. Findings of "other than satisfied" become weaknesses. Output is the **Security Assessment Report (SAR)**. Remediate what you can before authorization; the rest flows to the POA&M.

### 6. Authorize
Assemble the **authorization package**: SSP + SAR + POA&M (plus supporting artifacts). The AO reviews **residual risk** and renders a decision:
- **ATO** — authorized, typically with a defined term and a ConMon expectation.
- **Conditional / cATO** — authorized subject to conditions or operating under an approved ongoing-authorization model.
- **Denial / DATO** — risk too high; system may not operate.

The decision and its rationale are captured in the **authorization decision document**.

### 7. Monitor (continuous monitoring)
Authorization is not a one-time gate. Maintain an ongoing posture: track control effectiveness, ingest scan/config drift, update the SSP on change, work the POA&M to closure, report per the ConMon plan, and feed significant changes back into reassessment. Mature programs move from periodic re-ATO to **ongoing authorization**.

## Key Concepts

| Concept | Definition |
|---|---|
| Authorization boundary | The set of components, data flows, and inherited services covered by the authorization. |
| FIPS 199 categorization | Low/Moderate/High per C/I/A; overall = high-water mark across the three. |
| Control baseline | The SP 800-53B starting control set for the categorization, before tailoring. |
| Tailoring | Adjusting the baseline via scoping, compensating controls, and parameter values. |
| Common / inherited control | A control provided by another entity (e.g., the platform) and inherited by the system. |
| SSP | System Security Plan — describes the system, boundary, and how each control is implemented. |
| SAR | Security Assessment Report — the assessor's findings on control effectiveness. |
| POA&M | Plan of Action & Milestones — tracked weaknesses with owners and remediation dates. |
| ATO / cATO / DATO | Authorize / conditional (ongoing) / denial of authorization to operate. |
| Authorizing Official (AO) | The senior official who accepts residual risk and signs the authorization. |
| ConMon | Continuous monitoring — ongoing control-effectiveness and risk tracking post-ATO. |

## Tools & Systems

- **NIST SP 800-37 Rev 2** — the RMF process (7 steps).
- **FIPS 199 / FIPS 200 / SP 800-60** — categorization and minimum requirements.
- **NIST SP 800-53 Rev 5 / 800-53B** — control catalog and baselines.
- **NIST SP 800-53A Rev 5** — assessment procedures (examine/interview/test).
- **OSCAL** — machine-readable SSP/SAR/POA&M (NIST's authorization-document format).
- **eMASS** (DoD) / **FedRAMP** templates — package management and submission.
- **GRC platforms** — Xacta, ServiceNow, RegScale, etc., to manage the package and ConMon.
- **NIST CSF 2.0** — cross-walks to communicate RMF posture in framework terms.

## Common Scenarios

- **New system pre-launch.** Run Categorize → Authorize before go-live; ATO is the gate to production.
- **Cloud service (FedRAMP).** Inherit the platform's controls, document the CRM split, and authorize the customer-responsible delta.
- **Re-authorization.** Triggered by term expiry or significant change; refresh SSP/SAR/POA&M and re-decide.
- **cATO / ongoing authorization.** Replace periodic re-ATO with continuous evidence and an approved ConMon model.
- **POA&M review.** Triage open weaknesses by risk, assign owners and dates, and report closure trend to the AO.

## Output Format

Produce an **Authorization Package summary** using `assets/template.md`, containing:

1. **System & boundary** — description, components, data flows, inherited services.
2. **Categorization** — FIPS 199 C/I/A and overall impact, with information-type rationale.
3. **Control baseline & tailoring** — baseline selected, tailoring decisions, common vs system-specific.
4. **Implementation status** — per-family implementation summary (from the SSP).
5. **Assessment results (SAR)** — findings by severity; what's satisfied vs other-than-satisfied.
6. **POA&M** — open weaknesses, risk, owner, milestone dates.
7. **Authorization decision** — ATO/cATO/DATO, term, conditions, residual-risk statement, AO.
8. **ConMon plan** — what's monitored, how often, reporting cadence, reassessment triggers.

Use `scripts/process.py` to select the right SP 800-53B baseline from a FIPS 199 categorization, summarize control-implementation status, and generate a POA&M table from a findings JSON.
