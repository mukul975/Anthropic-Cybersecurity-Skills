---
name: managing-third-party-vendor-risk
description: Build and run a third-party/vendor risk management (TPRM) program aligned to NIST SP 800-161 C-SCRM - inventory and tier vendors, issue SIG/CAIQ questionnaires, review SOC 2/ISO 27001 evidence, set contractual right-to-audit clauses, monitor vendors continuously, and offboard securely. Use when assessing a new vendor, standing up a vendor-risk program, tiering a portfolio, reviewing a SOC 2/CAIQ, or writing security terms into a contract. Do not use for building an organization's own ISO 27001 ISMS - use implementing-iso-27001-information-security-management.
domain: cybersecurity
subdomain: compliance-governance
tags:
- third-party-risk
- vendor-risk-management
- tprm
- supply-chain-risk
- c-scrm
- nist-800-161
- soc2
- caiq
- continuous-monitoring
- governance
version: "1.0"
author: andrewibrah
license: Apache-2.0
nist_csf:
- GV.SC-01
- GV.SC-04
- GV.SC-06
- GV.SC-07
- ID.RA-05
- GV.OC-03
mitre_attack:
- T1199
- T1195
- T1078
- T1190
- T1567
---

# Managing Third-Party Vendor Risk

## When to Use

- When assessing a **new vendor** before onboarding, especially one that will handle sensitive data, connect to your network, or be embedded in a critical process.
- When **standing up or maturing** a third-party risk management (TPRM) program and you need a repeatable tiering + assessment workflow.
- When **tiering an existing vendor portfolio** so effort matches risk.
- When **reviewing vendor evidence** — a SOC 2 Type II report, ISO 27001 certificate, CAIQ, or pen-test summary — and you need to know what to look for.
- When writing **security and privacy requirements into a contract / DPA**, including breach-notification SLAs and right-to-audit.
- When a vendor (or their subcontractor) suffers a **breach** and you must assess exposure.
- When managing **software supply-chain** and **Nth-party** (fourth-party and beyond) risk.

## Prerequisites

- A **vendor inventory** (who you use, for what, and what data/access each has).
- A defined **risk-tiering model** (criteria and thresholds) agreed with the business.
- Access to standardized **questionnaires** (Shared Assessments **SIG**, CSA **CAIQ**) and a way to collect evidence.
- Clarity on your own **regulatory obligations** that flow down to vendors (e.g., HIPAA BAAs, CMMC flowdown, GDPR processor terms, PCI).
- Stakeholders identified: procurement, legal, security, data owner, and the business sponsor.

## Workflow

### 1. Inventory and classify vendors
Catalog every third party and capture: data sensitivity handled, type of access (network, physical, none), business criticality, and regulatory scope. You cannot manage what you have not inventoried — shadow vendors are a common blind spot.

### 2. Tier by inherent risk
Score each vendor on inherent-risk factors (data sensitivity, access, criticality, regulatory scope, spend/concentration) and assign a **tier** (e.g., Critical / High / Moderate / Low). The tier drives **how deep** the assessment goes and **how often** you reassess. A payroll processor with PII and system access is not the same risk as a stock-photo subscription.

### 3. Run tier-appropriate due diligence
- **Critical/High:** full **SIG** (or SIG Core), request **SOC 2 Type II** and/or **ISO 27001**, recent **pen-test** summary, and evidence of an incident-response capability. Consider an assessor call.
- **Moderate:** **SIG Lite** or **CAIQ**, plus key attestations.
- **Low:** lightweight questionnaire / self-attestation.

### 4. Review evidence critically
Don't just collect — **read**:
- **SOC 2 Type II:** check scope, the Trust Services Criteria covered, the audit **period** (not just the date), and especially the **exceptions/deviations** and any qualified opinion. A clean cover page can hide noted exceptions.
- **ISO 27001:** confirm the **scope statement** and the Statement of Applicability actually cover the service you're buying.
- **CAIQ:** look for "no" answers and CCM domains left blank.
- **Pen-test:** age, scope, and whether highs/criticals were remediated.

### 5. Identify gaps and decide
Compare findings against your control requirements. For each gap: accept, require remediation (with a date), add a compensating control on your side, or walk away. Record the **residual risk** and a risk-owner decision.

### 6. Codify in the contract / DPA
Bake requirements into the agreement: security control obligations, **breach-notification timeline**, data-handling and return/destruction terms, **right-to-audit / right to assessment evidence**, subcontractor (Nth-party) flowdown, and liability/insurance. Contracts are where TPRM gets teeth.

### 7. Monitor continuously
Tiering is not a one-time gate. For higher tiers: periodic reassessment, **security-ratings** feeds, breach/news monitoring, certificate-expiry tracking, and watching for material changes (acquisition, region change, new subprocessors). Re-tier on change.

### 8. Manage Nth-party and concentration risk
Map critical **fourth parties** (your vendor's key subprocessors) and watch for **concentration** (many vendors riding on the same upstream provider) — a single upstream outage or breach can hit your whole portfolio at once.

### 9. Offboard securely
On termination: revoke access and credentials, confirm **data return or certified destruction**, remove integrations/API keys, and update the inventory. Un-offboarded vendors are standing risk.

## Key Concepts

| Concept | Definition |
|---|---|
| Inherent risk | Risk a vendor poses before controls — drives tiering. |
| Residual risk | Risk remaining after the vendor's (and your) controls. |
| Vendor tier | Risk band (Critical/High/Moderate/Low) setting assessment depth and cadence. |
| SIG | Shared Assessments Standardized Information Gathering questionnaire (full / Lite / Core). |
| CAIQ | CSA Consensus Assessments Initiative Questionnaire (maps to the Cloud Controls Matrix). |
| SOC 2 Type II | Attestation on control design **and** operating effectiveness over a period. |
| Right to audit | Contractual right to assess the vendor or obtain assessment evidence. |
| Nth-party / fourth-party | Your vendor's vendors (and beyond) — indirect supply-chain risk. |
| Concentration risk | Many vendors depending on the same upstream provider. |
| C-SCRM | Cybersecurity Supply Chain Risk Management (NIST SP 800-161). |

## Tools & Systems

- **NIST SP 800-161 Rev 1** — Cybersecurity Supply Chain Risk Management practices.
- **NIST CSF 2.0 — GV.SC** — the supply-chain risk-management category (program backbone).
- **Shared Assessments SIG** and **CSA CAIQ / STAR registry** — standardized questionnaires.
- **SOC 2 / ISO 27001 / PCI AOC / pen-test reports** — vendor evidence.
- **Security-ratings services** (e.g., BitSight/SecurityScorecard-style) — continuous external signal.
- **TPRM platforms** — OneTrust, ProcessUnity, Prevalent, ServiceNow VRM, etc., to manage the workflow and inventory.
- **GDPR DPA / HIPAA BAA / CMMC flowdown** — regulatory contract instruments.

## Common Scenarios

- **New SaaS onboarding.** Tier it, send the right questionnaire, read the SOC 2 exceptions, set contract terms, then approve with documented residual risk.
- **Portfolio has 400 vendors, no tiers.** Tier first; concentrate assessment effort on the Critical/High tail rather than spreading thin.
- **Vendor breach in the news.** Pull the vendor record, assess data/access exposure, invoke the breach-notification clause, and require a post-incident report.
- **Auditor asks for your TPRM program.** Show the tiering model, the assessment cadence, and evidence of continuous monitoring mapped to GV.SC.
- **Critical fourth party identified.** Document the dependency and the concentration risk; build a contingency for that upstream provider.

## Output Format

Produce a **Vendor Risk Assessment** using `assets/template.md`, containing:

1. **Vendor profile** — service, data handled, access type, business criticality, regulatory scope.
2. **Inherent-risk tier** — score and resulting tier, with rationale.
3. **Due-diligence performed** — questionnaire used and evidence collected (SOC 2 period, ISO scope, pen-test age).
4. **Findings** — gaps with severity, including notable SOC 2 exceptions.
5. **Decision & residual risk** — approve/conditional/reject, with risk-owner sign-off.
6. **Contractual requirements** — security terms, breach SLA, right-to-audit, subprocessor flowdown.
7. **Monitoring & reassessment plan** — cadence, signals watched, re-tier triggers.
8. **Nth-party notes** — critical subprocessors and concentration risk.

Use `scripts/process.py` to compute a vendor's inherent-risk tier from a profile JSON, set the assessment depth and reassessment cadence, and flag missing evidence for the assigned tier.
