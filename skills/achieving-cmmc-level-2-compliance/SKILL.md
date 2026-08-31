---
name: achieving-cmmc-level-2-compliance
description: Prepare a defense-contractor environment for CMMC Level 2 certification - scope CUI and FCI, implement the 110 NIST SP 800-171 Rev 2 security requirements across 14 families, compute the SPRS score with the DoD Assessment Methodology, manage a compliant POA&M, and ready the organization for a C3PAO assessment. Use when an organization handles Controlled Unclassified Information (CUI) under a DoD contract, when a contract carries DFARS clause 252.204-7012/7019/7020/7021, when preparing for or responding to a CMMC assessment, when computing or improving an SPRS score, when building a System Security Plan or POA&M for 800-171, or when scoping which systems are in the CUI boundary. Keywords - CMMC, NIST 800-171, SP 800-171 Rev 2, CUI, FCI, SPRS, DFARS 7012, C3PAO, POA&M, System Security Plan, DoD Assessment Methodology, defense industrial base, DIB, FedRAMP equivalency. Do not use for federal FISMA/FedRAMP RMF authorization-to-operate packages - use executing-nist-rmf-authorization-to-operate.
domain: cybersecurity
subdomain: compliance-governance
tags:
- cmmc
- nist-800-171
- cui
- sprs
- dfars
- c3pao
- poam
- compliance
- governance
- defense-industrial-base
version: "1.0"
author: andrewibrah
license: Apache-2.0
nist_csf:
- GV.OC-03
- GV.SC-01
- ID.AM-08
- ID.RA-05
- PR.AA-01
- PR.DS-01
mitre_attack:
- T1078
- T1190
- T1041
- T1048
- T1567
---

# Achieving CMMC Level 2 Compliance

## When to Use

- When an organization in the **Defense Industrial Base (DIB)** stores, processes, or transmits **Controlled Unclassified Information (CUI)** under a DoD contract.
- When a contract includes **DFARS 252.204-7012** (safeguarding/incident reporting), **-7019/-7020** (NIST 800-171 self-assessment + SPRS), or the new **-7021** (CMMC requirement).
- When preparing for a **C3PAO** third-party assessment or a DoD-led assessment.
- When you must **compute, post, or improve an SPRS score** based on the NIST SP 800-171 DoD Assessment Methodology.
- When authoring or remediating a **System Security Plan (SSP)** and **POA&M** for the 110 requirements.
- When **scoping** which assets fall inside the CUI/FCI boundary (CUI assets, security-protection assets, contractor risk-managed assets, out-of-scope).

## Prerequisites

- Knowledge of **which contracts carry CUI** and the CUI categories involved (check the contract and the DoD CUI Registry).
- An asset inventory and network diagram so you can define the **CMMC assessment scope** before assessing controls.
- The **NIST SP 800-171 Rev 2** requirements and the **DoD Assessment Methodology** scoring weights.
- A documented **SSP** (its absence is itself a failed requirement — 3.12.4).
- Identification of any **External Service Providers (ESPs)** / cloud services touching CUI, and whether they meet **FedRAMP Moderate (or equivalency)**.

## Workflow

### 1. Determine applicability and CUI categories
Confirm the contract requires CMMC Level 2 (CUI present, not just FCI). FCI-only contracts are **Level 1** (the 15 FAR 52.204-21 requirements). Identify CUI categories from the contract and the DoD CUI Registry.

### 2. Scope the environment
Classify every asset into one of the CMMC scoping categories:
- **CUI Assets** — process/store/transmit CUI (in scope, assessed against all applicable controls).
- **Security Protection Assets** — provide security to the CUI environment (in scope).
- **Contractor Risk Managed Assets** — could but are not intended to handle CUI; managed by policy.
- **Specialized Assets** (IoT/OT, GFE, test equipment) — documented, limited assessment.
- **Out-of-Scope** — physically/logically isolated from CUI.

Minimize scope deliberately — a smaller, well-segmented CUI enclave is far cheaper to certify than a flat network.

### 3. Implement the 110 requirements (NIST SP 800-171 Rev 2)
Work the **14 families** (3.1–3.14). For each requirement, implement, then write the **how** in the SSP. High-leverage early wins: MFA (3.5.3), FIPS-validated cryptography (3.13.11), audit logging (3.3.x), access control + least privilege (3.1.x), and incident response (3.6.x).

### 4. Score with the DoD Assessment Methodology (SPRS)
Start at **110** and subtract the weighted value (**1, 3, or 5 points**) of each **unmet** requirement; partial credit applies to a small number of controls (e.g., MFA, FIPS crypto). The result is the **SPRS score** (maximum 110; the methodology floor is −203). Post the score, the SSP date, and the assessment scope to **SPRS** (or eMASS for higher assessments).

### 5. Build a compliant POA&M
Document every unmet requirement with owner, remediation, and milestone. **Constraints under the CMMC rule:** a **Conditional** status requires a score of at least **80%** (≥ 88 of 110), only **POA&M-eligible** requirements may be deferred (the highest-weighted security requirements must be fully met — verify eligibility against 32 CFR Part 170), and all POA&M items must be **closed within 180 days** to convert Conditional → **Final**.

### 6. Assess (self or C3PAO)
- **Level 1** and a subset of Level 2 = annual **self-assessment** with an affirmation in SPRS.
- **Level 2 (most CUI contracts)** = triennial **C3PAO** certification assessment.
- **Level 3** = DoD (DIBCAC) assessment on top of Level 2, adding SP 800-172 enhanced requirements.
Assessors evaluate each objective as **MET / NOT MET / N/A** with evidence (examine/interview/test). A senior official files the **annual affirmation** of continued compliance.

### 7. Maintain certification
Certification is valid **three years** with **annual affirmations**. Maintain the SSP, re-score on change, keep evidence current, and feed significant changes back into the assessment.

## Key Concepts

| Concept | Definition |
|---|---|
| FCI | Federal Contract Information — Level 1 protects it (FAR 52.204-21). |
| CUI | Controlled Unclassified Information — Level 2 protects it (NIST 800-171). |
| 110 requirements | The SP 800-171 Rev 2 security requirements across 14 families. |
| SPRS | Supplier Performance Risk System — where the 800-171 score is posted. |
| DoD Assessment Methodology | The 1/3/5-point weighting used to compute the score from 110. |
| C3PAO | CMMC Third-Party Assessment Organization — performs Level 2 certification. |
| POA&M | Plan of Action & Milestones — limited, must close in 180 days for Final status. |
| Conditional vs Final | Conditional = open POA&M (score ≥ 80%); Final = all controls met. |
| ESP | External Service Provider — must meet FedRAMP Moderate / equivalency for CUI. |
| Scoping categories | CUI / Security Protection / Contractor Risk Managed / Specialized / Out-of-Scope. |

## Tools & Systems

- **NIST SP 800-171 Rev 2** — the 110 requirements (and 800-171A for assessment objectives).
- **DoD NIST SP 800-171 Assessment Methodology** — the scoring weights.
- **32 CFR Part 170** (CMMC Program rule) and **48 CFR / DFARS 252.204-7021** (acquisition rule).
- **SPRS** — score posting; **SAM.gov** for registration.
- **SP 800-172 / 800-172A** — enhanced requirements for Level 3.
- **GRC / compliance tooling** — to manage the SSP, POA&M, and evidence (e.g., Xacta, RegScale, FutureFeed-style trackers).

## Common Scenarios

- **Prime flows CUI to a sub.** The sub needs its own Level 2 scope, SSP, SPRS score, and (most likely) C3PAO certification.
- **Score is below 88.** Prioritize the highest-weighted unmet requirements (5-point, then 3-point) to clear the conditional threshold and shrink the POA&M.
- **Cloud holds CUI.** Confirm the service is FedRAMP Moderate authorized or meets equivalency; document the responsibility split.
- **Flat network.** Re-scope into a segmented CUI enclave to cut the assessment surface before spending on controls.
- **Annual affirmation due.** A senior official affirms continued compliance in SPRS; let it lapse and you risk contract eligibility.

## Output Format

Produce a **CMMC Level 2 Readiness Report** using `assets/template.md`, containing:

1. **Applicability & CUI categories** — why Level 2 applies.
2. **Scope** — assets by scoping category and the CUI boundary diagram reference.
3. **Control status by family** — met / not met / N/A across the 14 families.
4. **SPRS score** — computed score, deductions, and the gap to 110 and to the 88 threshold.
5. **POA&M** — unmet requirements, eligibility check, owners, 180-day milestones.
6. **Assessment path** — self vs C3PAO, target date, affirmation owner.
7. **Remediation roadmap** — sequenced by point value and effort.

Use `scripts/process.py` to compute the SPRS score from a control-status JSON, flag POA&M-eligibility concerns, and report the gap to the conditional-certification threshold.
