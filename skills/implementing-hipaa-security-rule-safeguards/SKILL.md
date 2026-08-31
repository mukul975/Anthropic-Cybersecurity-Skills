---
name: implementing-hipaa-security-rule-safeguards
description: Implement the HIPAA Security Rule (45 CFR Part 164 Subpart C) to protect electronic protected health information (ePHI) - conduct the required risk analysis, deploy the administrative, physical, and technical safeguards, handle required vs addressable implementation specifications, execute Business Associate Agreements, and stand up breach-notification readiness. Use when an organization is a HIPAA covered entity or business associate, when protecting ePHI, when preparing for an OCR audit or responding to a breach, when performing a HIPAA Security Risk Analysis, when drafting or reviewing a BAA, or when mapping security controls to the §164.308/310/312/314/316 safeguards. Notes the 2025 NPRM proposed changes (not yet final). Keywords - HIPAA, HIPAA Security Rule, ePHI, PHI, 45 CFR 164, risk analysis, addressable, required, Business Associate Agreement, BAA, OCR, breach notification, HITECH. Do not use for EU GDPR personal-data privacy compliance - use conducting-gdpr-compliance-assessment.
domain: cybersecurity
subdomain: compliance-governance
tags:
- hipaa
- hipaa-security-rule
- ephi
- phi
- 45-cfr-164
- risk-analysis
- baa
- breach-notification
- ocr
- compliance
- governance
version: "1.0"
author: andrewibrah
license: Apache-2.0
nist_csf:
- GV.OC-03
- GV.RM-01
- ID.RA-01
- ID.RA-05
- PR.DS-01
- PR.AA-01
- DE.CM-01
mitre_attack:
- T1078
- T1566
- T1486
- T1530
- T1048
---

# Implementing HIPAA Security Rule Safeguards

## When to Use

- When an organization is a **covered entity** (health plan, clearinghouse, or provider transmitting electronic transactions) or a **business associate** handling **ePHI** on their behalf.
- When standing up or maturing controls to protect **electronic protected health information**.
- When performing the mandatory **HIPAA Security Risk Analysis** (§164.308(a)(1)(ii)(A)) — the single most-cited gap in OCR enforcement.
- When preparing for an **OCR audit/investigation** or responding to a suspected **breach**.
- When drafting, reviewing, or remediating a **Business Associate Agreement (BAA)**.
- When mapping existing security controls to the HIPAA safeguard standards and implementation specifications.

> Scope note: this skill covers the **Security Rule** (ePHI). The **Privacy Rule** (uses/disclosures of all PHI) and the **Breach Notification Rule** are related but distinct; this skill touches breach readiness and BAAs where they intersect security.

## Prerequisites

- A clear determination of the organization's **role** (covered entity vs business associate) and where ePHI lives, flows, and is stored (an ePHI data map).
- An **asset inventory** of systems that create, receive, maintain, or transmit ePHI.
- Knowledge of the current rule's structure (45 CFR §§164.302–318) and the **required vs addressable** distinction.
- Awareness that a **2025 NPRM** proposes significant changes (see Workflow step 7 and `references/standards.md`) — track but do not assume them as in force.

## Workflow

### 1. Conduct the Security Risk Analysis (§164.308(a)(1)(ii)(A))
This is **required** and foundational. Inventory ePHI and systems, identify threats and vulnerabilities, assess current controls, determine likelihood and impact, and assign risk levels. (Pair with the NIST 800-30 methodology and HHS's SRA Tool.) Output is a documented, dated risk analysis — the artifact OCR asks for first.

### 2. Implement Administrative Safeguards (§164.308)
The largest section. Includes the **Security Management Process** (risk analysis, risk management, sanction policy, information-system activity review), assigned **security responsibility** (a named Security Official), **workforce security**, **information access management**, **security awareness and training**, **security incident procedures**, **contingency planning** (data backup, disaster recovery, emergency-mode operation), **evaluation**, and **BAAs** with business associates.

### 3. Implement Physical Safeguards (§164.310)
**Facility access controls**, **workstation use** and **workstation security**, and **device and media controls** (disposal, media re-use, accountability, data backup and storage).

### 4. Implement Technical Safeguards (§164.312)
**Access control** (unique user ID, emergency access, automatic logoff, encryption/decryption), **audit controls**, **integrity** (mechanisms to authenticate ePHI), **person/entity authentication**, and **transmission security** (integrity controls + encryption).

### 5. Resolve "Required" vs "Addressable" specifications
Under the current rule, each implementation specification is **Required** (must implement) or **Addressable** (assess whether reasonable and appropriate; if so implement, if not document why and implement an equivalent alternative). **Addressable does not mean optional** — it means make and document a risk-based decision.

### 6. Execute Business Associate Agreements (§164.314 / §164.308(b))
Every business associate that touches ePHI needs a BAA binding it to safeguard ePHI, report incidents, and flow requirements to subcontractors. Maintain the BAA inventory.

### 7. Track the 2025 NPRM proposed changes (NOT yet final)
HHS OCR published an NPRM (Jan 6, 2025) proposing to **remove the required/addressable distinction** (make nearly all specifications required), and to mandate **MFA**, **encryption of ePHI at rest and in transit**, **asset inventory and network maps**, **vulnerability scans every 6 months**, **annual penetration testing**, **72-hour restoration of certain systems/data**, and **annual risk-analysis updates**. **These are proposals** — the current rule remains in force until a final rule is published and effective. Plan toward them, but comply with what is current.

### 8. Stand up breach-notification readiness (45 CFR §§164.400–414)
Define how you detect, assess (the four-factor risk assessment), and report breaches of unsecured PHI: to **individuals** and **HHS** (and **media** for breaches affecting 500+ in a state/jurisdiction), within the required timelines. Encryption to NIST standards renders PHI "secured" and is a safe harbor from breach notification.

### 9. Document everything (§164.316)
Maintain policies, procedures, and records of actions/decisions in writing, **retain for six years**, review periodically, and update in response to environmental or operational change.

## Key Concepts

| Concept | Definition |
|---|---|
| ePHI | Electronic protected health information — the Security Rule's scope. |
| Covered entity | Health plan, clearinghouse, or provider doing electronic transactions. |
| Business associate | A vendor that handles ePHI for a covered entity; bound by a BAA. |
| Risk analysis | Required, documented assessment of risks to ePHI (§164.308(a)(1)(ii)(A)). |
| Required vs addressable | Must-implement vs risk-based-decision implementation specifications. |
| Administrative / Physical / Technical safeguards | §164.308 / §164.310 / §164.312. |
| BAA | Business Associate Agreement — contractually binds vendors to safeguard ePHI. |
| Breach (unsecured PHI) | Triggers notification under §§164.400–414; encryption is a safe harbor. |
| OCR | HHS Office for Civil Rights — enforces HIPAA. |
| Six-year retention | Documentation retention requirement (§164.316). |

## Tools & Systems

- **45 CFR Part 164 Subpart C** — the Security Rule text (and Subpart D, Breach Notification).
- **HHS Security Risk Assessment (SRA) Tool** — free guided risk analysis.
- **NIST SP 800-66 Rev 2** — implementing the HIPAA Security Rule (NIST guidance, maps to 800-53).
- **NIST SP 800-30** — risk-assessment methodology to ground the SRA.
- **GRC / compliance platforms** — to manage policies, the BAA inventory, and evidence.
- **Encryption / MFA / SIEM / audit-logging tooling** — to satisfy technical safeguards and the proposed mandates.

## Common Scenarios

- **OCR investigation after a breach.** First request is almost always the current, dated **risk analysis** and the **risk-management plan** — have them ready.
- **New SaaS handling ePHI.** Sign a **BAA** before any ePHI flows; confirm the vendor's safeguards.
- **Addressable spec you won't implement as written.** Document the risk-based rationale and the **equivalent alternative** you implemented instead.
- **Preparing for the proposed rule.** Pre-position MFA, at-rest/in-transit encryption, asset inventory, scanning, and pen-testing so a final rule is a small step, not a scramble.
- **Lost/stolen device.** If ePHI was encrypted to NIST standards, the safe harbor applies; if not, run the four-factor breach assessment and notify as required.

## Output Format

Produce a **HIPAA Security Rule Gap Assessment** using `assets/template.md`, containing:

1. **Role & ePHI scope** — covered entity vs BA; ePHI data map and systems.
2. **Risk analysis summary** — top risks to ePHI with likelihood/impact (feeds risk management).
3. **Safeguard status** — Administrative / Physical / Technical, each specification marked **Implemented / Partial / Gap** with required-vs-addressable noted.
4. **BAA inventory** — business associates and BAA status.
5. **Breach-notification readiness** — detection, four-factor assessment, notification workflow.
6. **2025 NPRM gap view** — readiness against the proposed mandates (clearly labeled proposed).
7. **Remediation plan** — prioritized, with owners and dates; required specs and risk-analysis gaps first.

Use `scripts/process.py` to score a safeguard-status JSON across the §164.308/310/312 standards, weight required gaps above addressable ones, and emit the gap table plus a remediation-priority list.
