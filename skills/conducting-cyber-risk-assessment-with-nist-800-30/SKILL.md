---
name: conducting-cyber-risk-assessment-with-nist-800-30
description: Conduct a defensible cybersecurity risk assessment using the NIST SP 800-30 Rev 1 methodology - prepare scope and a risk model, identify threat sources and threat events, identify vulnerabilities and predisposing conditions, determine likelihood and impact, compute risk, and communicate results as a prioritized risk register. Use when an organization needs an actual risk *assessment* (not a maturity score), when a control framework (CSF, ISO 27001, RMF, SOC 2, PCI) requires a documented risk analysis as input, when leadership asks "what are our top risks and how bad are they", when assessing risk for a new system or major change, or when building a risk register from scratch. This is the methodology that feeds framework selection, ATO packages, and treatment decisions. Keywords - risk assessment, NIST 800-30, threat modeling, likelihood and impact, risk register, risk treatment. Do not use for scoring program maturity against CSF Implementation Tiers - use performing-nist-csf-maturity-assessment.
domain: cybersecurity
subdomain: compliance-governance
tags:
- risk-assessment
- nist-800-30
- risk-management
- threat-modeling
- risk-register
- governance
- nist-800-39
- compliance
version: "1.0"
author: andrewibrah
license: Apache-2.0
nist_csf:
- GV.RM-01
- ID.RA-01
- ID.RA-03
- ID.RA-04
- ID.RA-05
mitre_attack:
- T1566
- T1078
- T1190
- T1486
- T1021
---

# Conducting a Cyber Risk Assessment with NIST SP 800-30

## When to Use

- When the organization needs a real risk *assessment* — an analysis of specific threats, likelihoods, and impacts — rather than a maturity score against a framework. (Maturity tells you how mature your practices are; a risk assessment tells you what could hurt you and how badly.)
- When another framework requires a documented risk analysis as a mandatory input: NIST CSF (ID.RA), ISO 27001 (Clause 6.1.2), NIST RMF / 800-37 (the Prepare and Select steps), SOC 2 (CC3), PCI DSS, or HIPAA (§164.308(a)(1)(ii)(A)).
- When standing up or significantly changing a system and you must understand its risk before authorization or go-live.
- When leadership asks for the organization's top risks, ranked, with a rationale they can defend to a board or regulator.
- When building or refreshing an enterprise risk register.

## Prerequisites

- An inventory of in-scope assets, systems, and the information types they handle (system boundary defined).
- Access to threat intelligence (internal incident history, sector ISAC feeds, MITRE ATT&CK) to ground threat-event likelihood in observed behavior.
- Vulnerability data (scan results, pen-test findings, configuration/architecture review) for the in-scope systems.
- Business context: which missions/processes the systems support, and what impact to confidentiality, integrity, or availability would mean in business terms.
- Agreement on the **risk model and scales** before scoring, so results are comparable and repeatable (see `references/standards.md`).
- Familiarity with the three-tier risk-management context from NIST SP 800-39 (organization, mission/business process, information system).

## Workflow

NIST SP 800-30 Rev 1 defines four steps. Steps 1 and 4 bookend the assessment; Step 2 is the analytic core.

### 1. Prepare for the assessment
Define and document:
- **Purpose** (e.g., support an authorization decision, inform control selection, satisfy ISO 6.1.2).
- **Scope** — organizational tier (Tier 1/2/3), systems, and time horizon.
- **Assumptions and constraints** (e.g., assume an external adversarial threat with moderate capability).
- **Information sources** — threat, vulnerability, and impact inputs.
- **Risk model and analytic approach** — the factors (threat source, threat event, vulnerability, likelihood, impact) and the scales (qualitative Very Low–Very High, or semi-quantitative 0–10). Lock these now.

### 2. Conduct the assessment
Work through the analytic tasks in order. The 800-30 appendices provide the reference taxonomies (D–I).

**2a. Identify threat sources (Appendix D).** Classify by type: **Adversarial** (individuals, groups, nation-states — characterize capability, intent, targeting), **Accidental** (user error), **Structural** (equipment/software failure), **Environmental** (natural disasters, infrastructure outages).

**2b. Identify threat events (Appendix E).** The specific actions a source could take (e.g., "adversary exfiltrates credentials via phishing then moves laterally"). Map adversarial events to MITRE ATT&CK techniques for traceability.

**2c. Identify vulnerabilities and predisposing conditions (Appendix F).** Weaknesses (missing MFA, unpatched service) and conditions that make exploitation more or less likely (internet exposure, flat network, lack of segmentation).

**2d. Determine likelihood (Appendix G).** Assess the likelihood that a threat event is *initiated* (adversarial) or *occurs* (non-adversarial), and the likelihood it results in adverse impact given the vulnerabilities. Combine into an overall likelihood on the agreed scale.

**2e. Determine impact (Appendix H).** Magnitude of harm if the event succeeds — to operations, assets, individuals, other organizations, or the nation. Express against the agreed scale and in business terms.

**2f. Determine risk (Appendix I).** Risk is a function of likelihood and impact. Plot each threat event on the risk matrix (e.g., likelihood × impact → Very Low … Very High). Record the risk level, the contributing factors, and uncertainty/assumptions.

### 3. Communicate and share results
Produce the **risk register** and an executive briefing. For each risk: the threat event, affected assets, likelihood, impact, risk level, key contributing vulnerabilities, and a recommended treatment. Rank by risk level so decision-makers see the top risks first.

### 4. Maintain the assessment
Risk is not static. Define a refresh cadence and the triggers that force re-assessment (new system, major architecture change, significant incident, new threat intel). Track risk-acceptance decisions and treatment progress over time.

### 5. Drive treatment decisions
Hand the ranked register to risk owners. For each risk choose a treatment — **mitigate** (add/strengthen controls), **transfer** (insurance, contractual), **avoid** (stop the activity), or **accept** (document residual risk with an authorizing signature). Re-score residual risk after planned controls to show the post-treatment position.

## Key Concepts

| Concept | Definition |
|---|---|
| Threat source | The cause of a threat event: adversarial, accidental, structural, or environmental. |
| Threat event | A specific action or occurrence that could cause harm (mapped to ATT&CK for adversarial cases). |
| Vulnerability | A weakness that a threat event can exploit. |
| Predisposing condition | A condition that increases or decreases the likelihood of adverse impact (e.g., internet exposure). |
| Likelihood | The chance a threat event initiates/occurs *and* results in adverse impact. |
| Impact | The magnitude of harm if the event succeeds. |
| Risk | A function of likelihood and impact; the expected harm to the organization. |
| Inherent vs residual risk | Risk before vs after planned/implemented controls. |
| Risk tolerance / appetite | The level of risk leadership is willing to accept. |
| Risk register | The prioritized record of risks, scores, owners, and treatments. |

## Tools & Systems

- **NIST SP 800-30 Rev 1** — the methodology and Appendices D–I taxonomies (threat sources, events, vulnerabilities, likelihood, impact, risk).
- **NIST SP 800-39** — enterprise risk-management context (three tiers).
- **MITRE ATT&CK** — to enumerate and ground adversarial threat events in observed TTPs.
- **Vulnerability scanners / pen-test reports** — empirical vulnerability input.
- **Threat intel sources** — sector ISACs, vendor feeds, internal incident history for likelihood grounding.
- **GRC / risk-register tooling** — spreadsheet, or platforms such as ServiceNow GRC, Archer, OneTrust, to store and track the register.
- **FAIR** (optional) — a quantitative model if leadership wants risk expressed in dollar ranges rather than qualitative bands.

## Common Scenarios

- **CSF/ISO/SOC 2 needs a risk analysis.** Run 800-30 to produce the documented assessment those frameworks require as input, then map results to their control sets.
- **New system before go-live.** Assess threat events against the system's architecture and feed the result into the authorization (RMF Select/Authorize) decision.
- **Board wants the top risks.** Deliver a ranked register with impacts in business terms and clear treatment recommendations.
- **Post-incident.** Re-assess the affected systems; the incident updates likelihood evidence and may surface new threat events.
- **Annual refresh.** Re-score against current threat intel and control changes; show movement in residual risk year over year.

## Output Format

Produce a **Risk Assessment Report** using `assets/template.md`, containing:

1. **Purpose, scope, and tier** — what was assessed and why.
2. **Assumptions, constraints, and risk model** — the factors and scales used (so results are reproducible).
3. **Threat sources** — by type, with adversarial characterization.
4. **Threat events** — each with affected assets and ATT&CK mapping where adversarial.
5. **Vulnerabilities and predisposing conditions** — tied to threat events.
6. **Risk register** — table: ID, threat event, asset, likelihood, impact, **risk level**, contributing vulnerabilities, recommended treatment, owner, residual risk.
7. **Top risks summary** — ranked, in business terms, for leadership.
8. **Maintenance plan** — refresh cadence and re-assessment triggers.

Use `scripts/process.py` to score the register from a risk-input JSON (likelihood × impact → risk level on a configurable matrix), rank risks, and emit the register table.
