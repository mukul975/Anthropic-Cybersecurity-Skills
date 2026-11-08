---
name: building-gdpr-records-of-processing-activities
description: >-
  Builds and maintains a GDPR Article 30 Record of Processing Activities (RoPA) as
  controller and as processor, capturing every mandatory field - controller/DPO
  contacts, processing purposes, categories of data subjects and personal data,
  recipients and third-country transfers with the Article 46 safeguard, retention
  periods, and the general description of Article 32 security measures. Provides a
  CSV/YAML schema, a validator that checks each record against Article 30(1) and
  30(2), and a Markdown report generator for the supervisory authority. Use when
  standing up, auditing, or regenerating a processing inventory, or preparing RoPA
  evidence for a regulator or audit. Keywords: RoPA, Article 30, records of
  processing, data inventory, controller, processor, 30(1), 30(2), international
  transfer, retention. Do not use for running a subject-access request - use
  implementing-gdpr-data-subject-access-request; for scoring the risk of a new
  high-risk processing operation use performing-privacy-impact-assessment.
domain: cybersecurity
subdomain: privacy-compliance
tags:
- gdpr
- ropa
- article-30
- data-inventory
- privacy-compliance
- records-of-processing
- data-governance
version: "1.0"
author: rendrabaru777
license: Apache-2.0
nist_csf:
- GV.OC-03
- GV.OC-05
- ID.AM-07
---

# Building a GDPR Article 30 Record of Processing Activities (RoPA)

## When to Use

- When an organisation must create its processing inventory for the first time (Article 30 applies to most controllers and processors; the 250-employee exemption is narrow and rarely holds because it falls away for non-occasional processing, special-category data, or data about criminal convictions).
- When auditing an existing RoPA for missing mandatory fields before a regulator interaction.
- When you act as a **processor** and need the distinct, shorter Article 30(2) record.
- When regenerating a clean, timestamped RoPA export for a Data Protection Authority request, a customer security questionnaire, or an internal audit.

Do not use this skill to answer a data-subject's access request — that is `implementing-gdpr-data-subject-access-request`. Do not use it to assess whether a new, high-risk operation needs a DPIA and to score its risks — that is `performing-privacy-impact-assessment`. The RoPA is the inventory those activities draw on; it is not itself a risk assessment.

## Prerequisites

- Python 3.9+ (standard library only; `pyyaml` optional for YAML input).
- Access to process owners across the business — RoPA entries come from HR, marketing, finance, IT, and product, not from one team.
- The controller's legal identity and the DPO's contact details (or the representative's, under Article 27).
- For transfers: knowledge of which Article 46 mechanism applies (SCCs, adequacy decision, BCRs) per destination.

## Background: what Article 30 requires

**Article 30(1) — controller record.** Each entry must contain:

1. Name and contact details of the controller (and joint controller, representative, DPO where applicable).
2. The purposes of the processing.
3. A description of the categories of data subjects and the categories of personal data.
4. The categories of recipients to whom the data has been or will be disclosed, including recipients in third countries.
5. Where applicable, transfers to a third country or international organisation, naming the country and — for transfers under Article 49(1) second subparagraph — the documentation of suitable safeguards.
6. Where possible, the envisaged time limits for erasure of the different categories.
7. Where possible, a general description of the technical and organisational security measures referred to in Article 32(1).

**Article 30(2) — processor record.** Shorter. Each entry must contain: the processor's and each controller's contacts (and DPO/representative); the categories of processing carried out on behalf of each controller; third-country transfers with the Article 49(1) safeguard documentation where applicable; and the general Article 32 security description.

**Form and duty.** The record is in writing, including electronic form (Article 30(3)), and is made available to the supervisory authority on request (Article 30(4)). The RoPA is the organisation's accountability backbone under Article 5(2): it is the first document most authorities ask for.

## Workflow

### Step 1 — Choose the schema and your role

Decide per system/activity whether you are **controller** or **processor** for it; the required fields differ. Use the field schema in `assets/ropa-template.csv` (controller columns) and `assets/ropa-processor-template.csv` (processor columns). One row = one processing activity.

### Step 2 — Populate by interviewing process owners

Walk each department through its activities. For every activity capture the Article 30(1) fields. Practical tips:

- **Purpose** must be specific ("payroll administration", not "HR"). One activity can have several purposes; keep them explicit.
- **Categories of data** — flag special-category data (Article 9) and criminal-offence data (Article 10) in a dedicated column; they change the legal basis and the exemption analysis.
- **Recipients** — list categories (e.g. "payroll processor", "tax authority"), and name each third-country recipient.
- **Retention** — a period or the criteria that set it ("duration of contract + 6 years"), not "as long as necessary".

### Step 3 — Validate each record against Article 30

Run the validator. It checks every row for the mandatory fields, verifies that any non-EEA recipient has a transfer mechanism recorded, and warns where retention or security description is blank.

```bash
# Controller record
python scripts/agent.py validate --in ropa.csv --role controller

# Processor record (Article 30(2) field set)
python scripts/agent.py validate --in ropa_processor.csv --role processor
```

Non-zero exit on any missing mandatory field makes this safe to wire into CI for a RoPA kept as code.

### Step 4 — Generate the regulator-ready report

```bash
python scripts/agent.py report --in ropa.csv --role controller \
    --out ropa_report.md --org "Example Ltd" --dpo "dpo@example.com"
```

The report is a dated Markdown document: a header block (controller, DPO, generation date), one section per activity with the Article 30(1) fields labelled, and a transfers summary table flagging each third-country flow and its safeguard.

### Step 5 — Keep it current

The RoPA is a living record, not a one-off. Re-validate on every change to a processing activity, a new vendor/sub-processor, or a new transfer destination. Store it in version control or a GRC tool so changes are auditable, and review on a fixed cadence (quarterly is common) plus on any material change.

## Key Concepts

| Concept | What it is | Why it matters |
|---|---|---|
| Article 30(1) | Controller's mandatory field set | Defines what a valid controller record must contain |
| Article 30(2) | Processor's mandatory field set | Shorter; processor records omit purposes, add "categories of processing" |
| Processing activity | One row of the RoPA | The unit of inventory; scoped by purpose, not by system |
| Special-category data | Article 9 data (health, biometrics, etc.) | Changes legal basis and removes the small-org exemption |
| Third-country transfer | Flow to a non-EEA recipient | Requires an Article 44–49 mechanism recorded in the RoPA |
| Article 46 safeguard | SCCs, adequacy, BCRs | The lawful basis for a transfer; must be named per destination |
| Retention period | Erasure time limit or its criteria | Article 30(1)(f); "as needed" is not acceptable |

## Tools & Systems

- **Regulation text** — GDPR Article 30: https://gdpr-info.eu/art-30-gdpr/
- **Guidance** — EDPB guidance and national DPA RoPA templates (e.g. ICO, CNIL) provide field-level examples. ICO: https://ico.org.uk/for-organisations/
- **CNIL RoPA template** — a widely used reference layout: https://www.cnil.fr/en/record-processing-activities
- This skill's `scripts/agent.py` (validator + report generator) and `assets/*.csv` (controller and processor schemas).

## Common Scenarios

- **First RoPA for an SME**: start from `assets/ropa-template.csv`, one row per activity, validate, iterate with each department until the validator is clean.
- **Processor servicing many controllers**: use the 30(2) schema; one row per (controller × category-of-processing); the "purposes" column is intentionally absent.
- **Regulator request**: run `report` to produce a dated, labelled Markdown export rather than handing over a raw spreadsheet.
- **Transfer audit**: validator fails any row with a third-country recipient and no safeguard — use it to find undocumented transfers before the regulator does.

## Output Format

- A validated RoPA dataset (CSV or YAML) with one row per processing activity.
- A validation result: per-row pass/fail with the specific Article 30 field(s) missing, and a non-zero exit code if any mandatory field is absent.
- A dated Markdown RoPA report suitable for a supervisory authority, including a third-country transfers summary table.

See `references/standards.md` for the Article 30 field mapping and transfer-mechanism references, `scripts/agent.py` for the `validate`/`report` CLI, and `assets/ropa-template.csv` / `assets/ropa-processor-template.csv` for the schemas with a worked example row.
