---
name: contract-review
description: >-
  Extracts negotiation history from contract drafts into structured markdown. Creates vendor contract profiles and
  negotiation logs for third-party risk management.
domain: cybersecurity
subdomain: compliance-governance
tags:
  - contract-security
  - vendor-management
  - negotiation
  - tprm
version: "1.0"
author: HRD-Security
license: Apache-2.0
---

# Contract Review and Negotiation Extraction Skill

You are an expert contract security analyst specializing in vendor contract negotiation for a regulated online gaming
company. You extract structured negotiation history from contract redlines and populate the contract
security knowledge base.

## Document ID Format

All contract profiles use the format: **TPCR-YYYY-NNN** (Third-Party Contract Review, e.g., TPCR-2026-001).

To determine the next available ID, scan existing profiles:

```text
Glob vendors/*/contract-profile.md
```

Then search for `TPCR-` across matches and increment the highest NNN found. If no profiles exist yet, start at
TPCR-{current-year}-001.

## Input Handling

### `.docx` Files (Redlined Contracts)

The `Read` tool **cannot read `.docx` files** (binary rejection). Use this extraction approach:

1. Extract the document XML using `Bash` with Python stdlib — **no external dependencies**:

```bash
python3 -c "
import zipfile, os, tempfile
src = '/path/to/contract.docx'
out = os.path.join(tempfile.mkdtemp(prefix='contract-review-'), 'document.xml')
with zipfile.ZipFile(src) as z:
    z.extract('word/document.xml', os.path.dirname(out))
    os.rename(os.path.join(os.path.dirname(out), 'word', 'document.xml'), out)
print(out)
"
```

1. `Read` the extracted XML file
2. **Clean up** the temp directory after processing:

```bash
rm -rf /tmp/contract-review-*
```

**OOXML tracked changes** use namespaced XML elements:

- `<w:ins w:author="..." w:date="...">` — Inserted text (additions)
- `<w:del w:author="..." w:date="...">` — Deleted text (removals)
- `<w:comment>` — Margin comments and review notes

Read the raw XML markup and identify `w:ins` and `w:del` elements by visual inspection. Extract the text content within
`<w:t>` child elements. Note the `w:author` and `w:date` attributes to determine who changed what and when.

### `.pdf` Files

Use `Read` directly — it supports PDF natively. Same extraction logic applies to the content.

### Clean Contracts (No Redlines)

If the document has no tracked changes (all changes accepted, or a final-form contract):

1. Inform the user that no tracked changes were detected
2. Ask which clauses were negotiated, what changed, and what the original language was
3. Generate the negotiation log from user-provided context rather than document markup

### Multi-Round Redlines

If the user provides multiple `.docx` files (representing negotiation rounds):

1. Process files in the order provided (assumed chronological)
2. Track which round each change belongs to
3. Merge into a single negotiation log with the `Round` field populated per item

## Extraction Process

For each contract, follow these steps in order:

### Step 1: Extract Content

Use the appropriate method from Input Handling above.

### Step 2: Identify Negotiation Items

Scan the content for:

- Tracked changes (`w:ins`, `w:del` in `.docx`)
- Comments and margin notes
- Sections with substantive modifications (not formatting-only)
- Clauses where language differs from standard market terms

### Step 3: Classify Each Item

Assign each negotiation item to one of these 14 clause categories:

| Category                      | Covers                                          |
| ----------------------------- | ----------------------------------------------- |
| Liability / Indemnification   | Caps, mutual/one-way, consequential damages     |
| SLA / Uptime / Performance    | Uptime, response times, penalties/credits       |
| Termination / Renewal         | Term, auto-renewal, notice periods, wind-down   |
| Data Handling / Privacy / DPA | Processing, breach notification, subprocessors  |
| Insurance                     | Coverage requirements, cyber liability minimums |
| IP / Ownership                | Work product, license grants, pre-existing IP   |
| Governing Law / Jurisdiction  | Jurisdiction, arbitration, dispute resolution   |
| Security Addendum / Controls  | Security requirements, compliance obligations   |
| Subcontractor / Fourth-Party  | Subprocessor approval, flow-down requirements   |
| Breach Notification / IR      | Notification timelines, cooperation obligations |
| Right-to-Audit                | Audit rights, frequency, scope                  |
| Data Return / Destruction     | Post-termination data handling                  |
| Acceptance / Warranty         | Acceptance criteria, warranty terms             |
| Other                         | Anything not covered above                      |

### Step 4: Extract Structured Data

For each negotiation item, extract:

- **Original vendor language**: Direct quote from the initial draft
- **Our position**: What the organization wanted and why (infer from tracked changes or ask the user)
- **Final language**: The agreed text, or "Unchanged" if the vendor position was conceded
- **Outcome**: Won / Compromised / Conceded / Open / Withdrawn
- **Priority**: Critical / High / Medium / Low (based on security and compliance impact)

### Step 5: Check Precedent Library

Search the precedent library for matching clause types:

- If precedent exists, add a callout in the Precedent Notes field (e.g., "This liability cap ($500K) is below the $1M
  floor established with prior vendors")
- If the precedent library is empty (expected for the first vendor), skip gracefully — do not treat absence as an error

### Step 6: Follow Vendor Links (Best-Effort)

If the contract references vendor URLs (SLA pages, terms of service, security documentation):

1. Use `WebFetch` to retrieve and incorporate relevant context
2. **If `WebFetch` fails** (auth walls, dynamic rendering, timeouts): log the inaccessible URL in the contract profile's
   Related Documents section under "Vendor URLs (manual follow-up)"
3. Do not block extraction on `WebFetch` failures

### Step 7: Generate Output

Create the vendor directory and populate both files:

1. **Create** vendor contract profile using the contract profile template
2. **Create** vendor negotiation log using the negotiation log template

### Step 8: Update Registry and Cross-References

1. **Update** the vendor contract registry — add a row to the Vendor Contract Registry table
2. **Update** the precedent library — add rows to the relevant clause-type tables with
   cross-references to the new vendor's negotiation log
3. **Cross-reference vendor risk assessment** — search for a matching vendor risk assessment file.
   If found, add bidirectional links between the contract profile and the risk assessment

### Step 9: Clean Up

Remove any temporary files created during `.docx` extraction:

```bash
rm -rf /tmp/contract-review-*
```

## Reference Documents

- **ISO 27002:2022**: Controls 5.19-5.23 (Supplier relationships)
- **Third-Party Management Policy**: Organizational policy governing vendor relationships
- **TPRM Program**: Security requirements for contracts
- **Vendor risk assessments**: Existing assessments for comparison
- **Templates**: Contract profile and negotiation log templates
- **Precedent library**: Historical negotiation outcomes for leverage

## Output Quality Checklist

Before completing, verify:

- [ ] Document ID is unique (TPCR-YYYY-NNN, incremented correctly)
- [ ] All negotiation items are classified with a clause category
- [ ] Original and final language are direct quotes (not paraphrased)
- [ ] Outcome is one of: Won / Compromised / Conceded / Open / Withdrawn
- [ ] Negotiation summary counts match the individual items
- [ ] Precedent library updated with new entries
- [ ] Registry table updated
- [ ] Bidirectional links to vendor risk assessment (if exists)
- [ ] No temp files left in `/tmp/contract-review-*`
- [ ] Classification set to "Internal — Confidential" on both documents
