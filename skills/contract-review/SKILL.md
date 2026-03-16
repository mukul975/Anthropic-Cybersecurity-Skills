---
name: contract-review
description: Extracts negotiation history from contract drafts into structured markdown. Creates vendor contract profiles and negotiation logs for third-party risk management.
domain: cybersecurity
subdomain: compliance-governance
tags: [contract-security, vendor-management, negotiation, tprm]
version: "1.0"
author: HRD-Security
license: Apache-2.0
---

# Contract Review and Negotiation Extraction Skill

Expert contract security analysis specializing in vendor contract negotiation for regulated industries. Extracts structured negotiation history from contract redlines and populates a contract security knowledge base.

## Document ID Format

All contract profiles use the format: **TPCR-YYYY-NNN** (Third-Party Contract Review, e.g., TPCR-2026-001).

## Input Handling

### .docx Files (Redlined Contracts)

Extract the document XML using Python stdlib (no external dependencies):

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

**OOXML tracked changes** use namespaced XML elements:

- `<w:ins w:author="..." w:date="...">` -- Inserted text (additions)
- `<w:del w:author="..." w:date="...">` -- Deleted text (removals)
- `<w:comment>` -- Margin comments and review notes

### .pdf Files

Use PDF reading tools directly -- same extraction logic applies.

### Clean Contracts (No Redlines)

If the document has no tracked changes:

1. Inform the user that no tracked changes were detected
2. Ask which clauses were negotiated, what changed, and what the original language was
3. Generate the negotiation log from user-provided context

## Extraction Process

### Step 1: Identify Negotiation Items

Scan the content for:

- Tracked changes (`w:ins`, `w:del` in `.docx`)
- Comments and margin notes
- Sections with substantive modifications (not formatting-only)
- Clauses where language differs from standard market terms

### Step 2: Classify Each Item

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

### Step 3: Extract Structured Data

For each negotiation item, extract:

- **Original vendor language**: Direct quote from the initial draft
- **Our position**: What the organization wanted and why
- **Final language**: The agreed text, or "Unchanged" if the vendor position was conceded
- **Outcome**: Won / Compromised / Conceded / Open / Withdrawn
- **Priority**: Critical / High / Medium / Low (based on security and compliance impact)

### Step 4: Check Precedent Library

Search the precedent library for matching clause types to identify negotiation patterns and leverage.

### Step 5: Generate Output

Create a vendor contract profile and negotiation log with:

1. Contract metadata (parties, dates, term, value)
2. Risk classification
3. Full negotiation log table
4. Precedent comparison notes
5. Summary statistics (items won, compromised, conceded)

## Reference Standards

- **ISO 27002:2022**: Controls 5.19-5.23 (Supplier relationships)
- **PCI DSS**: Requirements 12.8-12.9
- **NIST CSF**: Supply chain risk management

## Output Quality Checklist

- [ ] Document ID is unique (TPCR-YYYY-NNN, incremented correctly)
- [ ] All negotiation items are classified with a clause category
- [ ] Original and final language are direct quotes (not paraphrased)
- [ ] Outcome is one of: Won / Compromised / Conceded / Open / Withdrawn
- [ ] Negotiation summary counts match the individual items
- [ ] Precedent library updated with new entries
