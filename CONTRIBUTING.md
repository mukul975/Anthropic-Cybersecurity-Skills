# Contributing to Anthropic-Cybersecurity-Skills

Before you start, read [SCOPE.md](SCOPE.md). It defines what belongs in this catalogue and what does not, and it will save you building something I have to decline.

Most of the policy below is new. Until now this file said nothing about scope, overlap, disclosure or pull-request size, and the absence of those rules is why several well-made contributions ended up somewhere I could not merge them. That is my failure to document, not anyone's failure to read. **These rules apply to pull requests opened from here on.** Anything already open will be reviewed as it was filed.

## How to add a new skill

1. Create a new directory: `skills/your-skill-name/`
2. Add a `SKILL.md` file with required YAML frontmatter:
   ```yaml
   ---
   name: your-skill-name
   description: >-
     What the skill does, in one sentence naming the real tools and artefacts.
     Use when THE TRIGGER CONDITION HOLDS. Keywords: tool, flag, artefact.
     Do not use for THE ADJACENT TASK - use the-other-skill-name.
   domain: cybersecurity
   subdomain: threat-hunting
   tags: [tag1, tag2, tag3]
   version: "1.0"
   author: your-github-username
   license: Apache-2.0
   ---
   ```
   `subdomain` is a single value, not a list — `subdomain: [threat-hunting]` is a YAML list and will fail validation. `name` must equal the directory name. Frontmatter values may not contain `<` or `>`.
3. Write clear, step-by-step instructions in the Markdown body using these sections:
   - ## When to Use
   - ## Prerequisites
   - ## Workflow (numbered steps with real commands)
   - ## Key Concepts (table)
   - ## Tools & Systems
   - ## Common Scenarios
   - ## Output Format
4. (Optional) Add supporting files:
   - `references/standards.md` — Real standard numbers, CVE refs, NIST/MITRE links
   - `references/workflows.md` — Deep technical procedure
   - `scripts/process.py` — Real working helper script
   - `assets/template.md` — Real filled-in checklist/template
5. Submit a PR with title: `Add skill: your-skill-name`

## Skill quality checklist
- [ ] Name is lowercase with hyphens (kebab-case), 1–64 characters
- [ ] Description is clear and includes agent-discovery keywords
- [ ] Instructions are actionable with real commands and tool names
- [ ] Domain and subdomain are set correctly
- [ ] Tags include relevant tools, frameworks, and techniques

## Writing the description

The description is the only text an agent sees when it decides whether to load your skill. Everything else in the file is invisible at that moment. Four things have to be in it:

1. **What it does** — the procedure, the real tools, the real artefacts.
2. **When to fire** — an explicit `Use when …` clause.
3. **Keywords** — the flags, event IDs, file names and tool names someone would actually search for.
4. **When *not* to fire** — a `Do not use for …` clause that names the nearest neighbouring skill by slug.

A worked example, the current description of `scanning-docker-images-with-trivy`:

> Scans a Docker image with Trivy for vulnerabilities in OS packages and language dependencies, misconfiguration, exposed secrets, and licence violations, emitting SARIF, CycloneDX, or SPDX output. Use when scanning or gating a specific image, wiring an image scan into CI/CD, or checking an image during an incident investigation. Keywords: Trivy, image scan, --severity, --exit-code, SARIF, ignore file, .trivyignore. Do not use for cluster-wide scanning or non-image targets - use performing-container-security-scanning-with-trivy; when the toolchain is Grype use scanning-container-images-with-grype.

The linter enforces the mechanical parts: 1024 characters maximum, terminal punctuation, a trigger clause, a negative trigger, and a 500-line cap on the file. Roughly 980 pre-existing failures are grandfathered in `tools/lint-baseline.json` so the gate blocks new debt only. That baseline may shrink and may never grow, which means a new skill has to meet the standard even though many old ones do not yet.

## Before you open a pull request

Run the validators locally. All five run in CI on every push and pull request that touches `skills/` or `tools/` — which any skill PR does — and all five have to be green before I can merge. A PR that changes only documentation does not trigger them at all, so an empty checks list there is not a pass.

```bash
pip install pyyaml   # the only external dependency

python tools/validate-skill.py skills/your-skill-name/      # frontmatter, this skill
python tools/lint-descriptions.py skills/your-skill-name/   # description quality, this skill
python tools/validate-agentskills.py --strict               # conformance, whole repo
python tools/detect-collisions.py                           # near-duplicates, whole repo
python tools/generate-index.py                              # regenerate index.json
```

Three things that catch people out:

- **Two of those commands are repo-wide.** `validate-agentskills.py` and `detect-collisions.py` have no single-skill mode, so a failure they report may belong to a skill you never touched. Check the slug in the output before assuming it is yours.
- **`index.json` is generated, and the PR must carry the regenerated file.** It is refreshed automatically on `main`, but not on your branch, and the freshness gate runs at PR time. If you touched a description and did not commit the regenerated `index.json`, the build fails.
- **The collision gate is a ratchet, currently sitting exactly at its ceiling.** One new near-duplicate pair fails the build. The cap CI enforces lives in `.github/workflows/validate-skills.yml` and gets lowered as disambiguation lands — read it from there rather than memorising a number.

## One skill per pull request

Open one pull request per skill.

Each skill is reviewed for technical accuracy — whether the flags exist, whether the output format is real, whether the procedure works on the version you claim. That review does not batch. In a ten-skill pull request, one wrong procedure holds up nine good ones, and the whole thing tends to stall.

A PR that adds more than one skill directory will be asked to split. It is not a judgement on the work; it is the only way I can land the good parts quickly. The exception is a mechanical repo-wide change — a lint sweep, a metadata fix across many files — which is fine in one PR as long as the description says plainly what the change is and that nothing else varies.

## Overlap with an existing skill

The catalogue currently has 55 unreviewed near-duplicate description pairs, involving 94 of the 818 skills. Overlapping descriptions are not a cosmetic problem: when two descriptions look alike, the agent picks the wrong one, and both skills get less useful.

Until that backlog is worked down, **a new skill that overlaps an existing one will usually be asked to extend the existing skill instead.** Adding depth to `performing-firmware-extraction-with-binwalk` is worth more to this catalogue right now than a second firmware-extraction skill beside it. That redirect is about where the work lands, not about its quality — an extension PR carries the same authorship and gets the same credit.

Before you write a new skill:

1. Search `index.json` for the tool, the technique and the artefact.
2. Run `python tools/detect-collisions.py` and see whether your intended description lands near anything.
3. If something close exists, open an issue proposing the extension, or send a PR against the existing skill.

If the overlap is real but the skills genuinely need to stay separate — different operating system, different tool, different stage of the same investigation — say so in the PR and make both descriptions name the other explicitly. That is how the split is recorded, and it is what `tools/collision-allowlist.json` is for.

## Review and response

I review every pull request myself, and the queue is currently longer than I would like. Small, focused PRs move fastest.

If a PR gets a review request and then goes quiet for 14 days, I may close it as stale. That is housekeeping, not rejection: your branch and your work are untouched, and a single comment reopens the conversation whenever you are ready to pick it up.

## Disclosure

### Self-promotion and vendor links

No undisclosed self-links. If a skill, a reference file, a README entry or a script links to a product, service, repository or domain you are involved with, say so in the PR. A link that exists to send traffic somewhere rather than to help the reader complete the procedure will be removed.

Many skills legitimately cover commercial tools, including ones with no free tier at all. That is fine — the procedure is the point. What is required of vendor-specific content is:

- **Honesty about cost.** If the procedure needs a paid licence, an enterprise appliance or a sales conversation, say so in `## Prerequisites` rather than letting a reader find out at step six.
- **Documentation links, not marketing links.** Link the vendor's docs, API reference or CLI manual. No pricing pages, no signup funnels, no referral or campaign-tagged URLs.
- **No cross-selling.** A general procedure should not route the reader toward one vendor's product when the task does not require it.

The `## Tools & Resources` lists are a special case. They carry standards, RFCs and vendor-neutral documentation. If you want to add a commercial product to one, open an issue first naming what it does that no entry already in that list does. "It also does this" is not enough: there are 87 of these lists in the repository and every vendor in a given space has an equal claim on them, so without that bar they turn into directories.

This applies to me as well. Where the README links to something of mine, it should be labelled as mine.

### Affiliation

If you are affiliated with a product, service, vendor, project or domain referenced in your PR — you work there, contract for it, founded it, are paid by it, or maintain it — say so in the PR description. One line is enough.

Disclosure is not disqualifying. People who build a tool often write the most accurate procedure for it, and I would rather have that procedure with a disclosure than a vaguer one without. It is the non-disclosure that damages trust, because it turns every later reader into someone who has to guess. If it is unclear to me, I will ask; a plain answer settles it.

If an undisclosed connection surfaces during review, that is the entire consequence: the PR goes on hold until it is stated, and is then reviewed on its merits like anything else. Adding the disclosure when asked carries no penalty, and nothing is closed over it.

### AI-assisted contributions

AI assistance is allowed. This is a repository of skills for AI agents; banning it would be absurd.

What is required is disclosure and human responsibility:

- **Say so in the PR description.** One line is enough.
- **A human must have run the commands.** Not read them, not sanity-checked them — run them, on a real system, and seen the output that is now in the skill.
- **A human takes responsibility.** The `author` frontmatter field names a person or a team account, not a tool, and that account should be able to answer review questions about the procedure.
- **It still has to pass the validators**, like everything else.

The failure mode to guard against is a generated procedure that was never executed: flags that look plausible but do not exist, options borrowed from a different major version, output formats that were invented rather than observed. That kind of content is worse than no skill at all, because an agent will follow it confidently. Generated and verified is welcome; generated and unverified is not.

## Subdomains

Choose the most appropriate subdomain for your skill. `tools/validate-skill.py` is the source of truth; these 34 are the canonical values. All current skills already use the canonical value. A handful of older aliases remain accepted by the validator as a safety net and are listed beside their canonical form — the validator prints a warning for any that reappear, so new skills should use the canonical value.

- `ai-security`
- `api-security`
- `blockchain-security`
- `cloud-security`
- `compliance-governance` — also accepts `governance-risk-compliance`
- `container-security`
- `cryptography`
- `data-protection`
- `deception-technology`
- `devsecops`
- `digital-forensics`
- `endpoint-security`
- `hardware-firmware-security` — also accepts `firmware-analysis`, `firmware-security`
- `identity-access-management` — also accepts `identity-and-access-management`, `identity-security`
- `incident-response`
- `malware-analysis`
- `mobile-security`
- `network-security`
- `ot-ics-security` — also accepts `ot-security`
- `penetration-testing` — also accepts `offensive-security`
- `phishing-defense` — also accepts `social-engineering-defense`
- `privacy-compliance`
- `purple-team`
- `ransomware-defense`
- `red-teaming` — also accepts `red-team`
- `soc-operations` — also accepts `security-operations`
- `supply-chain-security`
- `threat-detection`
- `threat-hunting`
- `threat-intelligence`
- `vulnerability-management`
- `web-application-security` — also accepts `application-security`
- `wireless-security`
- `zero-trust-architecture` — also accepts `zero-trust`

If none of these fits, open an issue before you submit. Adding a subdomain means changing the validator, and that is a separate conversation from adding a skill.

The thinnest subdomains are the ones most worth contributing to: `data-protection` and `purple-team` have one skill each, and `blockchain-security`, `wireless-security` and `privacy-compliance` have two.

## Code of Conduct
This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## License
By contributing, you agree that your contributions will be licensed under Apache-2.0.
