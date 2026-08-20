# Routines — Anthropic-Cybersecurity-Skills

## Goal clarity
- **Goal:** Grow and maintain the largest open-source library of structured, agent-usable cybersecurity skills (currently 817 skills / 29 domains), each mapped across MITRE ATT&CK, NIST CSF 2.0, MITRE ATLAS, MITRE D3FEND, NIST AI RMF, and MITRE F3.
- **Why now:** Community project accepting PRs (see [CONTRIBUTING.md](CONTRIBUTING.md)); recent activity is validator fixes and index/count auto-updates, so correctness of the skill index and framework mappings is the active concern, not just skill count.
- **Done when:** For any given change — a new skill validates against `CONTRIBUTING.md`'s quality checklist, `index.json` and skill-count badges are regenerated/consistent, and framework mappings under `mappings/` stay accurate for touched skills.
- **Out of scope:** This routines file does not cover actual red-team/pentest execution — only the meta-work of maintaining the library itself.

## Kickoff checklist (per new skill or subdomain addition)
- [ ] Confirm the skill's subdomain against the list in `CONTRIBUTING.md`
- [ ] Draft `SKILL.md` with required frontmatter (`name`, `description`, `domain`, `subdomain`, `tags`, `version`, `author`, `license`)
- [ ] Include the required body sections: When to Use, Prerequisites, Workflow, Key Concepts, Tools & Systems, Common Scenarios, Output Format
- [ ] Add any `references/`, `scripts/`, `assets/` the skill needs (real content, not placeholders)
- [ ] Run the repo validator before opening a PR (see recent commit `Fix validator: register hardware-firmware-security subdomain, skip .bak dirs`)

## Daily / standup routine
- [ ] What skills/PRs landed or got reviewed since last check-in
- [ ] What's in progress (new skills, validator fixes, mapping updates)
- [ ] What's blocked (e.g. subdomain not yet registered, missing framework mapping)
- [ ] Does `index.json` / skill-count badge still match what's actually in `skills/`?

## Weekly review routine
- [ ] Re-confirm goal clarity above still matches project direction
- [ ] Diff skill count/domain count against README badges — reconcile drift
- [ ] Check for open PRs stuck >1 week (see recent merges like #85, #87 for cadence)
- [ ] Pick next week's top 1-3 priorities (e.g. a subdomain gap, a validator edge case, a mapping backfill)

## Wrap-up / handoff checklist
- [ ] New/changed skills pass the quality checklist in `CONTRIBUTING.md`
- [ ] `index.json` and README badges regenerated and accurate
- [ ] Framework mappings (`mappings/`) updated for any touched skills
- [ ] Anything non-obvious (validator quirks, subdomain naming decisions) captured in `CONTRIBUTING.md` or a commit message, not left implicit

## Delegate to agents
Match routine work below to whatever specialist agents are actually listed in
the current session (names are namespaced per plugin, e.g.
`code-documentation:code-documentation-code-reviewer`) — this table is a
pattern, not a literal lookup. See `~/.claude/skills/routines/references/agent-map.md`.

| Recurring work in this repo | Delegate to |
|---|---|
| Reviewing a new skill's `SKILL.md` for quality/clarity | a code-review-style agent, or the `/code-review` skill |
| Fixing/extending the validator script | `general-purpose` or a Python-focused agent |
| Broad search ("which skills reference X technique/CVE") | `Explore` |
| Drafting a new skill's docs body | a docs-focused agent (`docs-architect`-style) if available, else write directly |
| Regenerating `index.json` / badge counts | direct script run — mechanical, no agent needed |

## Optional external routines (not set up — confirm before creating)
- **Todoist:** could add a recurring "Weekly library review" task (e.g. every
  Monday) mirroring the weekly review routine above. Not created — say the
  word and I'll list exact tasks/cadence for confirmation before adding them.
- **Scheduled check-in:** could schedule an automated weekly summary of new
  PRs/skills via the `schedule` skill. Not set up — same confirmation gate.
