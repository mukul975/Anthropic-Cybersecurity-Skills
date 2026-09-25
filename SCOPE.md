# Scope

This document defines what belongs in this repository and what does not.

It exists so the answer is available *before* the work is done rather than after it. Several of the pull requests I have had to decline were good work aimed at the wrong repository, and that is a documentation failure on my side, not a failure on the contributor's.

This repository is a catalogue. It holds cybersecurity procedures — 818 of them today — written so that an AI agent can read one and carry out a security task competently. Everything that ships here serves that one purpose. Work that does not serve it is out of scope regardless of how good it is, and is usually better off in its own repository, where it can be versioned, released and credited on its own terms.

## These rules apply going forward

This document is new. Until now the repository had no written scope, which is exactly why some contributors built things I then could not merge.

So: nothing here is applied retroactively as a reason to close a pull request that was already open when it landed. Every open PR will be worked through as it was filed, on its own merits, and where I decline one I will give the reason in the thread rather than pointing at a rule that did not exist when the work was done.

I should also say plainly that the review queue is longer than it should be — some pull requests have been waiting months. That is on me, not on the people who sent them, and raising the bar on new contributions does not excuse it. I am working through the backlog.

## What a skill is

A skill is one named security procedure that an agent can execute end to end.

On disk it is a single flat directory:

```
skills/your-skill-name/
├── SKILL.md          # YAML frontmatter + the procedure
├── LICENSE
├── references/       # api-reference.md, standards.md, workflows.md
├── scripts/          # agent.py, process.py, or another real helper
└── assets/           # optional: template.md, filled-in checklists
```

The namespace is flat and global. `skills/` is not nested by category; the category lives in the `subdomain` frontmatter field, which must be one of the values accepted by `tools/validate-skill.py`. All 818 skills today carry `SKILL.md`, `references/` and `scripts/`; 817 carry a `LICENSE` and 288 also carry `assets/`. The most common supporting files are `references/api-reference.md` (811 skills) and `scripts/agent.py` (809).

A submission is a skill when all of the following hold.

**It is a procedure, not a subject.** By convention the directory name is a gerund phrase naming the task — `analyzing-…`, `detecting-…`, `implementing-…`, `hunting-…`, `performing-…` — and 811 of the 818 current names follow it. CI enforces kebab-case, not the gerund, so treat this as the house style rather than a gate. Background material about a topic belongs in a skill's `references/`, not in a directory of its own.

**It is atomic.** One procedure per skill. A body carrying three unrelated workflows is either three skills, or one skill and two reference files.

**It is executable.** Real commands, real flags, real tool names, real paths. No placeholders, no `TODO`, no prose standing in for a command nobody ran.

**Its description routes.** The description is the only text an agent sees when deciding whether to load the skill. It has to say what the skill does, when to fire, which keywords match, and what it is *not* for — naming the nearest neighbouring skill. The 33 container-security skills are the current reference for that standard.

**It is distinct.** It does not restate a skill that already exists. See *Overlap* in [CONTRIBUTING.md](CONTRIBUTING.md).

**It passes CI.** Five gates run on every push and pull request that touches `skills/` or `tools/`: frontmatter validation, agentskills.io conformance, `index.json` freshness, description linting, and a near-duplicate ratchet. A documentation-only PR does not trigger them, so do not read an empty checks list as a pass. CONTRIBUTING.md lists the commands to run them locally.

## Offensive and dual-use content is in scope

This library deliberately covers red-team tradecraft, exploitation, C2, phishing simulation and adversary emulation alongside defence. A defender's agent that has never seen the offensive procedure detects it badly.

Offensive skills are in scope on exactly the same terms as everything else, subject to the authorised-use notice in [README.md](README.md). Nothing in this document is a reason to decline a skill for being offensive. If I decline one, the reason will be scope, overlap or accuracy, and I will say which.

## Out of scope

**Runtimes, engines, orchestrators and agent frameworks.** Code that loads, serves, routes or executes skills — MCP servers, agent harnesses, skill-browser web UIs, "foundation" or "platform" layers that turn the catalogue into a product.

**Applications built on the catalogue.** A tool that consumes these skills is a good thing to build and I will happily link it from the README. It is not a directory in this repository.

**A second toolchain.** `tools/` already holds a frontmatter validator, an agentskills.io conformance checker, an index generator, a description linter and a collision detector — all sharing one PyYAML-backed loader, all wired into CI. A new independent validator competes with those rather than improving them. Extend the existing tool and the existing gate; a PR that makes `tools/lint-descriptions.py` stricter is far more welcome than a new linter beside it.

**Documents about how the project is run.** Roadmaps, work cadences, routines, release plans, launch material, status trackers. How I schedule my own maintenance is not something the catalogue needs to carry, and a document describing a cadence I have not agreed to would be wrong the day it merged. Propose process changes in an issue or a discussion instead.

**Editor, IDE and per-contributor configuration.** `.vscode/` settings, local linter configs and vendor extension settings encode one contributor's environment on everyone else. Agent instruction files are the single exception and they are maintainer-owned — `.github/copilot-instructions.md` exists and is maintained in place. Changes to that class of file should start as an issue, not as a new parallel file.

**Product-shaped skills.** A skill may absolutely be tool-specific: 247 of the 818 names carry a `-with-<tool>` qualifier, and `scanning-docker-images-with-trivy` is exactly right, because the flags, the output formats and the failure modes genuinely differ by tool. What does not belong is a directory whose *subject* is a product rather than a task — a feature tour, an onboarding walkthrough, or an integration write-up for one vendor's service. The test: if the vendor vanished tomorrow and nothing of the procedure survived, it was a product page. When a skill does name a commercial tool, the vendor-link rules in CONTRIBUTING.md apply.

**Bulk imports.** A pull request adding many skills at once cannot be reviewed for technical accuracy at the depth this catalogue needs, and one wrong procedure blocks all the others. One skill per pull request; see CONTRIBUTING.md.

## Why there is no engine in this repository

The catalogue is engine-neutral by construction. `skills/` contains content only; `tools/` contains validators and the index generator and nothing that executes a skill; `.claude-plugin/` contains manifests that let an existing engine mount the catalogue rather than an engine of its own. The bug-report template asks which agent you were running, offering Claude Code, GitHub Copilot and Codex CLI as examples, and the README targets 26+ platforms.

That neutrality is the asset. The moment a runtime lives in this repository, the content starts being shaped by what that runtime supports, the release cadence of the content gets tied to the release cadence of the code, and every consumer on a different platform inherits a dependency they did not ask for. I want the content here to stay separate from the engine that reads it, and I intend to keep this repository on that side of the line.

## Grey areas

Some things sit on the boundary — a large rewrite of an existing skill, a new subdomain, a reference file that is really a small tool, a documentation page that is not README and not CONTRIBUTING. Open an issue and ask before you build it. I would much rather answer a two-line issue than decline a finished pull request, and if the answer is yes, the issue becomes the record of why.

## Changing this document

This is a working document, not a settlement. If a rule here is wrong, or is blocking something the catalogue would clearly be better for having, open an issue arguing the case. Scope decisions are mine to make, but they should be arguable in the open.
