# Skill Validation Tools

## validate-skill.py

Validate SKILL.md metadata before submitting a PR.

### Usage

```bash
# Validate a single skill
python tools/validate-skill.py skills/my-new-skill/

# Validate all skills
python tools/validate-skill.py --all
```

### What it checks

- SKILL.md exists in the skill directory
- Valid YAML frontmatter (between `---` markers)
- Required fields present: `name`, `description`, `domain`, `subdomain`, `tags`
- Name is kebab-case, 1–64 characters
- Description is at least 50 characters (no upper limit; multi-line folded scalars are valid)
- Domain is `cybersecurity`
- Subdomain is from the allowed list
- Tags is a list with at least 2 items

### Requirements

Python 3.8+ (stdlib only, no external dependencies)

## verify-agent-e2e.py

Repeatable end-to-end verification harness for the live agent stack.

### Usage

```bash
# One-time local environment setup from the repo root
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt

# Default Gemini verification
.venv/bin/python tools/verify-repo-hygiene.py
.venv/bin/python tools/verify-agent-e2e.py

# Local truth only (no live provider calls)
.venv/bin/python tools/verify-agent-e2e.py --mode quick

# Run the named search-then-load smoke scenario
.venv/bin/python tools/verify-agent-e2e.py --mode full --scenario search-then-load

# Force JSON output
.venv/bin/python tools/verify-agent-e2e.py --json

# Verify a different exact skill slug
.venv/bin/python tools/verify-agent-e2e.py --backend gemini --skill performing-api-rate-limiting-bypass
```

### What it checks

- Quick mode:
  - forced backend selection
  - expected skill parsing
  - API metadata reflects actual backend/model
- Named scenarios:
  - `exact-load-skill` — exact slug → `load_skill`
  - `search-then-load` — force `search_skills` before `load_skill`
- Forced backend selection via `AGENT_BACKEND`
- Direct `CybersecurityAgent` tool-loop behavior
- CLI entrypoint behavior via `run_agent.py`
- API `/v1/models` backend/model metadata
- API non-streaming `/v1/chat/completions`
- API streaming `/v1/chat/completions`

### Exit behavior

- `0` = requested checks passed
- `2` = live verification blocked by provider quota/runtime limits

### Requirements

- Python 3.10+
- Valid backend credentials in `data/.env`
- Backend selected with `AGENT_BACKEND` or default `gemini`

## cyberagent-doctor.py

One-command wrapper for the local runtime verification stack.

### Usage

```bash
# CI-safe local checks only
.venv/bin/python tools/cyberagent-doctor.py

# Include live Gemini/provider calls
.venv/bin/python tools/cyberagent-doctor.py --live

# Force the Python executable, useful in CI
python tools/cyberagent-doctor.py --python python

# Show child-check output even when checks pass
.venv/bin/python tools/cyberagent-doctor.py --verbose
```

### What it runs

- `verify-repo-hygiene.py`
- `verify-runtime-guardrails.py`
- `verify-agent-e2e.py --mode quick --json`
- `validate-skill.py --all`
- with `--live`: full E2E for `exact-load-skill`
- with `--live`: full E2E for `search-then-load`

Default mode uses a dummy Gemini key only for the quick local import path, so
CI can verify wiring without provider secrets or live network calls. `--live`
loads `data/.env` and uses the real backend credentials already configured for
the local runtime.

## publish-status.py

Read-only helper for the post-commit question: "is this still only local, and
what would I push?"

### Usage

```bash
.venv/bin/python tools/publish-status.py

# JSON for another tool or handoff note
.venv/bin/python tools/publish-status.py --json
```

### What it checks

- current branch
- push remote URL
- upstream tracking branch, if one exists
- clean/dirty working tree
- local commits waiting to publish
- the next push command when the branch is clean and ahead

It never stages, commits, pushes, or fetches.

## verify-runtime-guardrails.py

Fast local guardrail check that does not require a live LLM backend.

### Usage

```bash
python tools/verify-runtime-guardrails.py
```

### What it checks

- repo-local file reads remain allowed
- broad home-directory file reads are denied by default
- `ALLOW_LOCAL_FILE_TOOLS=1` intentionally restores broad local file access
- binding beyond localhost requires `API_TOKEN` unless explicitly overridden
- wildcard CORS with credentials is refused

## verify-repo-hygiene.py

Fast commit-surface hygiene check for this local runtime fork.

### Usage

```bash
python tools/verify-repo-hygiene.py
```

### What it checks

- generated, sensitive, lab, and prompt-workshop paths are not tracked
- required ignore rules still cover local-only material
- high-confidence API key/private-key/password patterns are absent from tracked files
- `data/.env` is private to the local user when present
