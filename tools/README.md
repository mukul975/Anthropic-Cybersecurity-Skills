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
