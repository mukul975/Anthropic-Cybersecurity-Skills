# Plan: Multi-Framework Knowledge Graph Expansion

## Status

- Existing graph covers **MITRE ATT&CK Enterprise**, **NIST CSF** (categories only), and **OWASP Top 10** (categories only).
- Skill frontmatter already references **MITRE ATLAS** (AML.T*), **NIST AI RMF** (MEASURE-*, MAP-*, etc.), and **OWASP** tags — but these frameworks are **not represented as graph entities**.
- `coverage-audit.py`, `build-jsonld.py`, and `build-lancedb.py` only verify/build ATT&CK technique coverage.

## Objective

Add ATLAS and NIST AI RMF as first-class entities in the knowledge graph, enabling multi-framework scenario generation and cross-framework coverage reporting. This positions the repository ahead of the curve by unifying adversarial ML attacks (ATLAS), AI risk governance (NIST AI RMF), traditional network attacks (ATT&CK), application risks (OWASP), and cybersecurity best practices (NIST CSF) in a single queryable graph.

## What We Already Have

| Asset | Details |
|-------|---------|
| `atlas_techniques` frontmatter | Present in skills: `AML.T0070`, `AML.T0066`, `AML.T0082`, etc. |
| `nist_ai_rmf` frontmatter | Present in skills: `MEASURE-2.7`, `MAP-5.1`, `MANAGE-2.4`, etc. |
| `nist_csf` frontmatter | Already partially modeled as `Category` nodes |
| `owasp` tags/frontmatter | OWASP Top 10 categories added in `build-owasp-entities()` |
| `tools/expand-coverage.py` | Pattern for parsing skill frontmatter and enriching the graph |

## Gap Analysis

| Framework | In Graph? | Entity Type | Count |
|-----------|-----------|-------------|-------|
| MITRE ATT&CK Enterprise | Yes | Technique | ~361 |
| MITRE ATLAS | No | Technique | Expected dozens (from frontmatter) |
| NIST CSF | Partial | Category | 10 Top-10 categories + CSF refs |
| NIST AI RMF | No | Category/Framework | Expected ~20 functions |
| OWASP Top 10 | Yes (recent) | Category | 10 |

## Implementation Plan

### 1. Extend `build-jsonld.py` with ATLAS and NIST AI RMF Builders

**New functions to add:**

- `build_atlas_entities(index_data)` — Parse `atlas_techniques` from all skill frontmatter, de-duplicate, and emit `@type: "ATLAS-Technique"` entities with `@id: "atlas:AML.TXXXX"`.
  - Use MITRE ATLAS public matrix data if available offline; otherwise seed from skill references and mark `source: skill-frontmatter`.
  - Fields: `id`, `name`, `description`, `framework: "mitre-atlas"`, `framework_id`, `tactic` (ATLAS tactics: `AML.TA0001` etc if available).

- `build_nist_ai_rmf_entities(index_data)` — Parse `nist_ai_rmf` from skill frontmatter, emit `@type: "AI-RMF-Function"` entities with `@id: "ai-rmf:FUNCTION"`.
  - Fields: `id`, `name`, `description`, `framework: "nist-ai-rmf"`, `framework_id`, `tactic: ""`.

**Update `build_techniques_jsonld()`:**
- No change needed; ATLAS entities are separate from ATT&CK techniques.

**Update `main()`:**
- Call new builders, write `mappings/jsonld/atlas.jsonld` and `mappings/jsonld/ai-rmf.jsonld`.

### 2. Extend `build-lancedb.py` to Ingest New Entities

- Add `build_atlas_table(atlas_entities)` and `build_ai_rmf_table(ai_rmf_entities)` using the same schema pattern as techniques/categories.
- LanceDB schema is already flexible (string `id`, `type`, `name`, `framework`, `framework_id`, `tactic`, `score`, `vector`); no schema migration needed.
- Relationships:
  - Skills → ATLAS techniques via `mitigates` predicate (already extracted from `atlas_techniques` frontmatter in `build_relationships_table`).
  - Skills → NIST AI RMF via new predicate `alignedWithAI` (or reuse `alignedWith`).

### 3. Cross-Framework Relationship Enrichment

- When a skill references both `mitre_attack` and `atlas_techniques`, create an inferred edge: `technique:TXXXX --(atlasesEquivalentTo)--> atlas:AML.TXXXX`.
- When a skill references both `mitre_attack` and `nist_ai_rmf`, create: `technique:TXXXX --(governedBy)--> ai-rmf:FUNCTION`.
- This creates a **translation layer** between ATT&CK and AI security frameworks.

### 4. Expand `coverage-audit.py` for Multi-Framework Mode

Add `--framework` flag:

```bash
python tools/coverage-audit.py --framework mitre-atlas
python tools/coverage-audit.py --framework nist-ai-rmf
python tools/coverage-audit.py --framework all
```

- `--framework mitre-atlas`: Audits `mappings/jsonld/atlas.jsonld` entities against graph nodes.
- `--framework nist-ai-rmf`: Audits `mappings/jsonld/ai-rmf.jsonld` entities.
- `--framework all` (default): Audits all frameworks and prints per-framework coverage table.

### 5. Extend `attack-scenario-generator.py` with Multi-Framework Queries

- Add `--framework mitre-atlas` flag to `generate_scenario()` to start chains from ATLAS techniques instead of ATT&CK.
- Add `--cross-framework` flag to generate scenarios that weave between ATT&CK and ATLAS (e.g., "data poisoning → model stealing → credential access").
- New tactic sequence for ATLAS if needed (or reuse ATT&CK sequence as fallback).

### 6. Update `tools/requirements-kg.txt`

- No new dependencies required; ATLAS and AI RMF entities use same LanceDB schema.

### 7. Add `mappings/atlas/` and `mappings/ai-rmf/` Directories

- `mappings/atlas/README.md` — Describe MITRE ATLAS embedding, source (skill frontmatter + eventual official matrix fetch).
- `mappings/ai-rmf/README.md` — Describe NIST AI RMF mapping.

### 8. CI Integration

- Update `.github/workflows/knowledge-graph.yml` to run `coverage-audit.py --framework all` after graph build.
- Add artifact upload for new JSON-LD files alongside the LanceDB database.

## Out of Scope (v2)

- Full offline MITRE ATLAS matrix download and parsing (v1 seeds from skill frontmatter only).
- Mobile/ICS ATT&CK matrices (existing plan item 3 still pending user clarification).
- Auto-generation of ATLAS tactic IDs from official MITRE data.

## Verification

1. `python tools/build-jsonld.py` — produces `atlas.jsonld` and `ai-rmf.jsonld`.
2. `python tools/build-lancedb.py` — stores new entity types.
3. `python tools/coverage-audit.py --framework all` — reports ATLAS + AI RMF coverage.
4. `python tools/attack-scenario-generator.py --entry AML.T0070 --framework mitre-atlas --format json` — generates ATLAS scenarios.

## Tradeoffs / Open Questions

- **ATLAS tactic metadata**: ATLAS has its own tactic IDs (`AML.TA0001` etc.). Should we fetch the official ATLAS matrix to populate tactic mappings, or leave tactic blank for v1 and fill later?
- **NIST AI RMF structure**: AI RMF has 4 functions (Govern, Map, Measure, Manage), each with categories and subcategories. Should we model flat list or hierarchical structure?
- **Relationship predicate naming**: `atlasesEquivalentTo` and `governedBy` are descriptive but verbose. Alternatives: `relatedTo`, `mappedTo`, `crosswalks`.
